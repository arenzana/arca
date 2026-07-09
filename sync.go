// arca sync — replicate the store through an untrusted network backend (S3-compatible),
// replacing "keep the store file in a git repo" as the only multi-machine story.
//
// The pushed envelope is the whole store file wrapped in ONE MORE age layer to the same
// recipients, so the backend sees no secret names, tags, or policy — only bytes. The
// local file remains the source of truth for every read/exec; sync never sits in an
// access path. Concurrency is compare-and-swap: lost updates are impossible, conflicts
// are reported with both sides' generations and never auto-merged.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/remote"
	"github.com/arenzana/arca/internal/store"
)

// syncStatePath holds what this machine last saw on the remote (never synced itself).
func syncStatePath() string { return filepath.Join(stateDir(), "sync-state.json") }

// syncConfigPath optionally pins the sync URL so it survives shells (ARCA_SYNC_URL wins).
func syncConfigPath() string { return filepath.Join(stateDir(), "sync.json") }

type syncState struct {
	LastGeneration int       `json:"last_generation"` // remote generation at last successful sync
	LastTag        string    `json:"last_tag"`        // backend CAS token for it
	LastSync       time.Time `json:"last_sync"`
}

type syncConfig struct {
	URL string `json:"url"`
	// Auto enables opportunistic sync: after any command that mutated the store the
	// change is pushed, and after any command at all a pull runs when the last sync
	// is older than autoSyncStaleness. Best-effort by design — a failed auto-sync
	// warns and never fails the command (offline-first), and it runs strictly AFTER
	// the command's real work, never in an access path.
	Auto bool `json:"auto,omitempty"`
}

// autoSyncStaleness is how old the last sync may be before an auto-enabled command
// opportunistically reconciles with the remote.
const autoSyncStaleness = 15 * time.Minute

// autoSyncTimeout bounds the post-command network work so a hung backend can't
// wedge the CLI.
const autoSyncTimeout = 10 * time.Second

func loadSyncState() syncState {
	var st syncState
	if b, err := os.ReadFile(syncStatePath()); err == nil { //#nosec G304 -- our own state dir
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func saveSyncState(st syncState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return err
	}
	tmp := syncStatePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, syncStatePath())
}

// loadSyncConfig reads the state-dir sync.json (zero value when absent/invalid).
func loadSyncConfig() syncConfig {
	var c syncConfig
	if b, err := os.ReadFile(syncConfigPath()); err == nil { //#nosec G304 -- our own state dir
		_ = json.Unmarshal(b, &c)
	}
	return c
}

func saveSyncConfig(c syncConfig) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(syncConfigPath(), b, 0o600); err != nil {
		return err
	}
	return nil
}

// syncURL resolves the backend URL: ARCA_SYNC_URL first, then the state-dir sync.json.
func syncURL() (string, error) {
	if v := os.Getenv("ARCA_SYNC_URL"); v != "" {
		return v, nil
	}
	if c := loadSyncConfig(); c.URL != "" {
		return c.URL, nil
	}
	return "", errors.New("sync is not configured: set ARCA_SYNC_URL (s3://bucket/prefix?endpoint=…) or run `arca sync init URL`")
}

// autoSyncEnabled reports whether opportunistic sync is on: the sync.json flag, with
// ARCA_SYNC_AUTO as an override in either direction (1/0).
func autoSyncEnabled() bool {
	switch os.Getenv("ARCA_SYNC_AUTO") {
	case "1", "true", "on", "yes":
		return true
	case "0", "false", "off", "no":
		return false
	}
	return loadSyncConfig().Auto
}

// maybeAutoSync is called once from the root command's PersistentPostRun after every
// invocation. It pushes when this command mutated the store (the loaded generation
// advanced), and otherwise pulls/reconciles when the last sync is stale. Best-effort:
// every failure is a warning, never an error — offline is a normal state.
func maybeAutoSync(invokedSync bool) {
	if invokedSync || !autoSyncEnabled() {
		return
	}
	mutated := curStore != nil && loadedGeneration >= 0 && curStore.Generation > loadedGeneration
	stale := time.Since(loadSyncState().LastSync) > autoSyncStaleness
	if !mutated && !stale {
		return
	}
	b, err := openBackend()
	if err != nil {
		fmt.Fprintf(os.Stderr, "arca: auto-sync skipped: %v\n", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), autoSyncTimeout)
	defer cancel()
	if err := runSyncCtx(ctx, b, false, false, false); err != nil {
		fmt.Fprintf(os.Stderr, "arca: auto-sync: %v\n", err)
	}
}

// openBackend is a var so tests can substitute remote.NewFake().
var openBackend = func() (remote.Backend, error) {
	raw, err := syncURL()
	if err != nil {
		return nil, err
	}
	cfg, err := remote.ParseURL(raw)
	if err != nil {
		return nil, err
	}
	return remote.NewS3(cfg)
}

// sealEnvelope wraps the raw store-file bytes in one more age layer to the store's
// own recipients — any machine holding a recipient identity can open it, which is
// exactly the multi-machine model. The backend learns nothing but size and timing.
func sealEnvelope(storeBytes []byte, recipients []string) ([]byte, error) {
	recips, err := crypto.ParseRecipients(recipients)
	if err != nil {
		return nil, err
	}
	armored, err := crypto.Encrypt(storeBytes, recips)
	if err != nil {
		return nil, fmt.Errorf("seal envelope: %w", err)
	}
	return []byte(armored), nil
}

// openEnvelope decrypts a fetched envelope with the local identities and validates the
// payload as a store document (parse + size checks) WITHOUT writing anything yet. It
// returns the raw payload and the parsed store.
func openEnvelope(envelope []byte) ([]byte, *store.Store, error) {
	ids, err := loadIDs()
	if err != nil {
		return nil, nil, err
	}
	plain, err := crypto.Decrypt(string(envelope), ids)
	if err != nil {
		return nil, nil, fmt.Errorf("open envelope (is this machine a recipient?): %w", err)
	}
	if err := os.MkdirAll(stateDir(), 0o700); err != nil { // fresh machine: nothing exists yet
		return nil, nil, err
	}
	tmp, err := os.CreateTemp(stateDir(), "sync-pull-*")
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(plain); err != nil {
		tmp.Close()
		return nil, nil, err
	}
	tmp.Close()
	s, err := store.Load(tmp.Name())
	if err != nil {
		return nil, nil, fmt.Errorf("remote envelope did not validate as a store: %w", err)
	}
	// Load is deliberately tolerant for local files (fresh stores, older schemas). A pulled
	// document replaces the local store wholesale, so hold it to what every real store has:
	// a version, recipients, and at least one write behind it. This stops a wrong-but-
	// decryptable object from silently wiping the local store.
	if s.Version < 1 || len(s.Recipients) == 0 || s.Generation < 1 {
		return nil, nil, fmt.Errorf("remote envelope did not validate as a store (version %d, %d recipient(s), generation %d)", s.Version, len(s.Recipients), s.Generation)
	}
	return plain, s, nil
}

// writeLocalStore atomically replaces the local store file with the pulled payload.
func writeLocalStore(payload []byte) error {
	dir := filepath.Dir(storePath())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".store-sync-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), storePath())
}

// localStoreForSync loads the local store plus its raw bytes; a missing store is
// reported as (nil, nil, nil) so a fresh machine can bootstrap with a pull.
func localStoreForSync() (*store.Store, []byte, error) {
	raw, err := os.ReadFile(storePath()) //#nosec G304 -- operator-controlled store path
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	s, err := openStore()
	if err != nil {
		return nil, nil, err
	}
	return s, raw, nil
}

func newSync() *cobra.Command {
	var pullOnly, pushOnly, force bool
	c := &cobra.Command{
		Use:   "sync",
		Short: "Replicate the store through a network backend (S3-compatible)",
		Long: "Reconciles the local store with the configured backend (ARCA_SYNC_URL or `arca sync init`).\n" +
			"The uploaded envelope is age-encrypted end-to-end: the backend never sees names, tags,\n" +
			"or policy. Pull and push are chosen automatically; conflicts are reported, never merged.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if pullOnly && pushOnly {
				return errors.New("--pull and --push are mutually exclusive")
			}
			b, err := openBackend()
			if err != nil {
				return err
			}
			return runSync(b, pullOnly, pushOnly, force)
		},
	}
	c.Flags().BoolVar(&pullOnly, "pull", false, "only pull (adopt the remote if it is ahead)")
	c.Flags().BoolVar(&pushOnly, "push", false, "only push (upload local changes)")
	c.Flags().BoolVar(&force, "force", false, "accept a remote that regressed (rolled back) — read the warning first")

	c.AddCommand(newSyncInit(), newSyncStatus(), newSyncAuto())
	return c
}

func newSyncInit() *cobra.Command {
	var auto bool
	c := &cobra.Command{
		Use:   "init URL",
		Short: "Pin the sync backend URL in the local state dir",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if _, err := remote.ParseURL(args[0]); err != nil {
				return err
			}
			if err := saveSyncConfig(syncConfig{URL: args[0], Auto: auto}); err != nil {
				return err
			}
			mode := "manual (`arca sync`)"
			if auto {
				mode = "automatic (opportunistic push after writes, periodic pull)"
			}
			fmt.Fprintf(os.Stderr, "sync backend pinned: %s — %s\n", args[0], mode)
			return nil
		},
	}
	c.Flags().BoolVar(&auto, "auto", false, "also enable automatic sync (push after writes, staleness-based pull)")
	return c
}

func newSyncAuto() *cobra.Command {
	return &cobra.Command{
		Use:   "auto on|off",
		Short: "Toggle automatic sync (best-effort push after writes, periodic pull)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			c := loadSyncConfig()
			switch args[0] {
			case "on":
				c.Auto = true
			case "off":
				c.Auto = false
			default:
				return fmt.Errorf("want on or off, got %q", args[0])
			}
			if c.URL == "" && os.Getenv("ARCA_SYNC_URL") == "" && c.Auto {
				return errors.New("configure a backend first: `arca sync init URL`")
			}
			if err := saveSyncConfig(c); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "automatic sync: %s\n", args[0])
			return nil
		},
	}
}

func newSyncStatus() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show local vs remote generation and last sync time",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			b, err := openBackend()
			if err != nil {
				return err
			}
			st := loadSyncState()
			localGen := 0
			if s, _, err := localStoreForSync(); err == nil && s != nil {
				localGen = s.Generation
			}
			head, err := b.Head(context.Background())
			switch {
			case errors.Is(err, remote.ErrNotFound):
				fmt.Fprintf(os.Stderr, "remote: empty | local: generation %d | never synced\n", localGen)
				return nil
			case err != nil:
				return err
			}
			last := "never"
			if !st.LastSync.IsZero() {
				last = st.LastSync.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(os.Stderr, "remote: generation %d | local: generation %d | last synced generation %d at %s\n",
				head.Generation, localGen, st.LastGeneration, last)
			return nil
		},
	}
}

// runSync reconciles. The decision table (L = local gen, S = last-synced gen, R = remote gen):
//
//	no remote            → push (bootstrap the backend)
//	no local             → pull (bootstrap this machine)
//	R < S                → the REMOTE rolled back → refuse (unless --force adopts local-wins push)
//	L == S && R == S     → up to date
//	L == S && R > S      → fast-forward pull
//	L > S  && R == S     → push
//	L > S  && R > S      → conflict: both sides advanced — report, never merge
//	L < S                → the LOCAL store rolled back → refuse push; pull repairs it
func runSync(b remote.Backend, pullOnly, pushOnly, force bool) error {
	return runSyncCtx(context.Background(), b, pullOnly, pushOnly, force)
}

func runSyncCtx(ctx context.Context, b remote.Backend, pullOnly, pushOnly, force bool) error {
	s, raw, err := localStoreForSync()
	if err != nil {
		return err
	}
	st := loadSyncState()

	head, err := b.Head(ctx)
	remoteEmpty := errors.Is(err, remote.ErrNotFound)
	if err != nil && !remoteEmpty {
		return err
	}

	switch {
	case remoteEmpty && s == nil:
		return errors.New("nothing to sync: no local store (run `arca init`) and the remote is empty")

	case remoteEmpty:
		if pullOnly {
			return errors.New("--pull requested but the remote is empty")
		}
		return pushStore(ctx, b, s, raw, remote.Rev{}, st)

	case s == nil:
		if pushOnly {
			return errors.New("--push requested but there is no local store (run `arca sync --pull` to bootstrap)")
		}
		return pullStore(ctx, b, st)
	}

	L, S, R := s.Generation, st.LastGeneration, head.Generation

	if R < S && !force {
		return fmt.Errorf("remote ROLLBACK detected: the remote is at generation %d but this machine last synced generation %d — an older copy was restored on the backend; investigate (`arca sync status`, the remote's revision objects), or --force to push local state over it", R, S)
	}
	if L < S {
		if pushOnly {
			return fmt.Errorf("local store looks rolled back (generation %d < last synced %d) — refusing to push it; `arca sync --pull` restores the newest synced state", L, S)
		}
		return pullStore(ctx, b, st)
	}

	switch {
	case L == S && R == S:
		fmt.Fprintln(os.Stderr, "in sync: nothing to do")
		escrowBestEffort(ctx, b, s.Recipients)
		return nil
	case L == S && R > S:
		if pushOnly {
			return fmt.Errorf("remote is ahead (generation %d > %d) and --push was requested; run without --push to pull first", R, L)
		}
		return pullStore(ctx, b, st)
	case L > S && (R == S || force):
		if pullOnly {
			return fmt.Errorf("local has unpushed changes (generation %d > last synced %d) and --pull was requested; run without --pull to push", L, S)
		}
		return pushStore(ctx, b, s, raw, head, st)
	default: // L > S && R > S — divergence
		if pullOnly {
			// The operator explicitly chose the documented resolution: adopt the
			// remote and discard local divergence.
			return pullStore(ctx, b, st)
		}
		return fmt.Errorf("sync CONFLICT: both sides advanced since the last sync (local generation %d, remote %d, last synced %d). No auto-merge for a secrets store: pull with `arca sync --pull` (discards local divergence) or re-apply the remote's changes locally and push", L, R, S)
	}
}

func pushStore(ctx context.Context, b remote.Backend, s *store.Store, raw []byte, prev remote.Rev, st syncState) error {
	env, err := sealEnvelope(raw, s.Recipients)
	if err != nil {
		return err
	}
	rev, err := b.Push(ctx, env, s.Generation, prev)
	if err != nil {
		if errors.Is(err, remote.ErrCASMismatch) {
			return fmt.Errorf("%w — run `arca sync` again to reconcile", err)
		}
		return err
	}
	if err := saveSyncState(syncState{LastGeneration: rev.Generation, LastTag: rev.Tag, LastSync: time.Now()}); err != nil {
		return err
	}
	if err := logAudit("sync-push", "-", ""); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "pushed generation %d\n", rev.Generation)
	escrowBestEffort(ctx, b, s.Recipients)
	return nil
}

func pullStore(ctx context.Context, b remote.Backend, st syncState) error {
	env, rev, err := b.Fetch(ctx)
	if err != nil {
		return err
	}
	payload, rs, err := openEnvelope(env)
	if err != nil {
		return err
	}
	// The envelope's own generation is authoritative over the backend's metadata tag —
	// the backend is untrusted; the payload is what we verified.
	if rs.Generation != rev.Generation {
		fmt.Fprintf(os.Stderr, "arca: warning: backend metadata says generation %d but the envelope holds %d; trusting the envelope\n", rev.Generation, rs.Generation)
		rev.Generation = rs.Generation
	}
	if rev.Generation < st.LastGeneration {
		return fmt.Errorf("remote ROLLBACK detected on pull: envelope generation %d < last synced %d — refusing to adopt it", rev.Generation, st.LastGeneration)
	}
	if err := writeLocalStore(payload); err != nil {
		return err
	}
	// Advance the SEC-14 local high-water mark through the normal path.
	warnIfStoreRolledBack(rs.Generation)
	if err := saveSyncState(syncState{LastGeneration: rev.Generation, LastTag: rev.Tag, LastSync: time.Now()}); err != nil {
		return err
	}
	if err := logAudit("sync-pull", "-", ""); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "pulled generation %d\n", rev.Generation)
	escrowBestEffort(ctx, b, rs.Recipients)
	return nil
}

// escrowBestEffort ships new audit events off-machine after a successful sync (SEC-14
// Option B). A failure is a warning: escrow strengthens the audit story, it must never
// weaken the sync one.
func escrowBestEffort(ctx context.Context, b remote.Backend, recipients []string) {
	if err := escrowAudit(ctx, b, recipients); err != nil {
		fmt.Fprintf(os.Stderr, "arca: warning: audit escrow failed (will retry on the next sync): %v\n", err)
	}
}
