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
	"io"
	"os"
	"path/filepath"
	"strings"
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
	// Backend credentials, stored 0600 in the local state dir alongside the audit DB —
	// the design's sanctioned home for bootstrap material (like the age identity, they
	// are needed before any secret store exists). Env vars win when both are set, and
	// nothing is stored unless the operator passes --store-credentials.
	AccessKey string `json:"access_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
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

// syncLog is where the sync machinery writes its human-facing notices, warnings, and
// errors. It defaults to stderr — the explicit `arca sync` command's output. Opportunistic
// auto-sync temporarily swaps in a newlineGuard (see maybeAutoSync) so whatever it emits
// can't run into the output of the command that triggered it.
var syncLog io.Writer = os.Stderr

// newlineGuard wraps a writer so the first byte written is preceded by exactly one newline;
// once anything has been written it is a transparent pass-through. Auto-sync routes its
// output through one so a warning or error starts on its own line instead of trailing the
// just-finished command (notably `get`, whose value carries no trailing newline). On a
// clean, silent sync nothing is written, so no stray blank line is produced.
type newlineGuard struct {
	w       io.Writer
	written bool
}

func (g *newlineGuard) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !g.written {
		g.written = true
		if _, err := io.WriteString(g.w, "\n"); err != nil {
			return 0, err
		}
	}
	return g.w.Write(p)
}

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
	b, err := json.MarshalIndent(c, "", "  ") //#nosec G117 -- deliberate: sync credentials persist 0600 in the state dir, the design's sanctioned bootstrap home (docs/SYNC.md); env still wins
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return err
	}
	// Atomic + mode-enforced write (SEC-37): sync.json can hold cleartext backend credentials, so
	// it must never be left half-written by a crash, and the 0600 must be guaranteed even when the
	// file already exists with a looser mode (a plain WriteFile only chmods on create). CreateTemp
	// makes a fresh 0600 file; the rename is atomic. Matches saveSyncState / saveEscrowState.
	tmp, err := os.CreateTemp(stateDir(), "sync-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), syncConfigPath())
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
	// Route everything this opportunistic sync prints through a guard that prepends one
	// newline before its first byte, so a warning or error can't run into the output of
	// the command that triggered it (notably `get`, whose value has no trailing newline).
	// quiet=true below silences the routine success notices, so on a clean sync the guard
	// writes nothing and no blank line appears — output shows up only when something is wrong.
	prev := syncLog
	syncLog = &newlineGuard{w: prev}
	defer func() { syncLog = prev }()

	b, err := openBackend()
	if err != nil {
		fmt.Fprintf(syncLog, "arca: auto-sync skipped: %v\n", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), autoSyncTimeout)
	defer cancel()
	if err := runSyncCtx(ctx, b, false, false, false, true); err != nil {
		fmt.Fprintf(syncLog, "arca: auto-sync: %v\n", err)
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
	cfg.AccessKey, cfg.SecretKey = resolveSyncCredentials(loadSyncConfig())
	return remote.NewS3(cfg)
}

// resolveSyncCredentials picks the backend credential pair: environment first
// (explicit always wins), then the 0600 state-dir config persisted by
// `sync init --store-credentials`. Empty results are fine — NewS3 falls back to
// the AWS_* names and errors with guidance if nothing resolves.
func resolveSyncCredentials(sc syncConfig) (access, secret string) {
	access = os.Getenv("ARCA_SYNC_ACCESS_KEY")
	if access == "" {
		access = sc.AccessKey
	}
	secret = os.Getenv("ARCA_SYNC_SECRET_KEY")
	if secret == "" {
		secret = sc.SecretKey
	}
	return access, secret
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
	if err := tmp.Chmod(0o600); err != nil { // explicit, not just CreateTemp's default (SEC-40)
		tmp.Close()
		return nil, nil, err
	}
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
	var auto, storeCreds bool
	c := &cobra.Command{
		Use:   "init URL",
		Short: "Pin the sync backend URL in the local state dir",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if _, err := remote.ParseURL(args[0]); err != nil {
				return err
			}
			cfg := syncConfig{URL: args[0], Auto: auto}
			if storeCreds {
				cfg.AccessKey = os.Getenv("ARCA_SYNC_ACCESS_KEY")
				cfg.SecretKey = os.Getenv("ARCA_SYNC_SECRET_KEY")
				if cfg.AccessKey == "" || cfg.SecretKey == "" {
					return errors.New("--store-credentials: set ARCA_SYNC_ACCESS_KEY and ARCA_SYNC_SECRET_KEY in the environment first (e.g. via `arca exec --only … -- arca sync init …`)")
				}
			}
			if err := saveSyncConfig(cfg); err != nil {
				return err
			}
			if storeCreds {
				fmt.Fprintln(os.Stderr, "credentials stored in the state dir (0600) — auto-sync needs no environment")
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
	c.Flags().BoolVar(&storeCreds, "store-credentials", false, "persist ARCA_SYNC_ACCESS_KEY/ARCA_SYNC_SECRET_KEY from the environment into the 0600 state-dir config")
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
	return runSyncCtx(context.Background(), b, pullOnly, pushOnly, force, false)
}

// quiet suppresses the informational success lines ("in sync: nothing to do",
// "pushed/pulled generation N"); warnings and errors are always emitted. It is set for
// opportunistic auto-sync so its chatter never trails another command's output.
func runSyncCtx(ctx context.Context, b remote.Backend, pullOnly, pushOnly, force, quiet bool) error {
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
		return pushStore(ctx, b, s, raw, remote.Rev{}, st, quiet)

	case s == nil:
		if pushOnly {
			return errors.New("--push requested but there is no local store (run `arca sync --pull` to bootstrap)")
		}
		return pullStore(ctx, b, st, nil, force, quiet)
	}

	L, S, R := s.Generation, st.LastGeneration, head.Generation

	if R < S && !force {
		return fmt.Errorf("remote ROLLBACK detected: the remote is at generation %d but this machine last synced generation %d — an older copy was restored on the backend; investigate (`arca sync status`, the remote's revision objects), or --force to push local state over it", R, S)
	}
	if L < S {
		if pushOnly {
			return fmt.Errorf("local store looks rolled back (generation %d < last synced %d) — refusing to push it; `arca sync --pull` restores the newest synced state", L, S)
		}
		return pullStore(ctx, b, st, s, force, quiet)
	}

	switch {
	case L == S && R == S:
		if !quiet {
			fmt.Fprintln(syncLog, "in sync: nothing to do")
		}
		escrowBestEffort(ctx, b, s.Recipients)
		return nil
	case L == S && R > S:
		if pushOnly {
			return fmt.Errorf("remote is ahead (generation %d > %d) and --push was requested; run without --push to pull first", R, L)
		}
		return pullStore(ctx, b, st, s, force, quiet)
	case L > S && (R == S || force):
		if pullOnly {
			return fmt.Errorf("local has unpushed changes (generation %d > last synced %d) and --pull was requested; run without --pull to push", L, S)
		}
		return pushStore(ctx, b, s, raw, head, st, quiet)
	default: // L > S && R > S — divergence
		if pullOnly {
			// The operator explicitly chose the documented resolution: adopt the
			// remote and discard local divergence.
			return pullStore(ctx, b, st, s, force, quiet)
		}
		return fmt.Errorf("sync CONFLICT: both sides advanced since the last sync (local generation %d, remote %d, last synced %d). No auto-merge for a secrets store: pull with `arca sync --pull` (discards local divergence) or re-apply the remote's changes locally and push", L, R, S)
	}
}

func pushStore(ctx context.Context, b remote.Backend, s *store.Store, raw []byte, prev remote.Rev, st syncState, quiet bool) error {
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
	if !quiet {
		fmt.Fprintf(syncLog, "pushed generation %d\n", rev.Generation)
	}
	escrowBestEffort(ctx, b, s.Recipients)
	return nil
}

// pullStore adopts the remote store. Because the backend is untrusted and age gives
// confidentiality but not writer-authentication, everything an attacker-controlled backend can
// do — replay an old envelope, serve one at an unexpected generation, broaden the recipient set —
// is refused HERE, before the local store is touched (SEC-35). `local` is the current local store
// (nil when bootstrapping this machine); `force` overrides the refusals for a deliberate adopt.
//
// This is defense-in-depth, not authentication: a backend that both knows the (non-secret)
// recipient keys AND serves a strictly-newer forged envelope can still substitute content. The
// complete fix is an operator signature over the store (tracked separately). What this closes is
// the whole replay/rollback/recipient-resurrection class against an established machine.
func pullStore(ctx context.Context, b remote.Backend, st syncState, local *store.Store, force, quiet bool) error {
	env, rev, err := b.Fetch(ctx)
	if err != nil {
		return err
	}
	payload, rs, err := openEnvelope(env)
	if err != nil {
		return err
	}
	// The envelope's own generation is authoritative over the backend's metadata tag. A backend
	// that claims a HIGHER head generation than the envelope it actually serves is replaying/
	// downgrading — refuse rather than silently trust the older payload (was: warn-and-adopt).
	if rs.Generation < rev.Generation && !force {
		return fmt.Errorf("remote TAMPER detected on pull: backend advertised head generation %d but served an envelope at generation %d — a replayed or rolled-back store; investigate, or --force to adopt it anyway", rev.Generation, rs.Generation)
	}
	if rs.Generation != rev.Generation {
		fmt.Fprintf(syncLog, "arca: warning: backend metadata says generation %d but the envelope holds %d; trusting the envelope\n", rev.Generation, rs.Generation)
	}
	rev.Generation = rs.Generation

	// Rollback floor is the DURABLE high-water mark — the newest generation this machine has ever
	// observed (SEC-14 `store.gen`) plus the last-synced cursor plus the current local store — not
	// the resettable sync cursor alone. Checked BEFORE any write, and a hard refusal, not a warning.
	floor := st.LastGeneration
	if h := storeGenHWM(); h > floor {
		floor = h
	}
	if local != nil && local.Generation > floor {
		floor = local.Generation
	}
	if rs.Generation < floor && !force {
		return fmt.Errorf("remote ROLLBACK detected on pull: envelope generation %d is behind this machine's high-water mark %d — an older store copy is being served; investigate, or --force to adopt it", rs.Generation, floor)
	}

	// Refuse a SILENT broadening of read access: a pulled store that ADDS recipients (e.g. a
	// replayed pre-removal copy resurrecting a cut key, or a forged one injecting the attacker)
	// must be an explicit operator choice. Narrowing/unchanged sets pull freely.
	if local != nil && !force {
		if added := addedRecipients(local.Recipients, rs.Recipients); len(added) > 0 {
			return fmt.Errorf("pull would ADD %d recipient(s) not in the local store (%s) — refusing to broaden read access from an untrusted backend; if this is intended (a teammate's new key), re-run with --force", len(added), strings.Join(added, ", "))
		}
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
	if !quiet {
		fmt.Fprintf(syncLog, "pulled generation %d\n", rev.Generation)
	}
	escrowBestEffort(ctx, b, rs.Recipients)
	return nil
}

// addedRecipients returns the recipients present in next but not in prev.
func addedRecipients(prev, next []string) []string {
	have := make(map[string]bool, len(prev))
	for _, r := range prev {
		have[r] = true
	}
	var added []string
	for _, r := range next {
		if !have[r] {
			added = append(added, r)
		}
	}
	return added
}

// escrowBestEffort ships new audit events off-machine after a successful sync (SEC-14
// Option B). A failure is a warning: escrow strengthens the audit story, it must never
// weaken the sync one.
func escrowBestEffort(ctx context.Context, b remote.Backend, recipients []string) {
	if err := escrowAudit(ctx, b, recipients); err != nil {
		fmt.Fprintf(syncLog, "arca: warning: audit escrow failed (will retry on the next sync): %v\n", err)
	}
}
