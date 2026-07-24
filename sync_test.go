package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/remote"
)

// withFakeBackend routes the sync command at an in-memory backend for the test.
func withFakeBackend(t *testing.T) *remote.Fake {
	t.Helper()
	f := remote.NewFake()
	old := openBackend
	t.Cleanup(func() { openBackend = old })
	openBackend = func() (remote.Backend, error) { return f, nil }
	return f
}

// switchMachine points the store/audit/state dirs at a fresh directory while KEEPING the
// age identity — simulating a second machine owned by the same operator (a recipient).
func switchMachine(t *testing.T, base string) string {
	t.Helper()
	dir := filepath.Join(base, "machine-b")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARCA_STORE", filepath.Join(dir, "store.json"))
	t.Setenv("ARCA_AUDIT", filepath.Join(dir, "audit.db"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	return dir
}

// TestSyncRoundTrip walks the primary two-machine story: bootstrap-push from machine A,
// bootstrap-pull onto machine B, fast-forward pulls, and CAS-protected pushes.
func TestSyncRoundTrip(t *testing.T) {
	dir := sandbox(t)
	withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API")

	// Machine A bootstraps the remote.
	runArca(t, "", "sync")

	// Machine B (same identity, empty store) bootstraps from the remote and can read.
	aState := os.Getenv("XDG_STATE_HOME")
	switchMachine(t, dir)
	runArca(t, "", "sync")
	if out := runArca(t, "", "get", "API"); out != "hunter2" {
		t.Fatalf("pulled store: get API = %q", out)
	}

	// B mutates and pushes; A fast-forwards.
	runArca(t, "v2", "rotate", "API")
	runArca(t, "", "sync")
	t.Setenv("ARCA_STORE", filepath.Join(dir, "store.json"))
	t.Setenv("ARCA_AUDIT", filepath.Join(dir, "audit.db"))
	t.Setenv("XDG_STATE_HOME", aState)
	runArca(t, "", "sync")
	if out := runArca(t, "", "get", "API"); out != "v2" {
		t.Fatalf("after fast-forward pull: get API = %q", out)
	}
}

// TestSyncConflict proves divergence is reported, not merged: both machines mutate from
// the same base; the second push is refused with a CONFLICT verdict.
func TestSyncConflict(t *testing.T) {
	dir := sandbox(t)
	withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")

	// Machine B pulls the base, then mutates AND pushes first.
	aStore, aAudit, aState := os.Getenv("ARCA_STORE"), os.Getenv("ARCA_AUDIT"), os.Getenv("XDG_STATE_HOME")
	switchMachine(t, dir)
	runArca(t, "", "sync")
	runArca(t, "b-wins", "rotate", "A")
	runArca(t, "", "sync")

	// Machine A mutates from the stale base; its push must be refused.
	t.Setenv("ARCA_STORE", aStore)
	t.Setenv("ARCA_AUDIT", aAudit)
	t.Setenv("XDG_STATE_HOME", aState)
	runArca(t, "a-loses", "rotate", "A")
	err := runArcaErr("", "sync")
	if err == nil {
		t.Fatal("divergent push was accepted")
	}
	if !strings.Contains(err.Error(), "CONFLICT") {
		t.Fatalf("want a CONFLICT verdict, got: %v", err)
	}
	// --pull resolves explicitly (B's version wins), and a plain sync is then clean.
	runArca(t, "", "sync", "--pull")
	if out := runArca(t, "", "get", "A"); out != "b-wins" {
		t.Fatalf("after conflict pull: get A = %q", out)
	}
}

// TestSyncRemoteRollbackDetected: a remote head replaced with an older envelope (backend
// tamper or restored bucket) is refused on sync, extending SEC-14 to the network side.
func TestSyncRemoteRollbackDetected(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")
	oldEnv, oldRev, err := fake.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "v2", "rotate", "A")
	runArca(t, "", "sync")

	fake.Corrupt(oldEnv, oldRev.Generation) // roll the remote head back out-of-band
	errSync := runArcaErr("", "sync")
	if errSync == nil || !strings.Contains(errSync.Error(), "ROLLBACK") {
		t.Fatalf("want a remote ROLLBACK verdict, got: %v", errSync)
	}
}

// TestSyncEnvelopeOpacity: the object stored on the backend must be an age envelope —
// no secret names, no metadata, not even the store's JSON shape.
func TestSyncEnvelopeOpacity(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "VERY_SECRET_NAME", "--desc", "notes about prod")
	runArca(t, "", "sync")
	env, _, err := fake.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	body := string(env)
	if !strings.Contains(body, "AGE ENCRYPTED FILE") {
		t.Fatalf("remote object is not an age envelope: %.60q", body)
	}
	for _, leak := range []string{"VERY_SECRET_NAME", "notes about prod", "hunter2", "\"secrets\""} {
		if strings.Contains(body, leak) {
			t.Fatalf("envelope leaked %q to the backend", leak)
		}
	}
}

// TestAutoSync: with auto enabled, a mutating command pushes on its own and a fresh
// machine needs no manual sync invocation beyond configuration.
func TestAutoSync(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	t.Setenv("ARCA_SYNC_AUTO", "1")
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A") // PersistentPostRun should auto-push

	head, err := fake.Head(context.Background())
	if err != nil {
		t.Fatalf("auto-sync did not push: %v", err)
	}
	if head.Generation < 2 {
		t.Fatalf("auto-pushed generation = %d, want the post-set store", head.Generation)
	}

	// A read-only command must never FAIL because auto-sync can't reach the backend;
	// break the backend and confirm get still works (warning only).
	old := openBackend
	t.Cleanup(func() { openBackend = old })
	openBackend = func() (remote.Backend, error) { return nil, os.ErrDeadlineExceeded }
	if out := runArca(t, "", "get", "A"); out != "v1" {
		t.Fatalf("get under broken auto-sync backend = %q", out)
	}
}

// TestSyncStatusAndInit covers the config surface: `sync init` pins the URL (validated),
// `sync auto` toggles, and `sync status` never mutates anything.
func TestSyncStatusAndInit(t *testing.T) {
	sandbox(t)
	if err := runArcaErr("", "sync", "init", "ftp://nope"); err == nil {
		t.Fatal("sync init accepted a bogus URL")
	}
	runArca(t, "", "sync", "init", "s3://bucket/prefix?endpoint=localhost:9000&insecure=1")
	if cfg := loadSyncConfig(); cfg.URL == "" || cfg.Auto {
		t.Fatalf("sync.json after init = %+v", cfg)
	}
	runArca(t, "", "sync", "auto", "on")
	if !loadSyncConfig().Auto {
		t.Fatal("sync auto on did not persist")
	}
	runArca(t, "", "sync", "auto", "off")
	if loadSyncConfig().Auto {
		t.Fatal("sync auto off did not persist")
	}
}

// TestSyncURLResolution: env beats the pinned config; unconfigured is a clear error.
func TestSyncURLResolution(t *testing.T) {
	sandbox(t)
	if _, err := syncURL(); err == nil {
		t.Fatal("unconfigured syncURL should error")
	}
	runArca(t, "", "sync", "init", "s3://pinned/x?endpoint=h:1&insecure=1")
	u, err := syncURL()
	if err != nil || !strings.Contains(u, "pinned") {
		t.Fatalf("pinned url = %q err %v", u, err)
	}
	t.Setenv("ARCA_SYNC_URL", "s3://env-wins/y?endpoint=h:1")
	if u, _ := syncURL(); !strings.Contains(u, "env-wins") {
		t.Fatalf("env should win, got %q", u)
	}
	if autoSyncEnabled() {
		t.Fatal("auto should default off")
	}
	t.Setenv("ARCA_SYNC_AUTO", "on")
	if !autoSyncEnabled() {
		t.Fatal("ARCA_SYNC_AUTO=on should enable")
	}
}

// TestSyncStatusOutput covers both status branches: empty remote, then a synced one.
func TestSyncStatusOutput(t *testing.T) {
	sandbox(t)
	withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "", "sync", "status") // remote empty
	runArca(t, "v", "set", "A")
	runArca(t, "", "sync")
	runArca(t, "", "sync", "status") // synced
}

// TestPushStoreCASRace covers the losing side of a Head→Push race directly: the prev
// rev goes stale between reading the head and pushing.
func TestPushStoreCASRace(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "A")
	runArca(t, "", "sync")
	head, err := fake.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Another writer advances the head after we captured it.
	if _, err := fake.Push(context.Background(), []byte("interloper"), head.Generation+1, head); err != nil {
		t.Fatal(err)
	}
	s, raw, err := localStoreForSync()
	if err != nil {
		t.Fatal(err)
	}
	s.Generation += 5 // pretend a local mutation targeting a new generation
	if err := pushStore(context.Background(), fake, s, raw, head, loadSyncState(), false); err == nil || !strings.Contains(err.Error(), "reconcile") {
		t.Fatalf("stale-prev push = %v, want a CAS reconcile hint", err)
	}
}

// TestSyncPullBadEnvelope: a remote object that isn't a valid age envelope (or whose
// payload isn't a store) is rejected without touching the local store.
func TestSyncPullBadEnvelope(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")
	fake.Corrupt([]byte("not an envelope at all"), 99)
	err := runArcaErr("", "sync")
	if err == nil || !strings.Contains(err.Error(), "envelope") {
		t.Fatalf("garbage remote head accepted: %v", err)
	}
	if out := runArca(t, "", "get", "A"); out != "v1" {
		t.Fatalf("local store was damaged by a bad pull: %q", out)
	}
}

// TestAutoSyncGuards: the post-run hook is inert when the sync command itself ran, when
// auto is off, and it degrades to a warning when escrow material is unusable.
func TestAutoSyncGuards(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")

	maybeAutoSync(true) // the sync command already handled it
	if _, err := fake.Head(context.Background()); err == nil {
		t.Fatal("maybeAutoSync(invokedSync=true) must not touch the backend")
	}
	maybeAutoSync(false) // auto disabled: also inert
	if _, err := fake.Head(context.Background()); err == nil {
		t.Fatal("maybeAutoSync with auto off must not touch the backend")
	}
	t.Setenv("ARCA_SYNC_AUTO", "1")
	maybeAutoSync(false) // enabled: reconciles (bootstrap push of the init-only store)
	if _, err := fake.Head(context.Background()); err != nil {
		t.Fatalf("auto-sync did not push: %v", err)
	}
}

// TestEscrowSealFailureWarns: unusable recipients make escrow fail as a warning while
// the sync itself succeeds — escrow must never weaken the sync path.
func TestEscrowSealFailureWarns(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	escrowBestEffort(context.Background(), fake, []string{"not-a-recipient"})
	if keys, _ := fake.List(context.Background(), remote.KeyAudit); len(keys) != 0 {
		t.Fatalf("broken recipients still escrowed: %v", keys)
	}
}

// TestSyncFlagGuards pins every explicit flag refusal in the reconcile table.
func TestSyncFlagGuards(t *testing.T) {
	dir := sandbox(t)
	fake := withFakeBackend(t)
	if err := runArcaErr("", "sync", "--pull", "--push"); err == nil {
		t.Fatal("--pull --push should be refused")
	}
	// Empty remote + no local store: nothing to do either way.
	if err := runArcaErr("", "sync"); err == nil {
		t.Fatal("sync with neither side should error")
	}
	runArca(t, "", "init")
	if err := runArcaErr("", "sync", "--pull"); err == nil {
		t.Fatal("--pull against an empty remote should error")
	}
	runArca(t, "", "sync") // bootstrap push
	// Remote ahead + --push: refused with a pull hint.
	head, _ := fake.Head(context.Background())
	if _, err := fake.Push(context.Background(), []byte("other"), head.Generation+1, head); err != nil {
		t.Fatal(err)
	}
	// (remote object is garbage, but --push must refuse before ever fetching it)
	if err := runArcaErr("", "sync", "--push"); err == nil || !strings.Contains(err.Error(), "ahead") {
		t.Fatalf("--push with a remote ahead = %v", err)
	}
	// Fresh machine + --push: nothing local to push.
	switchMachine(t, dir)
	if err := runArcaErr("", "sync", "--push"); err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("--push with no local store = %v", err)
	}
}

// TestSyncLocalAheadPullRefusedAndRepair: --pull with unpushed local changes is refused;
// a local store rolled back below the sync cursor is repaired by pull.
func TestSyncLocalAheadPullRefused(t *testing.T) {
	sandbox(t)
	withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")
	runArca(t, "v2", "rotate", "A")
	if err := runArcaErr("", "sync", "--pull"); err == nil || !strings.Contains(err.Error(), "unpushed") {
		t.Fatalf("--pull with local changes = %v", err)
	}
	// Local rollback below the cursor: --push refuses, plain sync pulls the repair.
	s, raw, err := localStoreForSync()
	if err != nil {
		t.Fatal(err)
	}
	_ = s
	_ = raw
	runArca(t, "", "sync") // push v2 first so remote == local == gen N
	old, err := os.ReadFile(storePath())
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "v3", "rotate", "A")
	runArca(t, "", "sync")
	if err := os.WriteFile(storePath(), old, 0o600); err != nil { // roll local back
		t.Fatal(err)
	}
	if err := runArcaErr("", "sync", "--push"); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("--push with a rolled-back local = %v", err)
	}
	runArca(t, "", "sync") // plain sync repairs by pulling
	if out := runArca(t, "", "get", "A"); out != "v3" {
		t.Fatalf("after repair pull: get A = %q", out)
	}
}

// TestSyncForceOverridesRemoteRollback: --force is the documented escape hatch to push
// local state over a remote that regressed.
func TestSyncForceOverridesRemoteRollback(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")
	oldEnv, _, _ := fake.Fetch(context.Background())
	runArca(t, "v2", "rotate", "A")
	runArca(t, "", "sync")
	fake.Corrupt(oldEnv, 1) // remote regressed
	if err := runArcaErr("", "sync"); err == nil {
		t.Fatal("regressed remote must refuse a plain sync")
	}
	runArca(t, "v3", "rotate", "A")
	runArca(t, "", "sync", "--force") // local-wins push over the rollback
	env, head, err := fake.Fetch(context.Background())
	if err != nil || head.Generation < 4 {
		t.Fatalf("force push did not land: gen %d err %v", head.Generation, err)
	}
	if string(env) == string(oldEnv) {
		t.Fatal("remote still holds the rolled-back envelope")
	}
}

// TestPullRefusesHeadAheadOfEnvelope (SEC-38): a backend that advertises a HIGHER head
// generation than the envelope it actually serves is replaying/downgrading — the pull is
// refused as tamper rather than silently adopting the older payload. --force overrides.
func TestPullRefusesHeadAheadOfEnvelope(t *testing.T) {
	dir := sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")
	env, _, _ := fake.Fetch(context.Background())
	fake.Corrupt(env, 999) // honest envelope (gen 2), lying metadata tag (gen 999)
	switchMachine(t, dir)
	err := runArcaErr("", "sync") // bootstrap pull must refuse the mismatch
	if err == nil || !strings.Contains(err.Error(), "TAMPER") {
		t.Fatalf("head-ahead-of-envelope should be refused, got: %v", err)
	}
	// A benign metadata LAG (envelope newer than the claimed head) is only a warning, adopted.
	env2, _, _ := fake.Fetch(context.Background())
	fake.Corrupt(env2, 1) // metadata gen 1 < envelope gen 2 — lag, not tamper
	runArca(t, "", "sync")
	s, _, err := localStoreForSync()
	if err != nil || s == nil || s.Generation != 2 {
		t.Fatalf("benign metadata lag should adopt the envelope: %+v err %v", s, err)
	}
	_ = dir
}

// TestSyncStateConfigErrorPaths: state/config writers fail cleanly when the state dir
// is unwritable — and autoSyncEnabled treats every documented spelling correctly.
func TestSyncStateConfigErrorPaths(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	dir := sandbox(t)
	blocker := filepath.Join(dir, "blk")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", blocker) // state dir cannot be created
	if err := saveSyncState(syncState{LastGeneration: 1}); err == nil {
		t.Fatal("saveSyncState should fail under an uncreatable state dir")
	}
	if err := saveSyncConfig(syncConfig{URL: "s3://b"}); err == nil {
		t.Fatal("saveSyncConfig should fail under an uncreatable state dir")
	}
	for val, want := range map[string]bool{"1": true, "yes": true, "0": false, "off": false} {
		t.Setenv("ARCA_SYNC_AUTO", val)
		if autoSyncEnabled() != want {
			t.Fatalf("ARCA_SYNC_AUTO=%s = %v, want %v", val, autoSyncEnabled(), want)
		}
	}
}

// TestOpenEnvelopeNotAStore: a valid age envelope whose payload is not a store document
// is rejected during pull validation.
func TestOpenEnvelopeNotAStore(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	s, _, err := localStoreForSync()
	if err != nil {
		t.Fatal(err)
	}
	env, err := sealEnvelope([]byte("{\"not\": \"a store\"}"), s.Recipients)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := openEnvelope(env); err == nil || !strings.Contains(err.Error(), "validate") {
		t.Fatalf("non-store payload accepted: %v", err)
	}
	// And a payload no local identity can open.
	if _, _, err := openEnvelope([]byte("-----BEGIN AGE ENCRYPTED FILE-----\ngibberish\n-----END AGE ENCRYPTED FILE-----\n")); err == nil {
		t.Fatal("undecryptable envelope accepted")
	}
}

// TestAutoSyncStalePull: an auto-enabled READ command reconciles when the last sync is
// stale, adopting a remote that moved ahead.
func TestAutoSyncStalePull(t *testing.T) {
	dir := sandbox(t)
	fake := withFakeBackend(t)
	t.Setenv("ARCA_SYNC_AUTO", "1")
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A") // auto-pushes
	// Second machine pushes ahead.
	aStore, aAudit, aState := os.Getenv("ARCA_STORE"), os.Getenv("ARCA_AUDIT"), os.Getenv("XDG_STATE_HOME")
	switchMachine(t, dir)
	runArca(t, "", "sync")
	runArca(t, "v2", "rotate", "A") // auto-pushes from machine B
	if _, err := fake.Head(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Machine A: make its last sync look stale, then any command reconciles.
	t.Setenv("ARCA_STORE", aStore)
	t.Setenv("ARCA_AUDIT", aAudit)
	t.Setenv("XDG_STATE_HOME", aState)
	st := loadSyncState()
	st.LastSync = st.LastSync.Add(-time.Hour)
	if err := saveSyncState(st); err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "ls") // read-only command triggers the stale reconcile
	if out := runArca(t, "", "get", "A"); out != "v2" {
		t.Fatalf("stale auto-pull did not adopt the remote: get A = %q", out)
	}
}

// TestSyncAutoArgGuards: bad toggle values and auto-without-a-backend are refused.
func TestSyncAutoArgGuards(t *testing.T) {
	sandbox(t)
	if err := runArcaErr("", "sync", "auto", "maybe"); err == nil {
		t.Fatal("sync auto maybe should be refused")
	}
	if err := runArcaErr("", "sync", "auto", "on"); err == nil {
		t.Fatal("sync auto on without a configured backend should be refused")
	}
}

// TestSyncInitStoreCredentials: --store-credentials persists the env pair into the
// 0600 state-dir config, after which sync needs no environment; env still wins when
// both are present, and the flag without env is refused.
func TestSyncInitStoreCredentials(t *testing.T) {
	sandbox(t)
	// This test asserts the no-env refusal path, so clear any ambient sync credentials a
	// developer machine may carry (sandbox leaves them alone for the sync e2e test's sake).
	t.Setenv("ARCA_SYNC_ACCESS_KEY", "")
	t.Setenv("ARCA_SYNC_SECRET_KEY", "")
	if err := runArcaErr("", "sync", "init", "s3://b/x?endpoint=h:1", "--store-credentials"); err == nil {
		t.Fatal("--store-credentials without env should be refused")
	}
	t.Setenv("ARCA_SYNC_ACCESS_KEY", "AKIA-stored")
	t.Setenv("ARCA_SYNC_SECRET_KEY", "shh-stored")
	runArca(t, "", "sync", "init", "s3://b/x?endpoint=h:1", "--store-credentials")
	cfg := loadSyncConfig()
	if cfg.AccessKey != "AKIA-stored" || cfg.SecretKey != "shh-stored" {
		t.Fatalf("credentials not persisted: %+v", cfg)
	}
	if runtime.GOOS != "windows" { // Unix permission bits don't map on Windows
		fi, err := os.Stat(syncConfigPath())
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("sync.json mode = %v err %v, want 0600", fi.Mode(), err)
		}
	}
	// Resolution: env wins; with env cleared the stored pair is used.
	t.Setenv("ARCA_SYNC_ACCESS_KEY", "")
	t.Setenv("ARCA_SYNC_SECRET_KEY", "")
	// openBackend resolves through to NewS3, which must accept the stored pair
	// (construction succeeds; no network happens until a call).
	if _, err := openBackend(); err != nil {
		t.Fatalf("openBackend with stored credentials: %v", err)
	}
}

// TestResolveSyncCredentials pins the precedence contract: env wins per-field, the
// stored config fills gaps, and mixed sources compose.
func TestResolveSyncCredentials(t *testing.T) {
	sandbox(t)
	sc := syncConfig{AccessKey: "cfg-ak", SecretKey: "cfg-sk"}

	t.Setenv("ARCA_SYNC_ACCESS_KEY", "")
	t.Setenv("ARCA_SYNC_SECRET_KEY", "")
	if a, s := resolveSyncCredentials(sc); a != "cfg-ak" || s != "cfg-sk" {
		t.Fatalf("config fallback = %q/%q", a, s)
	}
	t.Setenv("ARCA_SYNC_ACCESS_KEY", "env-ak")
	t.Setenv("ARCA_SYNC_SECRET_KEY", "env-sk")
	if a, s := resolveSyncCredentials(sc); a != "env-ak" || s != "env-sk" {
		t.Fatalf("env should win = %q/%q", a, s)
	}
	t.Setenv("ARCA_SYNC_SECRET_KEY", "")
	if a, s := resolveSyncCredentials(sc); a != "env-ak" || s != "cfg-sk" {
		t.Fatalf("mixed sources = %q/%q", a, s)
	}
	if a, s := resolveSyncCredentials(syncConfig{}); a != "env-ak" || s != "" {
		t.Fatalf("nothing stored, partial env = %q/%q", a, s)
	}
}

// TestPullRefusesRecipientBroadening (SEC-35): a pulled store that ADDS a recipient not in
// the local set is refused without --force — the recipient-resurrection / injection defense.
// Two machines share the identity; A adds a recipient and pushes, B (which never saw it) must
// refuse the broadening on its fast-forward pull.
func TestPullRefusesRecipientBroadening(t *testing.T) {
	dir := sandbox(t)
	withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync") // A pushes the single-recipient store

	aStore, aAudit, aState := os.Getenv("ARCA_STORE"), os.Getenv("ARCA_AUDIT"), os.Getenv("XDG_STATE_HOME")
	switchMachine(t, dir)
	runArca(t, "", "sync") // B bootstraps: recipients == [self]

	// A adds an attacker key and pushes the broader store at a higher generation.
	t.Setenv("ARCA_STORE", aStore)
	t.Setenv("ARCA_AUDIT", aAudit)
	t.Setenv("XDG_STATE_HOME", aState)
	_, evilRec, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "recipients", "add", evilRec)
	runArca(t, "", "reencrypt")
	runArca(t, "", "sync")

	// B fast-forward-pulls the broader store — the added recipient must be refused.
	switchMachine(t, dir)
	err = runArcaErr("", "sync")
	if err == nil || !strings.Contains(err.Error(), "ADD") {
		t.Fatalf("recipient-broadening pull should be refused, got: %v", err)
	}
	// --force adopts it deliberately.
	runArca(t, "", "sync", "--force")
}

// TestPullDurableFloorRefusesRollback (SEC-35): the rollback floor is the durable high-water
// mark, so a replayed OLD envelope is refused even after the sync cursor is wiped.
func TestPullDurableFloorRefusesRollback(t *testing.T) {
	dir := sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")
	old, oldRev, _ := fake.Fetch(context.Background())
	runArca(t, "v2", "rotate", "A")
	runArca(t, "", "sync") // now at a higher generation; HWM advanced

	// Wipe the sync cursor (the resettable file the OLD code trusted); the durable store.gen
	// high-water mark still remembers the newer generation. Local is ahead of the wiped cursor,
	// so the explicit `--pull` resolution routes to the pull path where the floor is enforced.
	if err := os.Remove(syncStatePath()); err != nil {
		t.Fatal(err)
	}
	fake.Corrupt(old, oldRev.Generation) // backend replays the old envelope (generation 2)

	err := runArcaErr("", "sync", "--pull")
	if err == nil || !strings.Contains(err.Error(), "ROLLBACK") {
		t.Fatalf("replayed old envelope should be refused by the durable floor, got: %v", err)
	}
	_ = dir
}

// TestSyncConfigAtomicMode (SEC-37): saveSyncConfig writes 0600 atomically even when the
// file already exists with a looser mode (the reachable "init URL then add credentials" path).
func TestSyncConfigAtomicMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix perm bits")
	}
	sandbox(t)
	runArca(t, "", "sync", "init", "s3://b/x?endpoint=h:1&insecure=1") // URL only
	// Loosen the mode as a hostile/careless restore might.
	if err := os.Chmod(syncConfigPath(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARCA_SYNC_ACCESS_KEY", "AKIA")
	t.Setenv("ARCA_SYNC_SECRET_KEY", "shh")
	runArca(t, "", "sync", "init", "s3://b/x?endpoint=h:1&insecure=1", "--store-credentials")
	fi, err := os.Stat(syncConfigPath())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("credential rewrite did not re-tighten to 0600: mode=%v err=%v", fi.Mode(), err)
	}
}

// TestAddedRecipients pins the recipient-diff helper directly.
func TestAddedRecipients(t *testing.T) {
	if got := addedRecipients([]string{"a", "b"}, []string{"a", "b"}); len(got) != 0 {
		t.Fatalf("no change should add nothing, got %v", got)
	}
	if got := addedRecipients([]string{"a", "b"}, []string{"a"}); len(got) != 0 {
		t.Fatalf("narrowing should add nothing, got %v", got)
	}
	if got := addedRecipients([]string{"a"}, []string{"a", "c"}); len(got) != 1 || got[0] != "c" {
		t.Fatalf("broadening should report the added key, got %v", got)
	}
}

// TestPullRecipientNarrowingAllowed: removing a recipient on pull is fine (not a broadening).
func TestPullRecipientNarrowingAllowed(t *testing.T) {
	dir := sandbox(t)
	withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	_, rec, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "recipients", "add", rec)
	runArca(t, "", "reencrypt")
	runArca(t, "", "sync") // broad store pushed

	aStore, aAudit, aState := os.Getenv("ARCA_STORE"), os.Getenv("ARCA_AUDIT"), os.Getenv("XDG_STATE_HOME")
	switchMachine(t, dir)
	runArca(t, "", "sync") // B bootstraps with both recipients

	// A narrows back to one recipient and pushes.
	t.Setenv("ARCA_STORE", aStore)
	t.Setenv("ARCA_AUDIT", aAudit)
	t.Setenv("XDG_STATE_HOME", aState)
	runArca(t, "", "recipients", "rm", rec)
	runArca(t, "", "reencrypt")
	runArca(t, "", "sync")

	// B fast-forward-pulls the narrowed store — allowed, no --force needed.
	switchMachine(t, dir)
	runArca(t, "", "sync")
	if out := runArca(t, "", "get", "A"); out != "v1" {
		t.Fatalf("narrowed pull should succeed: get A = %q", out)
	}
}

// TestOpenEnvelopeValidationBranches exercises the three minimum-validity refusals directly.
func TestOpenEnvelopeValidationBranches(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	s, _, err := localStoreForSync()
	if err != nil {
		t.Fatal(err)
	}
	rec := s.Recipients
	for _, tc := range []struct{ name, body string }{
		{"no recipients", `{"version":1,"generation":2,"recipients":[],"secrets":{}}`},
		{"zero generation", `{"version":1,"generation":0,"recipients":["age1x"],"secrets":{}}`},
	} {
		env, err := sealEnvelope([]byte(tc.body), rec)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := openEnvelope(env); err == nil {
			t.Fatalf("%s should be refused", tc.name)
		}
	}
	// A valid minimal store passes.
	env, _ := sealEnvelope([]byte(`{"version":1,"generation":3,"recipients":["age1x"],"secrets":{}}`), rec)
	if _, got, err := openEnvelope(env); err != nil || got.Generation != 3 {
		t.Fatalf("valid store should open: %+v err %v", got, err)
	}
}

// TestWriteLocalStoreAndErrors covers writeLocalStore's happy path and localStoreForSync's
// missing-store path (returns nil, nil, nil to allow bootstrap).
func TestWriteLocalStoreAndErrors(t *testing.T) {
	sandbox(t)
	// No store yet: localStoreForSync reports "nothing local" without error.
	s, raw, err := localStoreForSync()
	if err != nil || s != nil || raw != nil {
		t.Fatalf("missing store should be (nil,nil,nil), got %v %v %v", s, raw, err)
	}
	if err := writeLocalStore([]byte(`{"version":1,"generation":1,"recipients":["age1x"],"secrets":{}}`)); err != nil {
		t.Fatalf("writeLocalStore: %v", err)
	}
	fi, err := os.Stat(storePath())
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("written store mode = %v, want 0600", fi.Mode())
	}
}

// TestPushStoreCASReconcileHint: a CAS mismatch surfaces with the reconcile hint.
func TestPushStoreCASReconcileHint(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")
	// Another writer advances the head; our stale-prev push must mismatch with a hint.
	head, _ := fake.Head(context.Background())
	if _, err := fake.Push(context.Background(), []byte("other"), head.Generation+1, head); err != nil {
		t.Fatal(err)
	}
	s, raw, _ := localStoreForSync()
	s.Generation += 3
	err := pushStore(context.Background(), fake, s, raw, head, loadSyncState(), false)
	if err == nil || !strings.Contains(err.Error(), "reconcile") {
		t.Fatalf("stale push should hint reconcile, got: %v", err)
	}
}

// TestRunSyncDecisionTableErrors covers the reconcile guard branches that return errors.
func TestRunSyncDecisionTableErrors(t *testing.T) {
	dir := sandbox(t)
	fake := withFakeBackend(t)

	// Neither side present.
	if err := runArcaErr("", "sync"); err == nil {
		t.Fatal("no local + empty remote should error")
	}
	// --pull against an empty remote.
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	if err := runArcaErr("", "sync", "--pull"); err == nil {
		t.Fatal("--pull against empty remote should error")
	}
	runArca(t, "", "sync") // bootstrap push
	// Remote ahead + --push refuses.
	head, _ := fake.Head(context.Background())
	if _, err := fake.Push(context.Background(), []byte("x"), head.Generation+1, head); err != nil {
		t.Fatal(err)
	}
	if err := runArcaErr("", "sync", "--push"); err == nil || !strings.Contains(err.Error(), "ahead") {
		t.Fatalf("--push with remote ahead = %v", err)
	}
	// Fresh machine + --push has nothing to push.
	switchMachine(t, dir)
	if err := runArcaErr("", "sync", "--push"); err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("--push on fresh machine = %v", err)
	}
}

// TestEscrowBestEffortWarns: escrowBestEffort never returns an error; a broken recipient set
// warns and the sync path is unaffected.
func TestEscrowBestEffortWarns(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	escrowBestEffort(context.Background(), fake, []string{"not-a-valid-recipient"})
	if keys, _ := fake.List(context.Background(), remote.KeyAudit); len(keys) != 0 {
		t.Fatalf("broken escrow should have shipped nothing, got %v", keys)
	}
}

// TestSyncStatusBranches covers sync status against an empty and a populated remote.
func TestSyncStatusBranches(t *testing.T) {
	sandbox(t)
	withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "", "sync", "status") // empty remote branch
	runArca(t, "v", "set", "A")
	runArca(t, "", "sync")
	runArca(t, "", "sync", "status") // synced branch
}

// captureStderr swaps os.Stderr for a temp file around fn and returns what was written,
// mirroring execArca's stdout swap. Not parallel-safe (shares the process global).
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp("", "arca-err-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	oldStderr, oldLog := os.Stderr, syncLog
	os.Stderr, syncLog = f, f // syncLog is the sync subsystem's own sink; redirect both
	defer func() { os.Stderr, syncLog = oldStderr, oldLog; f.Close() }()
	fn()
	_ = f.Sync()
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f.Name())
	return string(b)
}

// TestSyncQuietSuppressesInformationalOutput locks in the auto-sync UX fix: an up-to-date sync
// announces "in sync: nothing to do" only when NOT quiet. The quiet path (used by opportunistic
// auto-sync) must stay silent so its output never trails another command — e.g. appending to
// `get`'s deliberately newline-free value (`<value>in sync: nothing to do`).
func TestSyncQuietSuppressesInformationalOutput(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "A")
	runArca(t, "", "sync") // now L == S == R: the "nothing to do" branch

	verbose := captureStderr(t, func() {
		if err := runSyncCtx(context.Background(), fake, false, false, false, false); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(verbose, "in sync: nothing to do") {
		t.Fatalf("explicit sync should announce being up to date, got %q", verbose)
	}

	quiet := captureStderr(t, func() {
		if err := runSyncCtx(context.Background(), fake, false, false, false, true); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(quiet, "nothing to do") {
		t.Fatalf("quiet auto-sync must not print the up-to-date notice, got %q", quiet)
	}
}

// TestNewlineGuard: the guard prepends exactly one newline before the first byte and then
// passes through unchanged, and writes nothing when nothing is written.
func TestNewlineGuard(t *testing.T) {
	var buf strings.Builder
	g := &newlineGuard{w: &buf}
	fmt.Fprint(g, "first")
	fmt.Fprint(g, " second")
	if got := buf.String(); got != "\nfirst second" {
		t.Fatalf("guard output = %q, want %q", got, "\nfirst second")
	}

	var empty strings.Builder
	eg := &newlineGuard{w: &empty}
	fmt.Fprint(eg, "") // a zero-length write must not trigger the leading newline
	if empty.Len() != 0 {
		t.Fatalf("empty write should produce nothing, got %q", empty.String())
	}
}

// TestAutoSyncOutputNeverTrailsCommand locks in the collision fix end to end: when auto-sync
// emits a warning (here, a failing audit escrow) it must begin on its own line rather than
// running into a preceding `get`'s newline-free value. It exercises maybeAutoSync via the same
// syncLog guard the real post-command hook installs.
func TestAutoSyncOutputNeverTrailsCommand(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "A") // leaves an un-escrowed audit event to ship

	// Force a real warning: escrow to a broken recipient set, routed through the guard
	// exactly as maybeAutoSync routes auto-sync output.
	out := captureStderr(t, func() {
		prev := syncLog
		syncLog = &newlineGuard{w: os.Stderr}
		defer func() { syncLog = prev }()
		escrowBestEffort(context.Background(), fake, []string{"not-a-valid-recipient"})
	})
	if !strings.HasPrefix(out, "\n") {
		t.Fatalf("guarded auto-sync output must start on its own line, got %q", out)
	}
	if !strings.Contains(out, "audit escrow failed") {
		t.Fatalf("the warning itself must still be visible, got %q", out)
	}
}
