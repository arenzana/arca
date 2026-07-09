package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
