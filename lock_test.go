package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLockStoreOpenError covers the non-EEXIST open-failure branch (the lock's directory is
// missing, so the exclusive create fails outright).
func TestLockStoreOpenError(t *testing.T) {
	sandbox(t)
	t.Setenv("ARCA_STORE", filepath.Join(t.TempDir(), "nodir", "store.json"))
	if _, err := lockStore(); err == nil {
		t.Fatal("expected lockStore to error when the lock directory is missing")
	}
}

func TestLockStore(t *testing.T) {
	sandbox(t)

	rel, err := lockStore()
	if err != nil {
		t.Fatal(err)
	}

	// A second acquisition while the first is held contends and fails (quickly).
	old := lockTimeout
	lockTimeout = 60 * time.Millisecond
	defer func() { lockTimeout = old }()
	if _, err := lockStore(); err == nil {
		t.Fatal("expected a held lock to block a second acquisition")
	}

	rel() // release; now it acquires again
	rel2, err := lockStore()
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	rel2()

	// A lock older than staleLockAge is treated as abandoned and stolen.
	lock := storePath() + ".lock"
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-time.Hour)
	if err := os.Chtimes(lock, stale, stale); err != nil {
		t.Fatal(err)
	}
	oldStale := staleLockAge
	staleLockAge = time.Second
	defer func() { staleLockAge = oldStale }()
	rel3, err := lockStore()
	if err != nil {
		t.Fatalf("expected to steal a stale lock: %v", err)
	}
	rel3()
}

// TestLockTokenPathSafe guards against the Windows regression where the lock token contained ':'
// (illegal in a Windows filename): the token is used to build the steal-rename temp path, so it
// must not carry any path-unsafe character.
func TestLockTokenPathSafe(t *testing.T) {
	tok, err := lockToken()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(tok, `:\/`) {
		t.Fatalf("lock token %q contains a path-unsafe character", tok)
	}
}

// TestLockReleaseChecksOwnership covers SEC-08: a process whose lock was reclaimed (so the file now
// holds a different token) must not delete the successor's lock on release.
func TestLockReleaseChecksOwnership(t *testing.T) {
	sandbox(t)
	rel, err := lockStore()
	if err != nil {
		t.Fatal(err)
	}
	lock := storePath() + ".lock"
	// Simulate a successor taking over: overwrite the lock with a different owner's token.
	if err := os.WriteFile(lock, []byte("99999:deadbeef"), 0o600); err != nil {
		t.Fatal(err)
	}
	rel() // must be a no-op: we no longer own the lock
	if _, err := os.Stat(lock); err != nil {
		t.Fatalf("release deleted a lock owned by someone else: %v", err)
	}
	_ = os.Remove(lock)
}

// TestLockHeartbeat covers SEC-08: while a lock is held, its mtime is refreshed, so a live holder
// past staleLockAge is not mistaken for a crash and stolen.
func TestLockHeartbeat(t *testing.T) {
	sandbox(t)
	oldStale := staleLockAge
	staleLockAge = 150 * time.Millisecond // heartbeat ticks every ~50ms
	defer func() { staleLockAge = oldStale }()

	rel, err := lockStore()
	if err != nil {
		t.Fatal(err)
	}
	defer rel()

	lock := storePath() + ".lock"
	time.Sleep(3 * staleLockAge) // well past the stale threshold
	fi, err := os.Stat(lock)
	if err != nil {
		t.Fatalf("held lock disappeared: %v", err)
	}
	if age := time.Since(fi.ModTime()); age > staleLockAge {
		t.Fatalf("heartbeat did not keep the lock fresh: mtime age %v > staleLockAge %v", age, staleLockAge)
	}
}
