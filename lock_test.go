package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arenzana/arca/internal/xdg"
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
	lock := xdg.StorePath() + ".lock"
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
	lock := xdg.StorePath() + ".lock"
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

	lock := xdg.StorePath() + ".lock"
	time.Sleep(3 * staleLockAge) // well past the stale threshold
	fi, err := os.Stat(lock)
	if err != nil {
		t.Fatalf("held lock disappeared: %v", err)
	}
	if age := time.Since(fi.ModTime()); age > staleLockAge {
		t.Fatalf("heartbeat did not keep the lock fresh: mtime age %v > staleLockAge %v", age, staleLockAge)
	}
}

// TestLockStoreForNonBlocking pins the wait budget added for opportunistic auto-sync: a
// timeout <= 0 makes exactly one attempt and reports errStoreLocked, so background work can
// tell "someone else is holding it" apart from a real failure and skip. Without this,
// auto-sync would sit for lockTimeout behind an `arca edit` session an operator left open.
func TestLockStoreForNonBlocking(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	unlock, err := lockStore()
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	release, err := lockStoreFor(0)
	elapsed := time.Since(start)
	if err == nil {
		release()
		unlock()
		t.Fatal("lockStoreFor(0) acquired a lock that was already held")
	}
	if !errors.Is(err, errStoreLocked) {
		t.Fatalf("lockStoreFor(0) = %v, want errStoreLocked so a caller can skip on contention", err)
	}
	if elapsed > time.Second {
		t.Fatalf("lockStoreFor(0) waited %v; it must not block", elapsed)
	}
	// The message still names the lock file, which is the operator's escape hatch.
	if !strings.Contains(err.Error(), xdg.StorePath()+".lock") {
		t.Fatalf("contention error lost the lock path: %v", err)
	}

	// Once the holder releases, the same non-blocking call succeeds.
	unlock()
	release, err = lockStoreFor(0)
	if err != nil {
		t.Fatalf("lockStoreFor(0) on a free lock = %v, want success", err)
	}
	release()

	// A blocking caller still waits and still succeeds — lockStore's 16 existing call sites
	// keep their behaviour.
	release, err = lockStoreFor(lockTimeout)
	if err != nil {
		t.Fatalf("lockStoreFor(lockTimeout) on a free lock = %v", err)
	}
	release()
}
