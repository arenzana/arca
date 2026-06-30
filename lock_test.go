package main

import (
	"os"
	"path/filepath"
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
