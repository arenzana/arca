package main

import (
	"os"
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/store"
)

// TestSaveBumpsGeneration confirms every store write advances the monotonic generation counter,
// which is what makes a later rollback detectable (SEC-14).
func TestSaveBumpsGeneration(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "A")
	s1, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "v2", "set", "B")
	s2, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	if s2.Generation <= s1.Generation {
		t.Fatalf("Save did not bump generation: %d -> %d", s1.Generation, s2.Generation)
	}
}

// TestStoreRollbackDetection covers SEC-14's high-water logic: a generation that goes backwards is
// flagged, the mark stays high across a rollback (so the warning persists), and advancing past the
// mark clears it.
func TestStoreRollbackDetection(t *testing.T) {
	sandbox(t)

	if reg, _ := recordStoreGeneration(5); reg {
		t.Fatal("first sighting should not be a rollback")
	}
	if reg, _ := recordStoreGeneration(7); reg {
		t.Fatal("advancing the generation should not be a rollback")
	}
	if reg, prev := recordStoreGeneration(3); !reg || prev != 7 {
		t.Fatalf("rollback to 3 not flagged (reg=%v prev=%d, want true/7)", reg, prev)
	}
	if reg, _ := recordStoreGeneration(3); !reg {
		t.Fatal("the high-water mark must stay high after a rollback (still flagged)")
	}
	if reg, _ := recordStoreGeneration(8); reg {
		t.Fatal("advancing past the mark should clear the rollback flag")
	}
}

// TestVerifyDetectsStoreRollback covers the SEC-14 hardening: the store generation is bound into
// each hashed audit event, so `log --verify` detects a restored older store copy from the
// tamper-evident log itself — no local high-water mark required.
func TestVerifyDetectsStoreRollback(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")

	// Snapshot the store, then advance it (a rotate bumps the generation and is audited).
	old, err := os.ReadFile(storePath())
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "v2", "rotate", "A")
	runArca(t, "", "log", "--verify") // intact store: verify passes

	// Restore the older copy — the resurrection scenario. Verify must now fail loudly, even
	// though the local high-water mark file is wiped (the heuristic a machine owner can reset).
	if err := os.WriteFile(storePath(), old, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(storeGenPath()); err != nil {
		t.Fatal(err)
	}
	err = runArcaErr("", "log", "--verify")
	if err == nil {
		t.Fatal("log --verify passed on a rolled-back store")
	}
	if !strings.Contains(err.Error(), "ROLLBACK") {
		t.Fatalf("expected a rollback verdict, got: %v", err)
	}
}

// TestVerifyDetectsInLogGenerationRegression: if operations continue against a rolled-back store,
// the log itself records a generation going backwards — also a verify failure.
func TestVerifyDetectsInLogGenerationRegression(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	old, err := os.ReadFile(storePath())
	if err != nil {
		t.Fatal(err)
	}
	// Advance the store twice so a post-rollback write (old generation + 1) still lands below
	// the audited maximum — a single-step rollback re-records the same generation, which only
	// the store-older-than-log check can see.
	runArca(t, "v2", "rotate", "A")
	runArca(t, "v3", "rotate", "A")
	if err := os.WriteFile(storePath(), old, 0o600); err != nil {
		t.Fatal(err)
	}
	// Keep operating on the rolled-back store: the new event records an older generation.
	runArca(t, "v4", "rotate", "A")
	err = runArcaErr("", "log", "--verify")
	if err == nil {
		t.Fatal("log --verify passed despite a generation regression recorded in the log")
	}
	if !strings.Contains(err.Error(), "ROLLBACK") {
		t.Fatalf("expected a rollback verdict, got: %v", err)
	}
}
