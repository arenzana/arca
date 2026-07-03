package main

import (
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
