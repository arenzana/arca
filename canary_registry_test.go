package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/store"
)

// TestCanaryCommandRegistryFailure covers the command-level error path: if the registry can't be
// written, `canary` and `set --canary` surface a clear "failed to arm" error rather than silently
// leaving the secret unarmed.
func TestCanaryCommandRegistryFailure(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")
	// Point the state dir at a path whose parent is a regular file, so the registry write fails.
	blocker := filepath.Join(dir, "blk")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", blocker)
	if err := runArcaErr("", "canary", "TRAP"); err == nil {
		t.Fatal("canary plant should fail when the registry can't be written")
	}
	if err := runArcaErr("v", "set", "S", "--canary"); err == nil {
		t.Fatal("set --canary should fail when the registry can't be written")
	}
}

// TestCanaryRegistryRoundTrip exercises the registry helpers directly: mark, detect (registry and
// legacy-flag paths), unmark, and the persisted set.
func TestCanaryRegistryRoundTrip(t *testing.T) {
	sandbox(t)
	if err := markCanary("A"); err != nil {
		t.Fatal(err)
	}
	if err := markCanary("B"); err != nil {
		t.Fatal(err)
	}
	if !isCanary("A", nil) || !isCanary("B", nil) {
		t.Fatal("marked canaries not detected via the registry")
	}
	if isCanary("C", nil) {
		t.Fatal("an unmarked name reported as a canary")
	}
	if !isCanary("Z", &store.Secret{Canary: true}) {
		t.Fatal("legacy store flag not honored")
	}
	if err := unmarkCanary("A"); err != nil {
		t.Fatal(err)
	}
	if isCanary("A", nil) {
		t.Fatal("A still a canary after unmark")
	}
	if reg, _ := loadCanaries(); len(reg) != 1 || !reg["B"] {
		t.Fatalf("registry after mark/unmark = %v, want {B}", reg)
	}
}

// TestCanaryRegistryErrors covers the registry's failure branches: a corrupt registry file makes
// every reader/writer surface the error (and isCanary fail safe to "not a canary"), and an
// unwritable state dir makes saves fail.
func TestCanaryRegistryErrors(t *testing.T) {
	dir := sandbox(t)

	// A corrupt registry file: loads fail and the error propagates through every helper.
	if err := os.MkdirAll(filepath.Dir(canariesPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(canariesPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCanaries(); err == nil {
		t.Fatal("loadCanaries should fail on a corrupt registry")
	}
	if isCanary("X", nil) {
		t.Fatal("isCanary must be false (fail-safe) on a corrupt registry")
	}
	if err := markCanary("X"); err == nil {
		t.Fatal("markCanary should surface the read error")
	}
	if err := unmarkCanary("X"); err == nil {
		t.Fatal("unmarkCanary should surface the read error")
	}
	if err := renameCanary("X", "Y"); err == nil {
		t.Fatal("renameCanary should surface the read error")
	}

	// An unwritable state dir (its parent is a regular file) makes saves fail.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", blocker) // stateDir() = blocker/arca → MkdirAll can't create it
	if err := saveCanaries(map[string]bool{"A": true}); err == nil {
		t.Fatal("saveCanaries should fail when the state dir can't be created")
	}
}

// TestCanaryNotInStore is the core of SEC-04: planting a canary must NOT record the designation in
// the (git-synced) store — it lives only in the local registry — so someone who obtains the store
// file cannot tell the decoy from a real secret.
func TestCanaryNotInStore(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "", "canary", "TRAP", "--template", "github")
	runArca(t, "realvalue", "set", "REAL")

	// The store entry must exist but carry no canary flag...
	s, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	if s.Secrets["TRAP"] == nil {
		t.Fatal("canary secret was not stored")
	}
	if s.Secrets["TRAP"].Canary {
		t.Fatal("canary flag was persisted to the store (SEC-04 regression)")
	}
	// ...and the raw store bytes must not contain the word "canary" at all.
	raw, err := os.ReadFile(storePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "canary") {
		t.Fatalf("store file leaks the canary designation: %s", raw)
	}

	// The registry, in the state dir, is where it actually lives.
	reg, err := loadCanaries()
	if err != nil {
		t.Fatal(err)
	}
	if !reg["TRAP"] {
		t.Fatal("canary not recorded in the local registry")
	}
	if reg["REAL"] {
		t.Fatal("a non-canary secret ended up in the registry")
	}
}

// TestCanaryRegistryTrips confirms a registry-only canary (no store flag) still trips the gate.
func TestCanaryRegistryTrips(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "", "canary", "BAIT")
	runArca(t, "", "get", "BAIT")

	a, _ := audit.Open(auditPath())
	defer a.Close()
	if _, n, _ := a.LastOp("BAIT", "canary"); n < 1 {
		t.Fatal("a registry canary did not trip on get")
	}
}

// TestCanaryLegacyStoreFlagTrips confirms backward compatibility: a secret carrying the old
// pre-0.6.2 store flag (with nothing in the registry) is still detected as a canary.
func TestCanaryLegacyStoreFlagTrips(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "decoy", "set", "OLD")

	// Simulate a store written by an older arca: canary flag set, registry empty.
	s, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	s.Secrets["OLD"].Canary = true
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	runArca(t, "", "get", "OLD")
	a, _ := audit.Open(auditPath())
	defer a.Close()
	if _, n, _ := a.LastOp("OLD", "canary"); n < 1 {
		t.Fatal("a legacy store-flagged canary did not trip")
	}
	// It also shows up in `canary --list`.
	if out := runArca(t, "", "canary", "--list"); !strings.Contains(out, "OLD") {
		t.Fatalf("legacy canary missing from --list: %q", out)
	}
}

// TestCanaryRenameFollows verifies a renamed decoy keeps its designation (the registry moves).
func TestCanaryRenameFollows(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "", "canary", "TRAP")
	runArca(t, "", "rename", "TRAP", "MOVED")

	reg, _ := loadCanaries()
	if reg["TRAP"] || !reg["MOVED"] {
		t.Fatalf("canary registry did not follow the rename: %v", reg)
	}
	runArca(t, "", "get", "MOVED")
	a, _ := audit.Open(auditPath())
	defer a.Close()
	if _, n, _ := a.LastOp("MOVED", "canary"); n < 1 {
		t.Fatal("renamed canary did not trip under its new name")
	}
}

// TestCanaryRenameForceClearsStale covers FU-4: rename --force of a non-canary onto an existing
// canary must clear the stale registry entry, so the real value now at that name doesn't trip a
// false-positive alert.
func TestCanaryRenameForceClearsStale(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "", "canary", "DST")                   // DST is a decoy
	runArca(t, "realvalue", "set", "SRC")             // SRC is a real secret
	runArca(t, "", "rename", "SRC", "DST", "--force") // SRC's value overwrites DST
	reg, _ := loadCanaries()
	if reg["DST"] {
		t.Fatal("rename --force left a stale canary registry entry on the destination")
	}
	if reg["SRC"] {
		t.Fatal("source lingered in the canary registry after rename")
	}
}

// TestCanaryUnmarkAndRm confirms `set --canary=false` disarms a canary and `rm` cleans the registry.
func TestCanaryUnmarkAndRm(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "S", "--canary")
	if reg, _ := loadCanaries(); !reg["S"] {
		t.Fatal("set --canary did not arm the registry")
	}
	runArca(t, "v", "set", "S", "--canary=false")
	if reg, _ := loadCanaries(); reg["S"] {
		t.Fatal("set --canary=false did not disarm the registry")
	}

	runArca(t, "v", "set", "T", "--canary")
	runArca(t, "", "rm", "T")
	if reg, _ := loadCanaries(); reg["T"] {
		t.Fatal("rm did not clean the canary registry")
	}
}
