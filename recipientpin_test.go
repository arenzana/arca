package main

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

// newRecipientKey returns a syntactically real age recipient, so these tests exercise the same
// strings the store actually holds rather than a placeholder the parser would reject.
func newRecipientKey(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id.Recipient().String()
}

// injectRecipient adds a key straight to the stored file, modelling the T12 case the pin exists
// for: a recipient added on ANOTHER machine and pulled in by sync. It never goes through
// `recipients add`, so it never meets this machine's terminal anchor.
func injectRecipient(t *testing.T, key string) {
	t.Helper()
	s, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	s.Recipients = append(s.Recipients, key)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
}

func TestRecipientPinTrustOnFirstUse(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	if _, ok := readRecipientPin(); ok {
		t.Fatal("no pin should exist before the store is first loaded")
	}
	s, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	pin, ok := readRecipientPin()
	if !ok {
		t.Fatal("loading the store should establish the baseline on first use")
	}
	if len(pin) != len(s.Recipients) {
		t.Fatalf("pin has %d recipient(s), store has %d", len(pin), len(s.Recipients))
	}
	// A freshly pinned store is by definition not drifted.
	added, removed, pinned := recipientDrift(s)
	if !pinned || len(added) != 0 || len(removed) != 0 {
		t.Fatalf("fresh pin should show no drift, got added=%v removed=%v pinned=%v", added, removed, pinned)
	}
}

func TestRecipientDriftReportsSyncedInKey(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if _, err := openStore(); err != nil { // establish the baseline
		t.Fatal(err)
	}

	attacker := newRecipientKey(t)
	injectRecipient(t, attacker)

	s, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	added, _, pinned := recipientDrift(s)
	if !pinned {
		t.Fatal("baseline should still exist after a store write")
	}
	if len(added) != 1 || added[0] != attacker {
		t.Fatalf("drift should name the injected key, got %v", added)
	}

	// Loading the store must NOT quietly accept it: a warning that silences itself would report
	// each injected key exactly once, which is indistinguishable from not reporting it.
	if _, err := openStore(); err != nil {
		t.Fatal(err)
	}
	if added, _, _ := recipientDrift(s); len(added) != 1 {
		t.Fatalf("reloading must not absorb the injected key into the baseline, got %v", added)
	}
}

// The property that makes the unanchored removal path safe. `recipients rm` is deliberately not
// anchored, because removal only ever restricts. If it re-pinned from the store instead of
// editing the pin, removing any key at all would accept every other pending change with it,
// handing an agent an unanchored way to launder an injected key into the baseline.
func TestPinRemoveDoesNotAcceptUnrelatedDrift(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if _, err := openStore(); err != nil {
		t.Fatal(err)
	}

	victim := newRecipientKey(t)
	if err := pinAdd(victim); err != nil { // a key this machine legitimately accepted earlier
		t.Fatal(err)
	}
	attacker := newRecipientKey(t)
	injectRecipient(t, attacker)

	if err := pinRemove(victim); err != nil {
		t.Fatal(err)
	}

	s, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	added, _, _ := recipientDrift(s)
	if len(added) != 1 || added[0] != attacker {
		t.Fatalf("removing one key must leave the injected key reported, got %v", added)
	}
	if pin, _ := readRecipientPin(); pin[victim] {
		t.Fatal("pinRemove should have dropped the removed key from the baseline")
	}
}

// The same property on the add path: approving one key approves that key, not whatever else has
// arrived since. Re-pinning from the store here would turn an approval of one key into an
// approval of every key present.
func TestPinAddAcceptsOnlyTheGivenKeys(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if _, err := openStore(); err != nil {
		t.Fatal(err)
	}

	attacker := newRecipientKey(t)
	injectRecipient(t, attacker)
	approved := newRecipientKey(t)
	injectRecipient(t, approved)

	if err := pinAdd(approved); err != nil {
		t.Fatal(err)
	}
	s, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	added, _, _ := recipientDrift(s)
	if len(added) != 1 || added[0] != attacker {
		t.Fatalf("only the approved key should be accepted, still-reported = %v", added)
	}
}

func TestRecipientDriftReportsRemoval(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if _, err := openStore(); err != nil {
		t.Fatal(err)
	}
	gone := newRecipientKey(t)
	if err := pinAdd(gone); err != nil {
		t.Fatal(err)
	}
	s, err := openStore()
	if err != nil {
		t.Fatal(err)
	}
	_, removed, _ := recipientDrift(s)
	if len(removed) != 1 || removed[0] != gone {
		t.Fatalf("a pinned key absent from the store should be reported, got %v", removed)
	}
}

// doctor is where an operator goes looking. Before this change it reported the recipient count at
// LOW with no baseline to compare against, so an injected key was indistinguishable from a
// legitimate one.
func TestDoctorFlagsUnpinnedRecipient(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if _, err := openStore(); err != nil {
		t.Fatal(err)
	}
	attacker := newRecipientKey(t)
	injectRecipient(t, attacker)

	out, _ := execArca("", "doctor")
	if !strings.Contains(out, "HIGH") {
		t.Fatalf("an unpinned recipient should raise doctor to HIGH:\n%s", out)
	}
	if !strings.Contains(out, attacker) {
		t.Fatalf("doctor should name the unpinned key:\n%s", out)
	}
}

func TestRecipientPinFileIsPrivate(t *testing.T) {
	// GOOS is a build constant, not an environment variable: os.Getenv("GOOS") is empty
	// everywhere, so guarding on it would run this POSIX-only check on Windows too.
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not Windows' access-control mechanism")
	}
	sandbox(t)
	runArca(t, "", "init")
	if _, err := openStore(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(recipientPinPath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("pin file mode = %o, want 600", perm)
	}
}
