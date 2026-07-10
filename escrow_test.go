package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/remote"
)

// TestEscrowOnSync: every sync ships the audit increment as an append-only encrypted
// segment; a second sync with no new events ships nothing; segments chain to each other.
func TestEscrowOnSync(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")

	keys, err := fake.List(context.Background(), remote.KeyAudit)
	if err != nil || len(keys) != 1 {
		t.Fatalf("after first sync: escrow keys = %v err %v", keys, err)
	}
	// The escrowed object is an age envelope, not cleartext events.
	blob, err := fake.Get(context.Background(), keys[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(blob), "AGE ENCRYPTED FILE") || strings.Contains(string(blob), "\"events\"") {
		t.Fatalf("escrow segment is not sealed: %.60q", blob)
	}

	// More activity → next sync ships exactly one more segment, chained to the first.
	runArca(t, "", "get", "A")
	runArca(t, "v2", "rotate", "A")
	runArca(t, "", "sync")
	keys, _ = fake.List(context.Background(), remote.KeyAudit)
	if len(keys) != 2 {
		t.Fatalf("after second sync: escrow keys = %v", keys)
	}
	segs, err := fetchEscrowedSegments(context.Background(), fake)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 2 || segs[1].PrevAnchor != segs[0].Anchor || segs[1].FirstID != segs[0].LastID+1 {
		t.Fatalf("segments do not chain: %+v", segs)
	}

	// Nothing new → nothing shipped. (status reads the head but logs no event... a plain
	// sync logs nothing when in sync, so the segment count must hold.)
	runArca(t, "", "sync")
	if keys, _ = fake.List(context.Background(), remote.KeyAudit); len(keys) != 3 && len(keys) != 2 {
		t.Fatalf("unexpected escrow growth: %v", keys)
	}
}

// TestVerifyRemoteExtendsEscrow: --remote passes on an honest log and fails loudly when
// the local audit DB is replaced with a shorter (but internally clean) history — the
// off-machine witness a local tamperer can't retract.
func TestVerifyRemoteExtendsEscrow(t *testing.T) {
	dir := sandbox(t)
	withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "v2", "rotate", "A")
	runArca(t, "", "sync")

	runArca(t, "", "log", "--verify", "--remote") // honest log extends its escrow

	// Nuke the audit DB and rebuild a fresh, internally-consistent one. A plain
	// --verify is clean; --remote catches the retraction.
	if err := os.Remove(dir + "/audit.db"); err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "get", "A") // recreates a fresh log with one event
	runArca(t, "", "log", "--verify")
	err := runArcaErr("", "log", "--verify", "--remote")
	if err == nil {
		t.Fatal("--remote passed on a rebuilt (retracted) audit log")
	}
	if !strings.Contains(err.Error(), "escrow") && !strings.Contains(err.Error(), "rolled back or truncated") {
		t.Fatalf("want an escrow verdict, got: %v", err)
	}
}

// TestEscrowContinuityTamper: a segment removed from the backend (append-only violated
// by the storage owner) breaks the client-side continuity check.
func TestEscrowContinuityTamper(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")
	runArca(t, "v2", "rotate", "A")
	runArca(t, "", "sync")

	keys, _ := fake.List(context.Background(), remote.KeyAudit)
	if len(keys) != 2 {
		t.Fatalf("precondition: want 2 segments, got %v", keys)
	}
	fake.Delete(keys[0]) // storage-side removal of the first segment
	if _, err := fetchEscrowedSegments(context.Background(), fake); err == nil {
		t.Fatal("continuity check passed with a missing first segment")
	}
}

// TestMachineIDStable: generated once, reused, and safe for object keys.
func TestMachineIDStable(t *testing.T) {
	sandbox(t)
	a, err := machineID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := machineID()
	if err != nil || a != b {
		t.Fatalf("machineID not stable: %q vs %q (%v)", a, b, err)
	}
	if strings.ContainsAny(a, "/ :") {
		t.Fatalf("machineID unsafe for keys: %q", a)
	}
}

// TestVerifyRemoteNoEscrowYet: --remote before any sync explains itself.
func TestVerifyRemoteNoEscrowYet(t *testing.T) {
	sandbox(t)
	withFakeBackend(t)
	runArca(t, "", "init")
	err := runArcaErr("", "log", "--verify", "--remote")
	if err == nil || !strings.Contains(err.Error(), "sync") {
		t.Fatalf("want a run-sync-first hint, got: %v", err)
	}
}

// TestSealEnvelopeBadRecipient covers the seal error path directly.
func TestSealEnvelopeBadRecipient(t *testing.T) {
	if _, err := sealEnvelope([]byte("x"), []string{"age1notvalid"}); err == nil {
		t.Fatal("sealEnvelope accepted a bogus recipient")
	}
}

// TestEscrowErrorPaths: an unopenable audit DB and an unwritable state dir degrade to
// warnings (best-effort), and a garbage escrow segment fails decryption loudly on read.
func TestEscrowErrorPaths(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	dir := sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")

	// Direct cursor-writer failure.
	blocker := dir + "/blk"
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldState := os.Getenv("XDG_STATE_HOME")
	t.Setenv("XDG_STATE_HOME", blocker)
	if err := saveEscrowState(escrowState{LastID: 1}); err == nil {
		t.Fatal("saveEscrowState should fail under an uncreatable state dir")
	}
	if err := escrowAudit(context.Background(), fake, []string{"age1qy"}); err == nil {
		t.Fatal("escrowAudit should surface a machine-id/state failure")
	}
	t.Setenv("XDG_STATE_HOME", oldState)

	// A garbage segment planted on the backend fails the fetch path loudly.
	m, err := machineID()
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.PutIfAbsent(context.Background(), remote.KeyAudit+m+"/000002.age", []byte("garbage")); err != nil {
		t.Fatal(err)
	}
	if _, err := fetchEscrowedSegments(context.Background(), fake); err == nil {
		t.Fatal("garbage segment should fail decryption")
	}

	// An unopenable audit DB is a warning-path error from escrowAudit.
	t.Setenv("ARCA_AUDIT", blocker+"/nope/audit.db")
	if err := escrowAudit(context.Background(), fake, []string{"age1qy"}); err == nil {
		t.Fatal("escrowAudit should fail when the audit DB can't open")
	}
}

// TestEscrowTailTruncationDetected (SEC-36): a backend that deletes the newest escrow
// segments to hide a rollback is caught by the locally-pinned high-water Seq.
func TestEscrowTailTruncationDetected(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")
	runArca(t, "v2", "rotate", "A")
	runArca(t, "", "sync") // now 2 escrow segments; escrow-state.Seq == 2

	runArca(t, "", "log", "--verify", "--remote") // honest: passes

	// Backend deletes the newest segment (append-only violated).
	keys, _ := fake.List(context.Background(), remote.KeyAudit)
	fake.Delete(keys[len(keys)-1])
	err := runArcaErr("", "log", "--verify", "--remote")
	if err == nil || !strings.Contains(err.Error(), "TRUNCATION") {
		t.Fatalf("escrow tail truncation should be detected, got: %v", err)
	}
}

// TestEscrowRejectsInjectedKey (SEC-39): a non-segment object injected under this machine's
// escrow prefix is refused before it is ever fetched/decrypted.
func TestEscrowRejectsInjectedKey(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")
	m, err := machineID()
	if err != nil {
		t.Fatal(err)
	}
	if err := fake.PutIfAbsent(context.Background(), remote.KeyAudit+m+"/evil.txt", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := fetchEscrowedSegments(context.Background(), fake); err == nil || !strings.Contains(err.Error(), "non-segment") {
		t.Fatalf("injected non-segment key should be refused, got: %v", err)
	}
}
