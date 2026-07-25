//go:build e2e

// End-to-end coverage for behavior added in the 2026-07 security pass: the disable/enable kill
// switch (SEC-13), metadata-only `annotate`, canary trip alerts (SEC-04), store-rollback
// detection (SEC-14), and recipient-revocation honesty (SEC-15). Each drives the real binary, so it
// proves the shipped behavior end to end.
package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDisableEnable covers the half of the kill switch a headless caller can drive: a disabled
// secret is refused on every read path and surfaced to a human. `disable` is deliberately
// unanchored — arca's rule is that a caller may always narrow its own access — so all of that is
// unchanged.
//
// `enable` widens access and is anchored (T11/T12), so the second half is now a refusal assertion.
// Lost here: that enabling restores use *and preserves a real future expiry* rather than wiping it
// or now-stamping it (SEC-13). That claim keeps in-process coverage in disable_test.go
// TestDisableEnablePreservesExpiry, which asserts the same round-trip with the operator prompt
// stubbed. The asymmetry this test now shows is worth having on its own: the kill switch still
// works in an incident with no terminal, and only un-killing needs a human.
func TestDisableEnable(t *testing.T) {
	b := sandbox(t)
	b.must(t, "", "init")
	b.must(t, "topsecret", "set", "API", "--ttl", "365d") // a real, far-future expiry to preserve

	if out := b.must(t, "", "get", "API"); out != "topsecret" {
		t.Fatalf("get before disable = %q", out)
	}
	b.must(t, "", "disable", "API")

	if _, _, code := b.run(t, "", "get", "API"); code == 0 {
		t.Fatal("get of a disabled secret should fail")
	}
	if out := b.must(t, "", "show", "API"); !strings.Contains(out, "DISABLED") {
		t.Fatalf("show should flag DISABLED: %q", out)
	}
	if out := b.must(t, "", "ls"); !strings.Contains(out, "[disabled]") {
		t.Fatalf("ls should flag [disabled]: %q", out)
	}

	// Re-enabling widens access, so it is operator-only. Disabling was not.
	assertControlPlaneRefused(t, b, "enable", "API")

	// And the refusal left the kill switch on: a secret that could be re-enabled by a refused
	// command would make the anchor decorative.
	if _, _, code := b.run(t, "", "get", "API"); code == 0 {
		t.Fatal("get succeeded after a refused `enable`; the secret was re-enabled anyway")
	}
	if out := b.must(t, "", "show", "API"); !strings.Contains(out, "DISABLED") {
		t.Fatalf("show should still flag DISABLED after a refused enable: %q", out)
	}
}

// TestAnnotate covers the metadata-only editor: it changes tags/description/meta and never the value.
func TestAnnotate(t *testing.T) {
	b := sandbox(t)
	b.must(t, "", "init")
	b.must(t, "the-value", "set", "TOK", "--tag", "old")

	b.must(t, "", "annotate", "TOK", "--add-tag", "new", "--desc", "a token", "--meta", "env=prod")
	out := b.must(t, "", "show", "TOK")
	for _, want := range []string{"new", "old", "a token", "env", "prod"} {
		if !strings.Contains(out, want) {
			t.Fatalf("show after annotate missing %q: %q", want, out)
		}
	}
	if got := b.must(t, "", "get", "TOK"); got != "the-value" {
		t.Fatalf("annotate must not change the value: %q", got)
	}

	// Removals apply too.
	b.must(t, "", "annotate", "TOK", "--rm-tag", "old", "--rm-meta", "env")
	out = b.must(t, "", "show", "TOK")
	if strings.Contains(out, "old") || strings.Contains(out, "prod") {
		t.Fatalf("annotate --rm-tag/--rm-meta did not remove: %q", out)
	}
	if got := b.must(t, "", "get", "TOK"); got != "the-value" {
		t.Fatalf("annotate --rm must not change the value: %q", got)
	}
}

// TestCanary covers the decoy tripwire: using a canary still returns its (fake) value but raises a
// loud alert and records a canary event, so an exfiltration attempt is caught rather than blocked.
func TestCanary(t *testing.T) {
	b := sandbox(t)
	b.must(t, "", "init")
	b.must(t, "decoy-value", "set", "TRAP", "--canary")

	out, errOut, code := b.run(t, "", "get", "TRAP")
	if code != 0 || out != "decoy-value" {
		t.Fatalf("canary get = %q code=%d (the fake value should still be handed over)", out, code)
	}
	if !strings.Contains(errOut, "CANARY") {
		t.Fatalf("expected a canary alert on stderr: %q", errOut)
	}
	if log := b.must(t, "", "log", "TRAP"); !strings.Contains(log, "canary") {
		t.Fatalf("canary trip was not audited: %q", log)
	}
}

// TestStoreRollback covers SEC-14: restoring an older copy of the (git-synced) store is warned about
// on the next command, because the store's monotonic generation went backwards.
func TestStoreRollback(t *testing.T) {
	b := sandbox(t)
	b.must(t, "", "init")
	b.must(t, "v1", "set", "A")

	storePath := filepath.Join(b.dir, "store.json")
	snapshot, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}

	// Advance a couple of generations so the local high-water mark climbs past the snapshot.
	b.must(t, "v2", "set", "B")
	b.must(t, "v3", "set", "C")

	// Roll back: overwrite the store with the older, lower-generation snapshot.
	if err := os.WriteFile(storePath, snapshot, 0o600); err != nil {
		t.Fatal(err)
	}

	// The next command still runs, but warns about the rollback on stderr.
	_, errOut, code := b.run(t, "", "ls")
	if code != 0 {
		t.Fatalf("ls after a rollback should still succeed, got code=%d (%s)", code, errOut)
	}
	if !strings.Contains(errOut, "rolled back") {
		t.Fatalf("expected a rollback warning on stderr: %q", errOut)
	}
}

// TestRecipientAddIsOperatorOnly replaces the former TestRecipientRevocation.
//
// Adding an age recipient grants permanent decryption rights to every secret in the store, on every
// machine the store reaches — the widest-blast-radius mutation arca supports — so it is anchored
// (T11/T12) and a headless black-box caller cannot perform it. Every later step of the old test
// needed a second recipient to exist first.
//
// Lost here: SEC-15's revocation behaviour — that `recipients rm` auto-re-encrypts to the remaining
// key(s), prints the honest "this does not revoke what that key could already read" warning naming
// git history and `arca rotate`, and leaves the secret decryptable by us. That keeps in-process
// coverage in recipients_sec15_test.go (TestRecipientsRmReencrypts, TestWarnRecipientRevocation)
// and recipients_audit_test.go. `recipients rm` itself is unanchored and still usable headless,
// which is the property that matters mid-incident; it is only unreachable *here* because this test
// can no longer create something to remove.
func TestRecipientAddIsOperatorOnly(t *testing.T) {
	b := sandbox(t)
	b.must(t, "", "init")
	b.must(t, "topsecret", "set", "API")

	// A second, independent recipient: another box's freshly generated public key.
	other := sandbox(t)
	other.must(t, "", "init")
	otherRecip := strings.TrimSpace(other.must(t, "", "recipients"))
	if !strings.HasPrefix(otherRecip, "age1") {
		t.Fatalf("unexpected recipient string: %q", otherRecip)
	}

	assertControlPlaneRefused(t, b, "recipients", "add", otherRecip)

	// The refusal added nobody. This is the assertion that matters most in the file: a partial
	// success here is a permanent, store-wide grant of decryption rights.
	if out := b.must(t, "", "recipients"); strings.Contains(out, otherRecip) {
		t.Fatalf("a refused `recipients add` still added the key:\n%s", out)
	}
	if out := b.must(t, "", "get", "API"); out != "topsecret" {
		t.Fatalf("get after a refused recipients add = %q", out)
	}
}
