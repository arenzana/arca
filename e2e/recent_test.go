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

// TestDisableEnable covers the kill switch: a disabled secret is refused on every read path and
// surfaced to a human, and enabling it restores use while preserving a real future expiry (SEC-13).
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

	// enable restores use, and the real expiry survived the round-trip (not wiped, not now-stamped).
	b.must(t, "", "enable", "API")
	if out := b.must(t, "", "get", "API"); out != "topsecret" {
		t.Fatalf("get after enable = %q", out)
	}
	if out := b.must(t, "", "show", "API"); !strings.Contains(out, "expires") || strings.Contains(out, "EXPIRED") {
		t.Fatalf("expiry should be preserved and still valid after enable: %q", out)
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

// TestRecipientRevocation covers SEC-15: removing a recipient auto-re-encrypts existing secrets to
// the remaining key(s) AND prints the honest warning that this does not revoke what the removed key
// could already read (git history / backups) — you must rotate the values for that.
func TestRecipientRevocation(t *testing.T) {
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
	b.must(t, "", "recipients", "add", otherRecip)

	_, errOut, code := b.run(t, "", "recipients", "rm", otherRecip)
	if code != 0 {
		t.Fatalf("recipients rm failed: %s", errOut)
	}
	for _, want := range []string{"re-encrypted", "does NOT revoke", "git history", "arca rotate API"} {
		if !strings.Contains(errOut, want) {
			t.Fatalf("recipients rm stderr missing %q:\n%s", want, errOut)
		}
	}
	// Still decryptable by us after the auto-reencrypt.
	if out := b.must(t, "", "get", "API"); out != "topsecret" {
		t.Fatalf("get after recipient rm = %q", out)
	}
}
