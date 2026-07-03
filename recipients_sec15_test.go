package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/store"
)

// TestWarnRecipientRevocation covers the SEC-15 honesty message: it must state plainly that removal
// does not revoke prior access (git history / backups remain readable) and list the secrets to
// rotate for true revocation.
func TestWarnRecipientRevocation(t *testing.T) {
	s := store.New("", []string{"age1x"})
	s.Secrets["ALPHA"] = &store.Secret{}
	s.Secrets["BETA"] = &store.Secret{}

	var buf bytes.Buffer
	warnRecipientRevocation(&buf, s)
	out := buf.String()
	for _, want := range []string{"does NOT revoke", "git history", "ROTATE", "arca rotate ALPHA", "arca rotate BETA"} {
		if !strings.Contains(out, want) {
			t.Fatalf("revocation warning missing %q:\n%s", want, out)
		}
	}
}

// TestRecipientsRmReencrypts covers SEC-15's auto-re-encryption: removing a recipient re-wraps
// existing secrets to the remaining key(s) in the same step, so the current store stops depending on
// the removed one while staying decryptable by us.
func TestRecipientsRmReencrypts(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "topsecret", "set", "API")

	_, extra, err := crypto.GenerateIdentity() // a second recipient's public key
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "recipients", "add", extra)
	if out := runArca(t, "", "recipients"); !strings.Contains(out, extra) {
		t.Fatalf("second recipient was not added: %q", out)
	}

	runArca(t, "", "recipients", "rm", extra)
	if out := runArca(t, "", "recipients"); strings.Contains(out, extra) {
		t.Fatalf("recipient was not removed: %q", out)
	}
	// The auto-reencrypt re-wrapped to the remaining key, so the value is still decryptable.
	if out := runArca(t, "", "get", "API"); out != "topsecret" {
		t.Fatalf("secret not decryptable after rm + auto-reencrypt: %q", out)
	}

	// --no-reencrypt skips the re-wrap (deferred to `reencrypt`), but the removal still applies.
	runArca(t, "", "recipients", "add", extra)
	runArca(t, "", "recipients", "rm", extra, "--no-reencrypt")
	if out := runArca(t, "", "recipients"); strings.Contains(out, extra) {
		t.Fatalf("--no-reencrypt should still remove the recipient: %q", out)
	}
}
