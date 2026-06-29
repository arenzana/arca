package crypto

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// writeIdentity persists an age identity string to a temp file and returns its path, so the
// tests can exercise LoadIdentities (which reads from disk) rather than poking internals.
func writeIdentity(t *testing.T, idStr string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "id.txt")
	if err := os.WriteFile(p, []byte(idStr+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestEncryptDecryptRoundTrip is the core guarantee: a value encrypted to a recipient is
// recovered byte-for-byte by the matching identity (and the ciphertext is not the plaintext).
// Uses a non-ASCII value to catch any encoding mishandling.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	idStr, recStr, err := GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	recips, err := ParseRecipients([]string{recStr})
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("super-secret-🔐-value")
	armored, err := Encrypt(plain, recips)
	if err != nil {
		t.Fatal(err)
	}
	if len(armored) == 0 || armored == string(plain) {
		t.Fatal("output is not encrypted")
	}

	ids, err := LoadIdentities(writeIdentity(t, idStr))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(armored, ids)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("round-trip mismatch: got %q", got)
	}
}

// TestDecryptWrongIdentityFails confirms a different key cannot read the ciphertext — i.e. the
// encryption is actually targeted at the recipient, not trivially reversible.
func TestDecryptWrongIdentityFails(t *testing.T) {
	_, recStr, _ := GenerateIdentity()
	recips, _ := ParseRecipients([]string{recStr})
	armored, _ := Encrypt([]byte("x"), recips)

	otherStr, _, _ := GenerateIdentity() // an unrelated key
	ids, _ := LoadIdentities(writeIdentity(t, otherStr))
	if _, err := Decrypt(armored, ids); err == nil {
		t.Fatal("expected decrypt to fail with the wrong identity")
	}
}

// TestRecipientsFromIdentities verifies init's "derive the recipient from the user's own key"
// path: the public recipient extracted from an identity matches the one generated alongside it.
func TestRecipientsFromIdentities(t *testing.T) {
	idStr, recStr, _ := GenerateIdentity()
	ids, _ := LoadIdentities(writeIdentity(t, idStr))
	recs, err := RecipientsFromIdentities(ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0] != recStr {
		t.Fatalf("got %v, want [%s]", recs, recStr)
	}
}

// TestParseRecipientsEmpty guards the obvious misuse: encrypting to nobody must error rather
// than silently producing an unreadable blob.
func TestParseRecipientsEmpty(t *testing.T) {
	if _, err := ParseRecipients(nil); err == nil {
		t.Fatal("expected error for no recipients")
	}
}

// TestParseRecipientsBad rejects a malformed recipient string.
func TestParseRecipientsBad(t *testing.T) {
	if _, err := ParseRecipients([]string{"not-an-age-recipient"}); err == nil {
		t.Fatal("expected error for a bad recipient")
	}
}

// TestLoadIdentitiesMissing surfaces a clear error when the key file is absent.
func TestLoadIdentitiesMissing(t *testing.T) {
	if _, err := LoadIdentities(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for a missing identity file")
	}
}

// TestLoadIdentitiesEmpty errors when the file parses but contains no identities.
func TestLoadIdentitiesEmpty(t *testing.T) {
	p := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(p, []byte("# only a comment\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentities(p); err == nil {
		t.Fatal("expected error for a file with no identities")
	}
}

// TestRecipientsFromIdentitiesNoX25519 covers the "no X25519 identities" branch by passing a
// scrypt (passphrase) identity, which has no serializable public recipient.
func TestRecipientsFromIdentitiesNoX25519(t *testing.T) {
	si, err := age.NewScryptIdentity("pw")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RecipientsFromIdentities([]age.Identity{si}); err == nil {
		t.Fatal("expected error: no X25519 identities")
	}
}

// TestEncryptNoRecipients covers Encrypt's age.Encrypt error branch (encrypting to nobody).
func TestEncryptNoRecipients(t *testing.T) {
	if _, err := Encrypt([]byte("x"), nil); err == nil {
		t.Fatal("expected Encrypt to fail with no recipients")
	}
}

// TestLoadIdentitiesMalformed covers the parse-error branch (a syntactically invalid key).
func TestLoadIdentitiesMalformed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(p, []byte("AGE-SECRET-KEY-1NOTVALID\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentities(p); err == nil {
		t.Fatal("expected a parse error for a malformed identity")
	}
}
