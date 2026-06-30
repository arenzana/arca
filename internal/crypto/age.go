// Package crypto is arca's thin encryption layer over filippo.io/age.
//
// Design: every secret value is encrypted *individually* (not the whole store as one blob)
// and stored as an ASCII-armored age ciphertext string. That gives two properties arca relies
// on:
//
//   - decrypting one secret (`get`/`inject`/`exec`) never has to touch the others, and
//   - an unchanged secret's ciphertext stays byte-identical across saves, so the JSON store
//     produces clean git diffs (only the secret you actually changed shows up).
//
// Recipients are age X25519 public keys ("age1…"); identities are the matching private keys,
// typically reused from the caller's existing $SOPS_AGE_KEY_FILE.
package crypto

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// LoadIdentities parses one or more age identities (private keys) from a key file such as
// ~/.config/sops/age/keys.txt. Comment lines are ignored by age's parser.
func LoadIdentities(path string) ([]age.Identity, error) {
	f, err := os.Open(path) //#nosec G304 -- the identity path is operator-controlled (config/env), not untrusted input
	if err != nil {
		return nil, fmt.Errorf("open identity %s: %w", path, err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parse identity %s: %w", path, err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no identities in %s", path)
	}
	return ids, nil
}

// RecipientsFromIdentities returns the public recipient strings for the X25519 identities in
// ids. It's used by `init` to derive the store's recipient list from the caller's own key, so
// no separate "recipient" configuration is needed.
func RecipientsFromIdentities(ids []age.Identity) ([]string, error) {
	var out []string
	for _, id := range ids {
		// Only X25519 identities expose a public recipient we can serialize; plugin/SSH
		// identities are skipped here (recipients for those would be configured explicitly).
		if x, ok := id.(*age.X25519Identity); ok {
			out = append(out, x.Recipient().String())
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no X25519 identities found")
	}
	return out, nil
}

// ParseRecipients turns the store's "age1…" recipient strings into age.Recipient values used
// for encryption.
func ParseRecipients(recips []string) ([]age.Recipient, error) {
	if len(recips) == 0 {
		return nil, fmt.Errorf("no recipients configured")
	}
	var out []age.Recipient
	for _, r := range recips {
		rec, err := age.ParseX25519Recipient(r)
		if err != nil {
			return nil, fmt.Errorf("parse recipient %q: %w", r, err)
		}
		out = append(out, rec)
	}
	return out, nil
}

// Encrypt returns an ASCII-armored age ciphertext for plaintext, readable by any of recips.
// The armored (PEM-like) form is used so the ciphertext embeds cleanly as a JSON string.
func Encrypt(plaintext []byte, recips []age.Recipient) (string, error) {
	var buf bytes.Buffer
	// Two nested writers: armor wraps the binary age stream as ASCII. Both must be closed,
	// innermost first, to flush correctly — age.Encrypt's writer finalizes the ciphertext on
	// Close, and the armor writer then writes its footer.
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recips...)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(plaintext); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil { // finalize the age stream
		return "", err
	}
	if err := aw.Close(); err != nil { // write the armor footer
		return "", err
	}
	return buf.String(), nil
}

// Decrypt reads an ASCII-armored age ciphertext using the first matching identity in ids.
func Decrypt(armored string, ids []age.Identity) ([]byte, error) {
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(armored)), ids...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// GenerateIdentity creates a fresh X25519 keypair, returning the private identity and its
// public recipient as strings. Used by `init` when no existing age key is found.
func GenerateIdentity() (identity, recipient string, err error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", err
	}
	return id.String(), id.Recipient().String(), nil
}
