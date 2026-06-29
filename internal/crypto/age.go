// Package crypto wraps filippo.io/age for per-value encryption.
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

// LoadIdentities parses age identities from a key file (e.g. ~/.config/sops/age/keys.txt).
func LoadIdentities(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
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

// RecipientsFromIdentities returns the public recipient strings for X25519 identities.
func RecipientsFromIdentities(ids []age.Identity) ([]string, error) {
	var out []string
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			out = append(out, x.Recipient().String())
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no X25519 identities found")
	}
	return out, nil
}

// ParseRecipients parses age recipient strings (age1...).
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

// Encrypt returns an ASCII-armored age ciphertext for plaintext.
func Encrypt(plaintext []byte, recips []age.Recipient) (string, error) {
	var buf bytes.Buffer
	aw := armor.NewWriter(&buf)
	w, err := age.Encrypt(aw, recips...)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(plaintext); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	if err := aw.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Decrypt reads an ASCII-armored age ciphertext.
func Decrypt(armored string, ids []age.Identity) ([]byte, error) {
	r, err := age.Decrypt(armor.NewReader(strings.NewReader(armored)), ids...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// GenerateIdentity creates a new X25519 identity, returning (identity, recipient).
func GenerateIdentity() (identity, recipient string, err error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", err
	}
	return id.String(), id.Recipient().String(), nil
}
