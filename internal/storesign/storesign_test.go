package storesign

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("canonical store json")
	sig := Sign(k.Priv, payload)
	if !Verify(k.Pub, payload, sig) {
		t.Fatal("fresh signature did not verify")
	}
	if Verify(k.Pub, append(payload, 'x'), sig) {
		t.Fatal("signature verified against a mutated payload")
	}
	other, _ := Generate()
	if Verify(other.Pub, payload, sig) {
		t.Fatal("signature verified under a different key")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "store-signing.key")
	if err := Save(p, k); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o, want 0600", st.Mode().Perm())
	}
	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Seed, k.Seed) || !bytes.Equal(got.Pub, k.Pub) {
		t.Fatal("loaded key does not match the saved seed")
	}
	if !Verify(got.Pub, []byte("x"), Sign(got.Priv, []byte("x"))) {
		t.Fatal("reloaded key cannot sign")
	}
}

func TestLoadMissingAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope.key")
	if _, err := Load(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing key = %v, want ErrNotExist", err)
	}
	corrupt := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(corrupt, []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(corrupt); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("truncated key = %v, want ErrCorrupt", err)
	}
}

func TestPinRoundTripAndCorrupt(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "store-signer.pin")
	if err := SavePin(p, k.Pub); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("pin mode = %o, want 0600", st.Mode().Perm())
	}
	got, err := LoadPin(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, k.Pub) {
		t.Fatal("loaded pin does not match")
	}
	// Encode/Decode survive a trailing newline (SavePin writes one).
	if EncodePub(got) != EncodePub(k.Pub) {
		t.Fatal("encode is not stable")
	}
	if err := os.WriteFile(p, []byte("not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPin(p); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("garbage pin = %v, want ErrCorrupt", err)
	}
	if _, err := LoadPin(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing pin = %v, want ErrNotExist", err)
	}
}

func TestDecodePubAcceptsPadded(t *testing.T) {
	k, _ := Generate()
	padded := base64.StdEncoding.EncodeToString(k.Pub)
	got, err := DecodePub(padded)
	if err != nil || !bytes.Equal(got, k.Pub) {
		t.Fatalf("padded decode = %v err %v", got, err)
	}
	if _, err := DecodePub("@@@@"); err == nil {
		t.Fatal("garbage should not decode")
	}
	short := base64.RawStdEncoding.EncodeToString(make([]byte, 8))
	if _, err := DecodePub(short); err == nil {
		t.Fatal("short key should not decode")
	}
}
