package storesign

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 { // Windows: ACLs, not 0600
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
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 { // Windows: ACLs, not 0600
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

func TestSaveRejectsIncompleteKey(t *testing.T) {
	if err := Save(filepath.Join(t.TempDir(), "k"), nil); err == nil {
		t.Fatal("Save(nil) should refuse")
	}
	if err := Save(filepath.Join(t.TempDir(), "k"), &Key{Seed: make([]byte, 4)}); err == nil {
		t.Fatal("Save(short seed) should refuse")
	}
	if err := SavePin(filepath.Join(t.TempDir(), "p"), make([]byte, 4)); err == nil {
		t.Fatal("SavePin(short pub) should refuse")
	}
}

func TestVerifyRejectsWrongSizes(t *testing.T) {
	k, _ := Generate()
	sig := Sign(k.Priv, []byte("x"))
	if Verify(k.Pub[:8], []byte("x"), sig) {
		t.Fatal("Verify accepted a short public key")
	}
	if Verify(k.Pub, []byte("x"), sig[:8]) {
		t.Fatal("Verify accepted a short signature")
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

func TestPinSetRoundTripWithLabels(t *testing.T) {
	a, _ := Generate()
	b, _ := Generate()
	p := filepath.Join(t.TempDir(), "store-signers.pin")
	set := PinSet{{Pub: a.Pub, Label: "om"}, {Pub: b.Pub}}
	if err := SavePinSet(p, set); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("pin set mode = %o, want 0600", st.Mode().Perm())
	}
	got, err := LoadPinSet(p)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Contains(a.Pub) || !got.Contains(b.Pub) {
		t.Fatalf("round trip lost a key: %s", got)
	}
	if got.Labeled(a.Pub) != "om" || got.Labeled(b.Pub) != "" {
		t.Fatalf("labels not preserved: %s", got)
	}
	c, _ := Generate()
	if got.Contains(c.Pub) {
		t.Fatal("Contains matched a key that was never added")
	}
}

// A label can never smuggle extra entries in through a newline.
func TestPinSetLabelCannotForgeEntries(t *testing.T) {
	a, _ := Generate()
	evil, _ := Generate()
	p := filepath.Join(t.TempDir(), "store-signers.pin")
	if err := SavePinSet(p, PinSet{{Pub: a.Pub, Label: "om\n" + EncodePub(evil.Pub) + " smuggled"}}); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPinSet(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Contains(evil.Pub) {
		t.Fatalf("a newline in a label forged a trusted signer: %s", got)
	}
	if len(got) != 1 {
		t.Fatalf("set has %d entries, want 1: %s", len(got), got)
	}
}

// A pin file is never partially honored: dropping an unparseable line would
// silently distrust a machine.
func TestLoadPinSetRefusesCorruptAndEmpty(t *testing.T) {
	a, _ := Generate()
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pin")
	if err := os.WriteFile(bad, []byte(EncodePub(a.Pub)+"\nnot-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPinSet(bad); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt line = %v, want ErrCorrupt", err)
	}
	empty := filepath.Join(dir, "empty.pin")
	if err := os.WriteFile(empty, []byte("# only a comment\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPinSet(empty); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("keyless file = %v, want ErrCorrupt", err)
	}
	if _, err := LoadPinSet(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file = %v, want os.ErrNotExist", err)
	}
	if err := SavePinSet(filepath.Join(dir, "out.pin"), nil); err == nil {
		t.Fatal("SavePinSet(empty) should refuse — it would un-pin the machine")
	}
}

func TestPinSetStringRendersLabels(t *testing.T) {
	a, _ := Generate()
	b, _ := Generate()
	got := PinSet{{Pub: a.Pub, Label: "om"}, {Pub: b.Pub}}.String()
	want := EncodePub(a.Pub) + " (om), " + EncodePub(b.Pub)
	if got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if PinSet(nil).String() != "" {
		t.Fatalf("empty set should render empty, got %q", PinSet(nil).String())
	}
}
