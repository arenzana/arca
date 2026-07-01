package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// FuzzEncryptDecrypt checks the age round-trip is lossless for arbitrary plaintext (binary, empty,
// multi-line, NUL bytes) and that the ciphertext never trivially contains the plaintext.
func FuzzEncryptDecrypt(f *testing.F) {
	idStr, recStr, err := GenerateIdentity()
	if err != nil {
		f.Fatal(err)
	}
	recips, err := ParseRecipients([]string{recStr})
	if err != nil {
		f.Fatal(err)
	}
	idPath := filepath.Join(f.TempDir(), "id.txt")
	if err := os.WriteFile(idPath, []byte(idStr), 0o600); err != nil {
		f.Fatal(err)
	}
	ids, err := LoadIdentities(idPath)
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte("hello"))
	f.Add([]byte(""))
	f.Add([]byte("multi\nline\x00binary\xff\xfe end"))
	f.Fuzz(func(t *testing.T, plain []byte) {
		armored, err := Encrypt(plain, recips)
		if err != nil {
			t.Fatalf("encrypt %d bytes: %v", len(plain), err)
		}
		got, err := Decrypt(armored, ids)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("round-trip mismatch for %d bytes", len(plain))
		}
		if len(plain) >= 8 && bytes.Contains([]byte(armored), plain) {
			t.Fatalf("ciphertext contains the plaintext")
		}
	})
}
