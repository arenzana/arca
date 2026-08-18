// Package storesign is the operator-held Ed25519 key that authenticates a
// synced store (audit H1). Age provides confidentiality, not authentication;
// without this signature a backend that knows the (public) recipients can
// fabricate a policy-stripped store that every machine will pull silently.
//
// The key is store-scoped and operator-anchored, distinct from the per-session
// audit signers in sign.go. The pin is this machine's memory of which public
// key it expects: it never travels with the store, and a mismatch is a hard
// refusal (not overrideable by --force).
package storesign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/arenzana/arca/internal/atomicfile"
)

// SeedSize is the Ed25519 seed length written to store-signing.key.
const SeedSize = ed25519.SeedSize

// Key is an operator store-signing keypair, derived from a 32-byte seed.
type Key struct {
	Seed []byte
	Priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
}

// ErrCorrupt is returned when a key or pin file exists but is not a valid
// 32-byte seed / 32-byte public key. Callers must refuse, never auto-heal:
// regenerating a corrupt seed would invalidate every prior signature and
// train the operator to discount a real tamper alarm (audit L3).
var ErrCorrupt = errors.New("store-signing key or pin is corrupt")

// Generate mints a fresh key from crypto/rand.
func Generate() (*Key, error) {
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return fromSeed(seed), nil
}

// Load reads a 32-byte seed from path. A missing file is os.ErrNotExist so
// the caller can decide whether to generate. A present-but-wrong file is
// ErrCorrupt — never silently replaced.
func Load(path string) (*Key, error) {
	b, err := os.ReadFile(path) //#nosec G304 -- path is the operator's state-dir file
	if err != nil {
		return nil, err
	}
	if len(b) != SeedSize {
		return nil, fmt.Errorf("%w: %s: got %d bytes, want %d", ErrCorrupt, path, len(b), SeedSize)
	}
	return fromSeed(b), nil
}

// Save writes the 32-byte seed to path at 0600 via atomicfile.
func Save(path string, k *Key) error {
	if k == nil || len(k.Seed) != SeedSize {
		return fmt.Errorf("refusing to save an incomplete store-signing key")
	}
	return atomicfile.Write(path, k.Seed, 0o600)
}

func fromSeed(seed []byte) *Key {
	priv := ed25519.NewKeyFromSeed(seed)
	return &Key{Seed: append([]byte(nil), seed...), Priv: priv, Pub: priv.Public().(ed25519.PublicKey)}
}

// Sign returns the Ed25519 signature of payload under priv.
func Sign(priv ed25519.PrivateKey, payload []byte) []byte {
	return ed25519.Sign(priv, payload)
}

// Verify reports whether sig is a valid Ed25519 signature of payload by pub.
func Verify(pub ed25519.PublicKey, payload, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, payload, sig)
}

// Encode is unpadded standard base64 of raw bytes — the wire spelling for
// both the public key and the signature in S3 user-metadata.
func Encode(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}

// Decode is the inverse of Encode (also accepting padded standard base64).
func Decode(s string) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(s)
	}
	return b, err
}

// EncodePub is the canonical on-disk / CLI spelling of a public key.
func EncodePub(pub ed25519.PublicKey) string {
	return Encode(pub)
}

// DecodePub parses EncodePub output (also accepting padded standard base64).
func DecodePub(s string) (ed25519.PublicKey, error) {
	b, err := Decode(s)
	if err != nil {
		return nil, fmt.Errorf("not a store-signer public key: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("not a store-signer public key: got %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// LoadPin reads the pinned signer public key. A missing pin is os.ErrNotExist
// (legacy unsigned fleet). A present-but-unparseable pin is ErrCorrupt.
func LoadPin(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path) //#nosec G304 -- path is the operator's state-dir file
	if err != nil {
		return nil, err
	}
	pub, err := DecodePub(string(trimNL(b)))
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, path, err)
	}
	return pub, nil
}

// SavePin writes the public key to path at 0600 via atomicfile.
func SavePin(path string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("refusing to pin an incomplete public key")
	}
	return atomicfile.Write(path, []byte(EncodePub(pub)+"\n"), fs.FileMode(0o600))
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
