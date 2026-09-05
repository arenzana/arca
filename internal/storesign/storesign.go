// Package storesign is the operator-held Ed25519 key that authenticates a
// synced store (audit H1). Age provides confidentiality, not authentication;
// without this signature a backend that knows the (public) recipients can
// fabricate a policy-stripped store that every machine will pull silently.
//
// The key is store-scoped and operator-anchored, distinct from the per-session
// audit signers in sign.go. The pin set is this machine's memory of which public
// keys it accepts: it never travels with the store, and a signature by anything
// outside it is a hard refusal (not overrideable by --force).
//
// It is a SET, not a single key, because every machine mints its own key: a
// fleet of N machines has N signers, and each machine must accept its peers as
// well as itself.
package storesign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

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

// PinEntry is one trusted signer: a public key and an optional operator label
// ("om", "daintree", "laptop (retired)"). The label is a human aid only —
// nothing verifies against it.
type PinEntry struct {
	Pub   ed25519.PublicKey
	Label string
}

// PinSet is this machine's set of accepted store signers, in file order.
//
// It replaces the single pinned key. A fleet where every machine mints its own
// signing key (which is what happens by default) has as many signers as
// machines, and one trust slot cannot express that: the operator is forced to
// pin a peer, at which point the machine no longer trusts its own signatures.
type PinSet []PinEntry

// Contains reports whether pub is one of the accepted signers.
func (s PinSet) Contains(pub ed25519.PublicKey) bool {
	for _, e := range s {
		if bytes.Equal(e.Pub, pub) {
			return true
		}
	}
	return false
}

// Labeled returns the label recorded for pub, or "" if it is absent or unlabeled.
func (s PinSet) Labeled(pub ed25519.PublicKey) string {
	for _, e := range s {
		if bytes.Equal(e.Pub, pub) {
			return e.Label
		}
	}
	return ""
}

// String renders the set for an error message: "KEY (label), KEY".
func (s PinSet) String() string {
	parts := make([]string, 0, len(s))
	for _, e := range s {
		p := EncodePub(e.Pub)
		if e.Label != "" {
			p += " (" + e.Label + ")"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, ", ")
}

// LoadPinSet reads the multi-signer pin file: one "<pubkey> [label]" per line,
// blank lines and #-comments ignored. A missing file is os.ErrNotExist; any
// unparseable line is ErrCorrupt — a pin file is never partially honored,
// because silently dropping a line would silently distrust a machine.
func LoadPinSet(path string) (PinSet, error) {
	b, err := os.ReadFile(path) //#nosec G304 -- path is the operator's state-dir file
	if err != nil {
		return nil, err
	}
	var set PinSet
	for i, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		key, label, _ := strings.Cut(ln, " ")
		pub, err := DecodePub(strings.TrimSpace(key))
		if err != nil {
			return nil, fmt.Errorf("%w: %s:%d: %v", ErrCorrupt, path, i+1, err)
		}
		if set.Contains(pub) {
			continue // a duplicate line is not corruption, just noise
		}
		set = append(set, PinEntry{Pub: pub, Label: strings.TrimSpace(label)})
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("%w: %s: no signer keys", ErrCorrupt, path)
	}
	return set, nil
}

// SavePinSet writes the set at 0600 via atomicfile. It refuses an empty set:
// truncating the pin to nothing would silently reopen the migration window in
// which an unsigned store is accepted. Use os.Remove for a deliberate reset.
func SavePinSet(path string, set PinSet) error {
	if len(set) == 0 {
		return fmt.Errorf("refusing to write an empty signer set (that would un-pin this machine); remove %s deliberately instead", path)
	}
	var sb strings.Builder
	sb.WriteString("# arca trusted store signers — one \"<pubkey> [label]\" per line.\n")
	sb.WriteString("# Manage with `arca signer add|rm|list`.\n")
	for _, e := range set {
		if len(e.Pub) != ed25519.PublicKeySize {
			return fmt.Errorf("refusing to pin an incomplete public key")
		}
		sb.WriteString(EncodePub(e.Pub))
		if lbl := sanitizeLabel(e.Label); lbl != "" {
			sb.WriteString(" " + lbl)
		}
		sb.WriteString("\n")
	}
	return atomicfile.Write(path, []byte(sb.String()), fs.FileMode(0o600))
}

// sanitizeLabel keeps a label to one printable line, so a label can never
// forge extra pin entries by carrying a newline.
func sanitizeLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
