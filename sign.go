package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

	"github.com/arenzana/arca/internal/audit"
)

// auditSigner returns the Ed25519 signer for the current session, generating and persisting its
// key on first use. The session is the detected agent session id (so every arca invocation in one
// agent session signs with the same key), or "local" for a non-agent caller. The key lives under
// the state dir at 0600; it is the holder of this key whose signature binds events to the session.
func auditSigner() (*audit.Signer, error) {
	sid := detectIdentity().Session
	if sid == "" {
		sid = "local"
	}
	seed, err := loadOrCreateSeed(sessionKeyPath(sid))
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &audit.Signer{
		SessionID: sid,
		Priv:      priv,
		Pub:       priv.Public().(ed25519.PublicKey),
	}, nil
}

// sessionKeyPath derives the key file path from a hash of the session id, so an arbitrary session
// string never has to be a safe filename.
func sessionKeyPath(sid string) string {
	h := sha256.Sum256([]byte(sid))
	return filepath.Join(stateDir(), "sessions", hex.EncodeToString(h[:16])+".key")
}

// loadOrCreateSeed reads an existing 32-byte Ed25519 seed, or generates and writes one.
func loadOrCreateSeed(path string) ([]byte, error) {
	b, err := os.ReadFile(path) //#nosec G304 -- path derives from the operator's state dir, not untrusted input
	if err == nil && len(b) == ed25519.SeedSize {
		return b, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		return nil, err
	}
	return seed, nil
}
