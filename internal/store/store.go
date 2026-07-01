// Package store is arca's on-disk secret store: a single JSON document holding cleartext
// metadata plus per-value age ciphertext.
//
// Why JSON (and not, say, SQLite) for the store:
//   - it diffs and merges in git, so the store can live in a dotfiles repo as the source of
//     truth, and `git log` gives a free "created/modified" history;
//   - metadata (names, tags, descriptions) stays human-readable, so `ls`/`show` can answer
//     questions without ever decrypting a value.
//
// Read tracking deliberately does NOT live here — it goes to the separate (local) audit DB —
// so a `get` never rewrites this file and never churns git. The store therefore only changes
// on real mutations (set/rotate/rm), which is exactly what you want versioned.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Version is the on-disk schema version, bumped if the JSON shape ever changes incompatibly.
const Version = 1

// maxStoreBytes caps the store file size read into memory — a generous ceiling that still
// guards against a runaway or hostile store file exhausting memory.
const maxStoreBytes = 64 << 20 // 64 MiB

// Secret is one entry. Value is the armored age ciphertext; every other field is cleartext
// metadata so the store can be listed and queried without the decryption key.
type Secret struct {
	Value           string            `json:"value"`                      // armored age ciphertext
	CreatedAt       time.Time         `json:"created_at"`                 // first set; preserved across rotate
	UpdatedAt       time.Time         `json:"updated_at"`                 // last value change
	Tags            []string          `json:"tags,omitempty"`             // free-form labels for filtering
	Description     string            `json:"description,omitempty"`      // human note
	RotateAfter     *time.Time        `json:"rotate_after,omitempty"`     // rotation due date (drives `stale`)
	ExpiresAt       *time.Time        `json:"expires_at,omitempty"`       // hard expiry: reads/use refuse the value after this (also how `disable` suspends a secret)
	NoPrint         bool              `json:"no_print,omitempty"`         // exec-only: never reveal to stdout
	RequireApproval bool              `json:"require_approval,omitempty"` // human must approve each release
	Canary          bool              `json:"canary,omitempty"`           // decoy: any use is a tripwire, alerted and audited
	RequireGrant    bool              `json:"require_grant,omitempty"`    // usable only via exec/MCP with a matching active grant
	RateLimit       int               `json:"rate_limit,omitempty"`       // max uses per RateWindow (0 = unlimited)
	RateWindow      string            `json:"rate_window,omitempty"`      // the window for RateLimit (e.g. "1h"); empty defaults to 1h
	Meta            map[string]string `json:"meta,omitempty"`             // open-ended extensibility bag
}

// Expired reports whether the secret has a hard expiry that has already passed as of now.
// Unlike RotateAfter (a soft "should rotate" surfaced by `stale`), an expired secret is
// refused by every access path — it cannot be read, injected, or exec-injected.
func (s *Secret) Expired(now time.Time) bool {
	return s.ExpiresAt != nil && now.After(*s.ExpiresAt)
}

// Store is the whole document. path is where it loads from / saves to (not serialized).
type Store struct {
	Version    int                `json:"version"`
	Recipients []string           `json:"recipients"` // age recipients re-encrypted to on `set`
	Secrets    map[string]*Secret `json:"secrets"`

	path string
}

// New returns an empty in-memory store bound to path, with the given recipients.
func New(path string, recipients []string) *Store {
	return &Store{Version: Version, Recipients: recipients, Secrets: map[string]*Secret{}, path: path}
}

// Load reads and parses the store at path. A missing file is reported as a friendly
// "run `arca init`" error rather than a raw os error.
func Load(path string) (*Store, error) {
	// Reject an implausibly large file before reading it into memory (DoS guard).
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxStoreBytes {
		return nil, fmt.Errorf("store %s is %d bytes, exceeding the %d-byte limit", path, fi.Size(), int64(maxStoreBytes))
	}
	b, err := os.ReadFile(path) //#nosec G304 -- the store path is operator-controlled (config/env), not untrusted input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no store at %s (run `arca init`)", path)
		}
		return nil, err
	}
	var s Store
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse store %s: %w", path, err)
	}
	// Refuse a store written by a newer, possibly-incompatible arca rather than misread it.
	if s.Version > Version {
		return nil, fmt.Errorf("store %s has version %d, newer than this arca supports (%d)", path, s.Version, Version)
	}
	if s.Secrets == nil { // tolerate a store with no secrets yet
		s.Secrets = map[string]*Secret{}
	}
	// Reject null secret entries (e.g. a hand-edited / synced `"FOO": null`) up front, so later
	// code never dereferences a nil *Secret and panics.
	for name, sec := range s.Secrets {
		if sec == nil {
			return nil, fmt.Errorf("store %s: secret %q is null", path, name)
		}
	}
	// Bring an older store up to the current schema in memory; the upgrade is persisted on the
	// next Save (a read alone won't rewrite the file).
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate store %s: %w", path, err)
	}
	s.path = path
	return &s, nil
}

// migration upgrades a store in place from schema version N to N+1.
type migration func(*Store) error

// migrations[N] upgrades a store from schema version N to N+1. When the on-disk shape changes
// incompatibly: bump Version, then add the N→N+1 step here. Load applies the chain in order, so
// an old store is always brought current.
var migrations = map[int]migration{
	// (none yet — version 1 is the initial schema)
}

// migrate brings the store up to the current Version by applying the registered migrations in
// sequence. A version-0 store (one written before versioning, or hand-edited without the field)
// is treated as the v1 baseline, whose shape is identical.
func (s *Store) migrate() error {
	if s.Version == 0 {
		s.Version = 1
	}
	return applyMigrations(s, Version, migrations)
}

// applyMigrations is the version-stepping core, split out so it can be tested with a synthetic
// target version and migration set (the real Version is a compile-time const).
func applyMigrations(s *Store, target int, migs map[int]migration) error {
	for s.Version < target {
		m, ok := migs[s.Version]
		if !ok {
			return fmt.Errorf("no migration registered from store version %d to %d", s.Version, s.Version+1)
		}
		if err := m(s); err != nil {
			return fmt.Errorf("migrate v%d->v%d: %w", s.Version, s.Version+1, err)
		}
		s.Version++
	}
	return nil
}

// Save writes the store atomically and with restrictive permissions:
//   - serialize to a temp file in the same directory (so rename is atomic on the same fs),
//   - chmod 0600 before writing any bytes,
//   - fsync-free rename over the destination.
//
// The temp file is removed on any early-return error path via the deferred Remove.
func (s *Store) Save() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".store-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename below succeeds
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil { // flush to disk before the rename so a crash can't leave a truncated store
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

// Names returns the secret names in sorted order, for stable listing output.
func (s *Store) Names() []string {
	names := make([]string, 0, len(s.Secrets))
	for n := range s.Secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
