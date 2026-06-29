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

// Secret is one entry. Value is the armored age ciphertext; every other field is cleartext
// metadata so the store can be listed and queried without the decryption key.
type Secret struct {
	Value       string            `json:"value"`                  // armored age ciphertext
	CreatedAt   time.Time         `json:"created_at"`             // first set; preserved across rotate
	UpdatedAt   time.Time         `json:"updated_at"`             // last value change
	Tags        []string          `json:"tags,omitempty"`         // free-form labels for filtering
	Description string            `json:"description,omitempty"`  // human note
	RotateAfter *time.Time        `json:"rotate_after,omitempty"` // rotation due date (drives `stale`)
	NoPrint     bool              `json:"no_print,omitempty"`     // exec-only: never reveal to stdout
	Meta        map[string]string `json:"meta,omitempty"`         // open-ended extensibility bag
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
	b, err := os.ReadFile(path)
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
	if s.Secrets == nil { // tolerate a store with no secrets yet
		s.Secrets = map[string]*Secret{}
	}
	s.path = path
	return &s, nil
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
