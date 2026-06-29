// Package store is the JSON secret store: cleartext metadata, per-value age ciphertext.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const Version = 1

// Secret holds one entry. Value is an armored age ciphertext; everything else is cleartext
// metadata so the store can be listed/queried without the decryption key.
type Secret struct {
	Value       string            `json:"value"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Tags        []string          `json:"tags,omitempty"`
	Description string            `json:"description,omitempty"`
	RotateAfter *time.Time        `json:"rotate_after,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
}

// Store is the on-disk document. Read access is NOT tracked here (that lives in the audit DB),
// so reads never mutate this file — keeping it clean for git.
type Store struct {
	Version    int                `json:"version"`
	Recipients []string           `json:"recipients"`
	Secrets    map[string]*Secret `json:"secrets"`

	path string
}

func New(path string, recipients []string) *Store {
	return &Store{Version: Version, Recipients: recipients, Secrets: map[string]*Secret{}, path: path}
}

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
	if s.Secrets == nil {
		s.Secrets = map[string]*Secret{}
	}
	s.path = path
	return &s, nil
}

// Save writes the store atomically (temp + rename) with 0600 perms.
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
	defer os.Remove(tmpName)
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

// Names returns secret names sorted.
func (s *Store) Names() []string {
	names := make([]string, 0, len(s.Secrets))
	for n := range s.Secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
