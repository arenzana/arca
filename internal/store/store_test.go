package store

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestSaveLoadRoundTrip checks that a store survives a Save/Load cycle with all metadata
// intact, and — importantly for a secrets file — that it lands on disk as 0600.
func TestSaveLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "store.json")
	s := New(p, []string{"age1xyz"})
	now := time.Now().UTC().Truncate(time.Second) // truncate so JSON time round-trips exactly
	s.Secrets["FOO"] = &Secret{
		Value:       "ciphertext",
		CreatedAt:   now,
		UpdatedAt:   now,
		Tags:        []string{"a", "b"},
		Description: "d",
		Meta:        map[string]string{"k": "v"},
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	// Unix mode bits: Windows governs file access by ACL, not 0600, so skip that check there.
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Fatalf("perms = %o, want 600", fi.Mode().Perm())
		}
	}

	got, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	sec := got.Secrets["FOO"]
	if sec == nil || sec.Value != "ciphertext" || sec.Description != "d" || sec.Meta["k"] != "v" {
		t.Fatalf("round-trip mismatch: %+v", sec)
	}
	if !sec.CreatedAt.Equal(now) {
		t.Fatalf("created_at mismatch: %v != %v", sec.CreatedAt, now)
	}
	if len(got.Recipients) != 1 || got.Recipients[0] != "age1xyz" {
		t.Fatalf("recipients mismatch: %v", got.Recipients)
	}
}

// TestLoadMissing ensures a missing store is a clean error (the CLI turns this into the
// friendly "run `arca init`" message), not a panic or empty store.
func TestLoadMissing(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error for a missing store")
	}
}

// TestNamesSorted verifies the deterministic ordering that keeps `ls`/`stale` output stable.
func TestNamesSorted(t *testing.T) {
	s := New("", nil)
	s.Secrets["b"] = &Secret{}
	s.Secrets["a"] = &Secret{}
	s.Secrets["c"] = &Secret{}
	got := s.Names()
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("names = %v, want %v", got, want)
		}
	}
}

// TestLoadBadJSON ensures a corrupt store yields a parse error rather than a panic.
func TestLoadBadJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(p, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected a parse error for corrupt JSON")
	}
}

// TestSaveError exercises the failure path: when the parent path is a regular file, the
// directory creation inside Save must fail.
func TestSaveError(t *testing.T) {
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(filepath.Join(f, "store.json"), nil)
	if err := s.Save(); err == nil {
		t.Fatal("expected Save to fail when the parent path is a file")
	}
}

// TestLoadNullSecrets covers Load's branch that initializes a nil secrets map (a store whose
// JSON has "secrets": null).
func TestLoadNullSecrets(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(p, []byte(`{"version":1,"recipients":[],"secrets":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.Secrets == nil {
		t.Fatal("expected an initialized secrets map")
	}
}

// TestLoadDirectory covers the non-"not exist" read error branch (reading a directory).
func TestLoadDirectory(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("expected an error loading a directory as a store")
	}
}

// TestSaveCreateTempError covers the temp-file creation error path: the target directory
// exists but is read-only, so CreateTemp inside Save fails. (Skipped when running as root,
// which bypasses permission checks.)
func TestSaveCreateTempError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a 0500 directory does not block the owner from writing on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permissions")
	}
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700) // allow t.TempDir cleanup
	s := New(filepath.Join(dir, "store.json"), nil)
	if err := s.Save(); err == nil {
		t.Fatal("expected Save to fail writing into a read-only directory")
	}
}

// TestSaveRenameError covers the final atomic-rename error branch: the target path is itself a
// directory, so renaming the temp file over it fails.
func TestSaveRenameError(t *testing.T) {
	target := filepath.Join(t.TempDir(), "store.json")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	s := New(target, nil)
	if err := s.Save(); err == nil {
		t.Fatal("expected Save to fail renaming over a directory")
	}
}

// TestExpired covers the hard-expiry predicate: no expiry → never; past → expired; future → not.
func TestExpired(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	if (&Secret{}).Expired(now) {
		t.Fatal("a secret with no expiry must not be expired")
	}
	if !(&Secret{ExpiresAt: &past}).Expired(now) {
		t.Fatal("a past expiry must be expired")
	}
	if (&Secret{ExpiresAt: &future}).Expired(now) {
		t.Fatal("a future expiry must not be expired")
	}
}

// TestLoadNullEntry rejects a store with a null secret object (which would otherwise nil-deref).
func TestLoadNullEntry(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(p, []byte(`{"version":1,"recipients":[],"secrets":{"FOO":null}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected an error for a null secret entry")
	}
}

// TestLoadNewerVersion refuses a store written by a newer arca.
func TestLoadNewerVersion(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(p, []byte(`{"version":999,"recipients":[],"secrets":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("expected an error for a newer store version")
	}
}

// TestLoadTooLarge refuses an implausibly large store (a sparse file, so the test stays cheap).
func TestLoadTooLarge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxStoreBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := Load(p); err == nil {
		t.Fatal("expected an error for an oversized store")
	}
}

// TestLoadUnversioned normalizes a store with no version field to the v1 baseline.
func TestLoadUnversioned(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(p, []byte(`{"recipients":["age1x"],"secrets":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 1 {
		t.Fatalf("an unversioned store should normalize to v1, got %d", s.Version)
	}
}

// TestApplyMigrations exercises the version-stepping core with a synthetic migration chain.
func TestApplyMigrations(t *testing.T) {
	s := &Store{Version: 1}
	migs := map[int]migration{
		1: func(s *Store) error { s.Recipients = append(s.Recipients, "v2"); return nil },
		2: func(s *Store) error { s.Recipients = append(s.Recipients, "v3"); return nil },
	}
	if err := applyMigrations(s, 3, migs); err != nil {
		t.Fatal(err)
	}
	if s.Version != 3 || len(s.Recipients) != 2 {
		t.Fatalf("after migrate: v%d recipients=%v", s.Version, s.Recipients)
	}
	// A missing step is an error.
	if err := applyMigrations(&Store{Version: 1}, 3, map[int]migration{}); err == nil {
		t.Fatal("expected an error for a missing migration step")
	}
	// A failing migration propagates.
	boom := map[int]migration{1: func(*Store) error { return fmt.Errorf("boom") }}
	if err := applyMigrations(&Store{Version: 1}, 2, boom); err == nil {
		t.Fatal("expected the migration error to propagate")
	}
}

// TestRecipientLabels covers Label/SetLabel: nil-map reads, set, overwrite, and clear.
func TestRecipientLabels(t *testing.T) {
	var s Store // zero value: RecipientLabels is nil
	if got := s.Label("age1abc"); got != "" {
		t.Fatalf("nil-map Label = %q, want empty", got)
	}
	s.SetLabel("age1abc", "laptop") // first set allocates the map
	if got := s.Label("age1abc"); got != "laptop" {
		t.Fatalf("Label after set = %q, want laptop", got)
	}
	s.SetLabel("age1abc", "workstation") // overwrite
	if got := s.Label("age1abc"); got != "workstation" {
		t.Fatalf("Label after overwrite = %q, want workstation", got)
	}
	s.SetLabel("age1abc", "") // empty clears
	if got := s.Label("age1abc"); got != "" {
		t.Fatalf("Label after clear = %q, want empty", got)
	}
	s.SetLabel("age1def", "") // clearing an absent key is a no-op, not a panic
}

// TestDecodeMatchesLoad pins Decode as a true peer of Load rather than a partial copy of it.
// Decode exists so `sync` can get the raw bytes and the parsed store from ONE read of one
// file; if it ever validated less than Load, sync would become the one caller that accepts a
// store everything else rejects.
func TestDecodeMatchesLoad(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string // "" = must parse
	}{
		{
			name: "valid store",
			body: `{"version":1,"recipients":["age1x"],"generation":3,"secrets":{}}`,
		},
		{
			name:    "malformed json",
			body:    `{"version":1,`,
			wantErr: "parse store",
		},
		{
			name:    "version from the future",
			body:    fmt.Sprintf(`{"version":%d,"recipients":["age1x"],"secrets":{}}`, Version+1),
			wantErr: "newer than this arca supports",
		},
		{
			name:    "null secret entry",
			body:    `{"version":1,"recipients":["age1x"],"secrets":{"FOO":null}}`,
			wantErr: `secret "FOO" is null`,
		},
		{
			name: "absent secrets map is tolerated",
			body: `{"version":1,"recipients":["age1x"],"generation":1}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "store.json")
			if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, loadErr := Load(p)
			decoded, decErr := Decode(p, []byte(tc.body))

			// Same verdict, same message: one implementation, reached two ways.
			switch {
			case (loadErr == nil) != (decErr == nil):
				t.Fatalf("Load err = %v but Decode err = %v", loadErr, decErr)
			case loadErr != nil && loadErr.Error() != decErr.Error():
				t.Fatalf("Load err = %q, Decode err = %q", loadErr, decErr)
			}
			if tc.wantErr == "" {
				if decErr != nil {
					t.Fatalf("Decode = %v, want success", decErr)
				}
				if decoded.Generation != loaded.Generation || decoded.Version != loaded.Version {
					t.Fatalf("Decode gave version %d gen %d, Load gave version %d gen %d",
						decoded.Version, decoded.Generation, loaded.Version, loaded.Generation)
				}
				if len(decoded.Secrets) != len(loaded.Secrets) {
					t.Fatalf("Decode gave %d secrets, Load gave %d", len(decoded.Secrets), len(loaded.Secrets))
				}
				// path must be bound so a decoded store can still Save.
				if decoded.path != p {
					t.Fatalf("Decode did not bind the path: %q", decoded.path)
				}
				return
			}
			if decErr == nil {
				t.Fatalf("Decode accepted %s, want error containing %q", tc.name, tc.wantErr)
			}
			if !strings.Contains(decErr.Error(), tc.wantErr) {
				t.Fatalf("Decode err = %q, want it to contain %q", decErr, tc.wantErr)
			}
		})
	}
}

// TestDecodeSizeLimit: Load rejects an oversized store by stat before reading it; Decode gets
// bytes the caller already holds, so it enforces the same ceiling on the slice.
func TestDecodeSizeLimit(t *testing.T) {
	if _, err := Decode("/tmp/store.json", make([]byte, maxStoreBytes+1)); err == nil {
		t.Fatal("Decode accepted a store over the size limit")
	} else if !strings.Contains(err.Error(), "exceeding the") {
		t.Fatalf("Decode err = %q, want the size-limit message", err)
	}
}
