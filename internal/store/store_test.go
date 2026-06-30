package store

import (
	"os"
	"path/filepath"
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

	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("perms = %o, want 600", fi.Mode().Perm())
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
