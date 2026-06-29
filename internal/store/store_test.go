package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "store.json")
	s := New(p, []string{"age1xyz"})
	now := time.Now().UTC().Truncate(time.Second)
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

func TestLoadMissing(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error for a missing store")
	}
}

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
