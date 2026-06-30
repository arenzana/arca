package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, s string
		want   bool
	}{
		{"terraform *", "terraform apply", true},
		{"terraform *", "terraform plan -out x", true},
		{"terraform *", "kubectl get", false},
		{"terraform", "terraform", true},
		{"terraform", "terraform apply", false},
		{"* apply", "terraform apply", true},
		{"kubectl * pods", "kubectl get pods", true},
		{"kubectl * pods", "kubectl get svc", false},
		{"a*b*c", "axxbyyc", true}, // two wildcards: exercises the middle-segment loop
		{"a*b*c", "axxyyc", false}, // middle segment 'b' missing
		{"*", "anything at all", true},
		{"true*", "true", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pat, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pat, c.s, got, c.want)
		}
	}
}

// TestLoadGrantsErrors covers the empty-object and malformed-JSON branches of loadGrants.
func TestLoadGrantsErrors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	if err := os.MkdirAll(filepath.Dir(grantsPath()), 0o700); err != nil {
		t.Fatal(err)
	}

	// A valid object with no grants key yields a non-nil empty map.
	if err := os.WriteFile(grantsPath(), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if g, err := loadGrants(); err != nil || g == nil {
		t.Fatalf("empty grants = %v, %v; want non-nil map, nil error", g, err)
	}

	// Malformed JSON is an error, not a silent empty.
	if err := os.WriteFile(grantsPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGrants(); err == nil {
		t.Fatal("malformed grants file should error")
	}
}
