package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSaveGrantsError covers the mkdir-failure path when the state dir can't be created.
func TestSaveGrantsError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil { // a file where a dir is needed
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", blocker)
	if err := saveGrants(map[string]Grant{"S": {Secret: "S", ExpiresAt: time.Now()}}); err == nil {
		t.Fatal("saveGrants should fail when the state dir can't be created")
	}
}

// TestGrantScopeStripsEscapes covers audit M1 on the grant prompt: --command and --agent are
// attacker-influenced and interpolated into the operator confirmation before they are validated.
func TestGrantScopeStripsEscapes(t *testing.T) {
	got := grantScope("15m\x1b[2J", 1, "terraform\x1b[2J apply", "claude\x07")
	if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x07) {
		t.Fatalf("grantScope leaked a terminal control: %q", got)
	}
	if !strings.Contains(got, "terraform") || !strings.Contains(got, "apply") || !strings.Contains(got, "claude") {
		t.Fatalf("grantScope dropped legitimate text: %q", got)
	}
}

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
