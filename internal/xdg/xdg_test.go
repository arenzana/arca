package xdg

import (
	"path/filepath"
	"strings"
	"testing"
)

// Everything here is a pure function of the environment, which is the property that makes this
// layer worth separating from the per-store state machinery: these tests set variables and read
// strings, and touch no filesystem at all.

func TestHomePrefersTheEnvironmentVariable(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/explicit/config")
	if got := Home("XDG_CONFIG_HOME", ".config"); got != "/explicit/config" {
		t.Fatalf("Home = %q, want the environment value", got)
	}
}

func TestHomeFallsBackToTheUserHome(t *testing.T) {
	// os.UserHomeDir reads a different variable per platform: $HOME on Unix, %USERPROFILE% on
	// Windows. Setting only HOME passes locally and fails on the Windows runner against the real
	// profile directory, so set both and derive the expectation from the same call the code makes.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	if got, want := Home("XDG_CONFIG_HOME", ".config"), filepath.Join(home, ".config"); got != want {
		t.Fatalf("Home = %q, want %q", got, want)
	}
}

func TestConfigAndStateAreDistinct(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/c")
	t.Setenv("XDG_STATE_HOME", "/s")
	if got, want := ConfigDir(), filepath.Join("/c", "arca"); got != want {
		t.Fatalf("ConfigDir = %q, want %q", got, want)
	}
	if got, want := StateDir(), filepath.Join("/s", "arca"); got != want {
		t.Fatalf("StateDir = %q, want %q", got, want)
	}
	// They must not collapse onto one another: the store is meant to be syncable and the state
	// dir is meant to stay machine-local, and that separation is the whole reason for two roots.
	if ConfigDir() == StateDir() {
		t.Fatal("config and state directories resolved to the same path")
	}
}

func TestStorePathOverride(t *testing.T) {
	t.Setenv("ARCA_STORE", "/dotfiles/secrets.json")
	if got := StorePath(); got != "/dotfiles/secrets.json" {
		t.Fatalf("StorePath = %q, want the ARCA_STORE override", got)
	}
	t.Setenv("ARCA_STORE", "")
	t.Setenv("XDG_CONFIG_HOME", "/c")
	if got, want := StorePath(), filepath.Join("/c", "arca", "store.json"); got != want {
		t.Fatalf("StorePath = %q, want %q", got, want)
	}
}

// The precedence here is a documented promise, not an implementation detail: an existing sops
// user's key is picked up without being copied, and ARCA_IDENTITY still wins over it.
func TestIdentityPathPrecedence(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/c")

	t.Setenv("ARCA_IDENTITY", "/keys/arca.txt")
	t.Setenv("SOPS_AGE_KEY_FILE", "/keys/sops.txt")
	if got := IdentityPath(); got != "/keys/arca.txt" {
		t.Fatalf("ARCA_IDENTITY should win, got %q", got)
	}

	t.Setenv("ARCA_IDENTITY", "")
	if got := IdentityPath(); got != "/keys/sops.txt" {
		t.Fatalf("SOPS_AGE_KEY_FILE should be used when ARCA_IDENTITY is unset, got %q", got)
	}

	t.Setenv("SOPS_AGE_KEY_FILE", "")
	if got, want := IdentityPath(), filepath.Join("/c", "arca", "identity.txt"); got != want {
		t.Fatalf("IdentityPath = %q, want %q", got, want)
	}
}

// The identity is a private key and the store is not. They may share a directory by default, but
// they must never resolve to the same file, or writing one would destroy the other.
func TestStoreAndIdentityNeverCollide(t *testing.T) {
	t.Setenv("ARCA_STORE", "")
	t.Setenv("ARCA_IDENTITY", "")
	t.Setenv("SOPS_AGE_KEY_FILE", "")
	t.Setenv("XDG_CONFIG_HOME", "/c")
	if StorePath() == IdentityPath() {
		t.Fatalf("store and identity resolved to the same path: %q", StorePath())
	}
	for _, p := range []string{StorePath(), IdentityPath(), ConfigDir(), StateDir()} {
		if !strings.Contains(p, "arca") {
			t.Errorf("%q is not namespaced under arca", p)
		}
	}
}
