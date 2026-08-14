// Package xdg resolves where arca's files live from configuration alone: the XDG base
// directories, the user's home, and the documented environment overrides.
//
// This is the lower of arca's two path layers, and the split is a real dependency boundary rather
// than a tidy one. Everything here is a pure function of the environment: same env, same answer,
// no filesystem access and no side effects. The layer above it (`storeStateDir` and the pre-D4
// legacy-state adoption in statedir.go) creates directories, takes a lock, and migrates files, and
// it is built *on* StateDir rather than beside it. Keeping the two apart is what makes this layer
// testable by setting environment variables and nothing else.
//
// The variables read here are a documented interface: ARCA_STORE, ARCA_IDENTITY and
// SOPS_AGE_KEY_FILE, plus XDG_CONFIG_HOME and XDG_STATE_HOME. See STABILITY.md, which lists them
// among the surfaces that keep their meaning.
package xdg

import (
	"os"
	"path/filepath"
)

// Home returns $env if it is set, else $HOME/def. The XDG-with-fallback rule, in one place so a
// second copy cannot disagree about which variable wins.
//
// A home directory that cannot be determined yields a relative path rather than an error, which is
// deliberate: every caller is building a path it will then try to use, and a failure there reports
// the actual problem with the actual path in it. Returning an error here would only move the same
// failure earlier and make every call site branch on it.
func Home(env, def string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, def)
}

// ConfigDir is arca's configuration directory: the store and the age identity live here by
// default, because both are things a user may want to keep in a dotfiles repository.
func ConfigDir() string { return filepath.Join(Home("XDG_CONFIG_HOME", ".config"), "arca") }

// StateDir is arca's state directory: machine-local data that must NOT travel with the store,
// such as the audit database and the recipient pin. The layer above subdivides this per store.
func StateDir() string { return filepath.Join(Home("XDG_STATE_HOME", ".local/state"), "arca") }

// StorePath is the JSON store, which is git-syncable by design. $ARCA_STORE overrides it, which
// is how a store gets pointed at a dotfiles repo while the audit log stays local.
func StorePath() string {
	if p := os.Getenv("ARCA_STORE"); p != "" {
		return p
	}
	return filepath.Join(ConfigDir(), "store.json")
}

// IdentityPath is the age identity used to decrypt. $ARCA_IDENTITY wins, then
// $SOPS_AGE_KEY_FILE, so an existing sops user's key is picked up without being copied or moved.
func IdentityPath() string {
	if p := os.Getenv("ARCA_IDENTITY"); p != "" {
		return p
	}
	if p := os.Getenv("SOPS_AGE_KEY_FILE"); p != "" {
		return p
	}
	return filepath.Join(ConfigDir(), "identity.txt")
}
