package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/store"
)

// TestRecipientNoopBranches covers the "no new" / "no matching" no-op branches of recipients
// add/rm and a successful reencrypt (local identity is a recipient).
func TestRecipientNoopBranches(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")
	_, r2, _ := crypto.GenerateIdentity()

	runArca(t, "", "recipients", "add", r2)
	runArca(t, "", "recipients", "add", r2) // already present → "no new recipients"
	_, r3, _ := crypto.GenerateIdentity()
	runArca(t, "", "recipients", "rm", r3) // not present → "no matching recipients"
	runArca(t, "", "reencrypt")            // succeeds; local identity can still decrypt
}

// TestReencryptCannotDecrypt covers reencrypt's decrypt-failure branch: the store's secret is
// encrypted to a foreign recipient the local identity can't read.
func TestReencryptCannotDecrypt(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	_, fRec, _ := crypto.GenerateIdentity()
	fr, _ := crypto.ParseRecipients([]string{fRec})
	ct, err := crypto.Encrypt([]byte("v"), fr)
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	s.Recipients = []string{fRec}
	s.Secrets["S"] = &store.Secret{Value: ct, CreatedAt: time.Now().UTC()}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if err := runArcaErr("", "reencrypt"); err == nil {
		t.Fatal("expected reencrypt to fail when the local identity is not a recipient")
	}
}

// TestRotateErrors covers rotate's error branches.
func TestRotateErrors(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := runArcaErr("v", "rotate", "NOPE"); err == nil {
		t.Fatal("expected rotate of a missing secret to fail")
	}
	runArca(t, "v", "set", "X")
	if err := runArcaErr("v", "rotate", "X", "--rotate-after", "nope"); err == nil {
		t.Fatal("expected a bad --rotate-after to fail")
	}
	if err := runArcaErr("v", "rotate", "X", "--ttl", "nope"); err == nil {
		t.Fatal("expected a bad --ttl to fail")
	}
}

// TestNewCommandsNoStore covers the openStore-error branch of the commands added recently.
func TestNewCommandsNoStore(t *testing.T) {
	sandbox(t) // no init → no store
	for _, args := range [][]string{
		{"recipients"}, {"recipients", "add", "age1xyz"}, {"recipients", "rm", "age1xyz"},
		{"reencrypt"}, {"rotate", "X"}, {"disable", "X"}, {"enable", "X"},
	} {
		if err := runArcaErr("v", args...); err == nil {
			t.Errorf("expected %v to fail with no store", args)
		}
	}
}

// TestInitForce covers init's refuse-existing, --force overwrite, and identity-reuse branches.
func TestInitForce(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init") // generates a new identity
	if err := runArcaErr("", "init"); err == nil {
		t.Fatal("expected init to refuse an existing store")
	}
	runArca(t, "", "init", "--force") // overwrites; reuses the now-existing identity
}

// TestCompletionNoStore covers the openStore-error branch of the completion helpers.
func TestCompletionNoStore(t *testing.T) {
	sandbox(t) // no init
	if names, _ := completeSecretNames(nil, nil, ""); names != nil {
		t.Fatalf("expected nil completions with no store, got %v", names)
	}
	if tags, _ := completeTags(nil, nil, ""); tags != nil {
		t.Fatalf("expected nil tag completions with no store, got %v", tags)
	}
}

// TestMCPErrorBranches covers the MCP handlers' loadIDs/decrypt and audit-open error paths.
func TestMCPErrorBranches(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "secret", "set", "API")

	// A missing identity makes loadIDs fail for the value paths.
	t.Setenv("ARCA_IDENTITY", filepath.Join(t.TempDir(), "missing"))
	if !call(t, mcpReadSecret, map[string]any{"name": "API"}).IsError {
		t.Fatal("expected read_secret to error with a missing identity")
	}
	if !call(t, mcpRunWithSecrets, map[string]any{"command": "true", "secrets": []any{"API"}}).IsError {
		t.Fatal("expected run_with_secrets to error with a missing identity")
	}
}

// TestMCPAuditLogBadPath covers audit_log's Open-error branch.
func TestMCPAuditLogBadPath(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARCA_AUDIT", filepath.Join(f, "a.db")) // parent is a file → Open fails
	if !call(t, mcpAuditLog, nil).IsError {
		t.Fatal("expected audit_log to error when the audit DB cannot open")
	}
}
