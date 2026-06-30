package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/arenzana/arca/internal/store"
)

// TestDecryptErrorPaths plants a validly-named but undecryptable secret (a corrupt store
// entry) and confirms every reveal/use path surfaces the decrypt failure: get, inject, exec,
// env, and the MCP value tools.
func TestDecryptErrorPaths(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "good", "set", "GOOD")

	s, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	s.Secrets["BAD"] = &store.Secret{Value: "-- not age ciphertext --", CreatedAt: time.Now().UTC()}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	if err := runArcaErr("", "get", "BAD"); err == nil {
		t.Error("get BAD should fail to decrypt")
	}
	if err := runArcaErr("x = arca://BAD\n", "inject"); err == nil {
		t.Error("inject BAD should fail to decrypt")
	}
	if err := runArcaErr("", "exec", "--only", "BAD", "--", "true"); err == nil {
		t.Error("exec BAD should fail to decrypt")
	}
	if err := runArcaErr("", "env"); err == nil {
		t.Error("env should fail with an undecryptable secret")
	}
	if !call(t, mcpReadSecret, map[string]any{"name": "BAD"}).IsError {
		t.Error("mcp read_secret BAD should error")
	}
	if !call(t, mcpRunWithSecrets, map[string]any{"command": "true", "secrets": []any{"BAD"}}).IsError {
		t.Error("mcp run_with_secrets BAD should error")
	}
}

// TestReencryptNoIdentity covers reencrypt's loadIDs-error branch.
func TestReencryptNoIdentity(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "A")
	t.Setenv("ARCA_IDENTITY", filepath.Join(t.TempDir(), "missing"))
	if err := runArcaErr("", "reencrypt"); err == nil {
		t.Fatal("expected reencrypt to fail with a missing identity")
	}
}
