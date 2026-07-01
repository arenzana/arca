package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHandles covers the handle lifecycle through the CLI plus resolveHandle's scope/expiry checks.
func TestHandles(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "DB")

	// handle ls with none planted.
	runArca(t, "", "handle", "ls")

	id := strings.TrimSpace(runArca(t, "", "handle", "create", "DB", "--as", "TOK", "--command", "sh *", "--ttl", "1h"))
	if !strings.HasPrefix(id, "hdl_") {
		t.Fatalf("handle id = %q", id)
	}
	if out := runArca(t, "", "handle", "ls"); !strings.Contains(out, id) || !strings.Contains(out, "DB") || !strings.Contains(out, "TOK") {
		t.Fatalf("handle ls = %q", out)
	}

	// resolveHandle: matching command ok, others refused.
	if _, err := resolveHandle(id, "sh -c echo"); err != nil {
		t.Fatalf("a matching command should resolve: %v", err)
	}
	if _, err := resolveHandle(id, "psql foo"); err == nil {
		t.Fatal("a non-matching command should be refused")
	}
	if _, err := resolveHandle("hdl_nope", "sh"); err == nil {
		t.Fatal("an unknown handle should be refused")
	}

	// revoke.
	runArca(t, "", "handle", "revoke", id)
	if _, err := resolveHandle(id, "sh"); err == nil {
		t.Fatal("a revoked handle should not resolve")
	}
	if err := runArcaErr("", "handle", "revoke", id); err == nil {
		t.Fatal("revoking an unknown handle should error")
	}
}

// TestHandleValidation covers create-time validation and the expiry check.
func TestHandleValidation(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	if err := runArcaErr("", "handle", "create", "GHOST", "--ttl", "1h"); err == nil {
		t.Fatal("a handle for a nonexistent secret should error")
	}
	runArca(t, "v", "set", "DB")
	if err := runArcaErr("", "handle", "create", "DB"); err == nil {
		t.Fatal("a handle without --ttl should error")
	}
	if err := runArcaErr("", "handle", "create", "bad-name", "--ttl", "1h"); err == nil {
		t.Fatal("an invalid secret name should error")
	}
	if err := runArcaErr("", "handle", "create", "DB", "--ttl", "1h", "--as", "bad-env"); err == nil {
		t.Fatal("an invalid --as env name should error")
	}
	if err := runArcaErr("", "handle", "create", "DB", "--ttl", "nonsense"); err == nil {
		t.Fatal("a bad --ttl should error")
	}

	// An expired handle does not resolve.
	id := strings.TrimSpace(runArca(t, "", "handle", "create", "DB", "--ttl", "1h"))
	handles, err := loadHandles()
	if err != nil {
		t.Fatal(err)
	}
	h := handles[id]
	h.ExpiresAt = time.Now().Add(-time.Hour)
	handles[id] = h
	if err := saveHandles(handles); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveHandle(id, "anything"); err == nil {
		t.Fatal("an expired handle should not resolve")
	}
	if out := runArca(t, "", "handle", "ls"); !strings.Contains(out, "expired") {
		t.Fatalf("handle ls should mark the backdated handle expired: %q", out)
	}
}

// TestLoadHandlesErrors covers the empty-object and malformed-JSON branches of loadHandles.
func TestLoadHandlesErrors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	if err := os.MkdirAll(filepath.Dir(handlesPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(handlesPath(), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if h, err := loadHandles(); err != nil || h == nil {
		t.Fatalf("empty handles = %v, %v", h, err)
	}
	if err := os.WriteFile(handlesPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHandles(); err == nil {
		t.Fatal("malformed handles file should error")
	}
	// A malformed store also fails resolveHandle (which loads it).
	if _, err := resolveHandle("hdl_x", "cmd"); err == nil {
		t.Fatal("resolveHandle over a malformed handles file should error")
	}
}

// TestHandleCreateNoStore covers the openStore error branch of handle create.
func TestHandleCreateNoStore(t *testing.T) {
	sandbox(t) // no init, so the store doesn't exist yet
	if err := runArcaErr("", "handle", "create", "X", "--ttl", "1h"); err == nil {
		t.Fatal("handle create without a store should error")
	}
}

// TestSaveHandlesError covers the mkdir failure path when the state dir can't be created.
func TestSaveHandlesError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil { // a file where a dir is needed
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", blocker)
	if err := saveHandles(map[string]Handle{}); err == nil {
		t.Fatal("saveHandles should fail when the state dir can't be created")
	}
}
