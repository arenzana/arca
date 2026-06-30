package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/arenzana/arca/internal/store"
)

func TestEditCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake editor is a /bin/sh script")
	}
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "original", "set", "API")

	// A fake $EDITOR that overwrites the file with new content.
	ed := filepath.Join(t.TempDir(), "ed.sh")
	if err := os.WriteFile(ed, []byte("#!/bin/sh\nprintf 'edited-value' > \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", ed)

	runArca(t, "", "edit", "API")
	if out := runArca(t, "", "get", "API"); out != "edited-value" {
		t.Fatalf("after edit, get = %q", out)
	}
	if err := runArcaErr("", "edit", "NOPE"); err == nil {
		t.Fatal("expected edit of a missing secret to fail")
	}
}

func TestEditErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses the unix `false`/`true` utilities as fake editors")
	}
	sandbox(t)
	runArca(t, "", "init")

	// A failing editor surfaces an error.
	runArca(t, "v", "set", "API")
	t.Setenv("EDITOR", "false")
	if err := runArcaErr("", "edit", "API"); err == nil {
		t.Fatal("expected a failing editor to error")
	}

	// An expired secret is gated before the editor runs.
	runArca(t, "v", "set", "OLD", "--expires-at", "2020-01-01")
	t.Setenv("EDITOR", "true")
	if err := runArcaErr("", "edit", "OLD"); err == nil {
		t.Fatal("expected edit of an expired secret to be refused")
	}

	// A missing identity fails the decrypt.
	runArca(t, "v", "set", "X")
	t.Setenv("ARCA_IDENTITY", filepath.Join(t.TempDir(), "missing"))
	if err := runArcaErr("", "edit", "X"); err == nil {
		t.Fatal("expected edit to fail with a missing identity")
	}
}

func TestRenameCommand(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "OLD", "--tag", "demo", "--desc", "d")

	runArca(t, "", "rename", "OLD", "NEW")
	if err := runArcaErr("", "get", "OLD"); err == nil {
		t.Fatal("OLD should no longer exist")
	}
	if out := runArca(t, "", "get", "NEW"); out != "v" {
		t.Fatalf("NEW = %q", out)
	}
	if out := runArca(t, "", "show", "NEW"); !strings.Contains(out, "demo") {
		t.Fatalf("metadata not preserved: %q", out)
	}

	// Refuse to clobber without --force; the mv alias + --force overwrites.
	runArca(t, "v2", "set", "OTHER")
	if err := runArcaErr("", "rename", "NEW", "OTHER"); err == nil {
		t.Fatal("rename onto an existing secret should fail without --force")
	}
	runArca(t, "", "mv", "NEW", "OTHER", "--force")

	if err := runArcaErr("", "rename", "GHOST", "X"); err == nil {
		t.Fatal("expected a missing source to fail")
	}
	if err := runArcaErr("", "rename", "OTHER", "bad-name"); err == nil {
		t.Fatal("expected an invalid destination name to fail")
	}
}

func TestEditRenameNoStore(t *testing.T) {
	sandbox(t) // no init
	if err := runArcaErr("", "edit", "X"); err == nil {
		t.Fatal("expected edit to fail with no store")
	}
	if err := runArcaErr("", "rename", "A", "B"); err == nil {
		t.Fatal("expected rename to fail with no store")
	}
}

func TestEditDecryptError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a /bin/sh editor")
	}
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "good", "set", "GOOD")
	s, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	s.Secrets["BAD"] = &store.Secret{Value: "not-ciphertext", CreatedAt: time.Now().UTC()}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", "true")
	if err := runArcaErr("", "edit", "BAD"); err == nil {
		t.Fatal("expected edit to fail decrypting a corrupt secret")
	}
}

func TestEditRenameAuditFailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a /bin/sh editor")
	}
	dir := sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "A")
	runArca(t, "v", "set", "B")
	if err := os.WriteFile(filepath.Join(dir, "audit.db"), []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", "true") // a no-op editor; edit still re-encrypts and audits
	if err := runArcaErr("", "edit", "A"); err == nil {
		t.Fatal("expected edit to fail-closed with a broken audit log")
	}
	if err := runArcaErr("", "rename", "B", "C"); err == nil {
		t.Fatal("expected rename to fail-closed with a broken audit log")
	}
}

func TestEditEncryptError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a /bin/sh editor")
	}
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "GOOD")
	s, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	s.Recipients = []string{"not-a-recipient"} // re-encrypt will fail to parse this
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", "true")
	if err := runArcaErr("", "edit", "GOOD"); err == nil {
		t.Fatal("expected edit to fail re-encrypting to an invalid recipient set")
	}
}

func TestEditInTemp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a /bin/sh editor")
	}
	ed := filepath.Join(t.TempDir(), "ed.sh")
	if err := os.WriteFile(ed, []byte("#!/bin/sh\nprintf 'edited\\n' > \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", ed)
	if out, err := editInTemp([]byte("orig")); err != nil || string(out) != "edited" { // trailing newline stripped
		t.Fatalf("editInTemp = %q, %v", out, err)
	}

	// An editor that deletes the file makes the read-back (and the scrub) fail.
	ed2 := filepath.Join(t.TempDir(), "rm.sh")
	if err := os.WriteFile(ed2, []byte("#!/bin/sh\nrm \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EDITOR", ed2)
	if _, err := editInTemp([]byte("x")); err == nil {
		t.Fatal("expected editInTemp to fail when the editor removed the file")
	}

	// A temp dir that can't be created surfaces the error.
	old := editTempDir
	defer func() { editTempDir = old }()
	editTempDir = func() string { return filepath.Join(t.TempDir(), "missing") }
	if _, err := editInTemp([]byte("x")); err == nil {
		t.Fatal("expected editInTemp to fail when the temp dir is missing")
	}
}
