package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/store"
)

// execArca runs the root command with args, feeding stdin and capturing stdout.
//
// The commands read os.Stdin directly (readValue, inject) and write output to os.Stdout (get,
// inject, env, log, --json), so we temporarily swap those process globals around a single
// Execute(). We back them with temp files rather than os.Pipe: a file has no reader/writer race,
// which keeps the harness deterministic on Windows (where a pipe whose peer closes early fails
// the write with "the pipe is being closed").
//
// Both globals are restored before returning, so tests must not run in parallel.
func execArca(stdin string, args ...string) (string, error) {
	inF, err := os.CreateTemp("", "arca-in-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(inF.Name())
	if _, err := inF.WriteString(stdin); err != nil {
		inF.Close()
		return "", err
	}
	if _, err := inF.Seek(0, 0); err != nil {
		inF.Close()
		return "", err
	}
	outF, err := os.CreateTemp("", "arca-out-*")
	if err != nil {
		inF.Close()
		return "", err
	}
	defer os.Remove(outF.Name())

	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inF, outF
	defer func() {
		os.Stdin, os.Stdout = oldIn, oldOut
		inF.Close()
		outF.Close()
	}()

	root := newRoot()
	root.SetArgs(args)
	root.SetOut(io.Discard) // silence cobra's own usage/output; we only care about os.Stdout
	root.SetErr(io.Discard)
	err = root.Execute()

	_ = outF.Sync()
	_, _ = outF.Seek(0, 0)
	b, _ := io.ReadAll(outF)
	return string(b), err
}

// runArca is execArca for the happy path: it fails the test on any command error.
func runArca(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	out, err := execArca(stdin, args...)
	if err != nil {
		t.Fatalf("arca %s: %v", strings.Join(args, " "), err)
	}
	return out
}

// runArcaErr is for the cases where an error is the expected outcome (e.g. get on --no-print).
func runArcaErr(stdin string, args ...string) error {
	_, err := execArca(stdin, args...)
	return err
}

// sandbox points every arca path at a temp dir and forces a freshly generated identity, so a
// test never touches the developer's real store, audit db, or sops key.
func sandbox(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SOPS_AGE_KEY_FILE", "") // ignore any real sops key → init generates one
	t.Setenv("ARCA_STORE", filepath.Join(dir, "store.json"))
	t.Setenv("ARCA_AUDIT", filepath.Join(dir, "audit.db"))
	t.Setenv("ARCA_IDENTITY", filepath.Join(dir, "id.txt"))
	return dir
}

// TestEndToEnd walks the primary lifecycle through the real command tree: init → set → get →
// rotate → get, asserting along the way that the stored value is encrypted (not cleartext),
// that rotate preserves created_at, and that the audit log captured the rotation and the actor.
func TestEndToEnd(t *testing.T) {
	dir := sandbox(t)
	t.Setenv("ARCA_ACTOR", "test-agent")

	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API_TOKEN", "--tag", "demo", "--desc", "d")

	if out := runArca(t, "", "get", "API_TOKEN"); out != "hunter2" {
		t.Fatalf("get returned %q, want hunter2", out)
	}

	s, err := store.Load(filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	sec := s.Secrets["API_TOKEN"]
	if sec == nil {
		t.Fatal("secret not stored")
	}
	if strings.Contains(sec.Value, "hunter2") {
		t.Fatal("value is stored in cleartext!")
	}
	created := sec.CreatedAt

	// rotate keeps created_at, replaces the value.
	runArca(t, "newsecret", "rotate", "API_TOKEN")
	s2, _ := store.Load(filepath.Join(dir, "store.json"))
	if !s2.Secrets["API_TOKEN"].CreatedAt.Equal(created) {
		t.Fatal("rotate changed created_at")
	}
	if out := runArca(t, "", "get", "API_TOKEN"); out != "newsecret" {
		t.Fatalf("after rotate, get = %q", out)
	}

	// The audit log must show a rotation and the explicit actor.
	a, _ := audit.Open(filepath.Join(dir, "audit.db"))
	defer a.Close()
	evs, _ := a.Recent("API_TOKEN", 50)
	var sawRotate, sawActor bool
	for _, e := range evs {
		if e.Op == "rotate" {
			sawRotate = true
		}
		if e.Actor == "test-agent" {
			sawActor = true
		}
	}
	if !sawRotate {
		t.Fatal("rotate was not audited")
	}
	if !sawActor {
		t.Fatal("actor was not recorded")
	}
}

// TestStale checks the rotation-due filter: a past rotate_after is listed, a far-future one is
// not.
func TestStale(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "OLD", "--rotate-after", "2000-01-01")
	runArca(t, "v", "set", "NEW", "--rotate-after", "2999-01-01")

	out := runArca(t, "", "stale")
	if !strings.Contains(out, "OLD") || strings.Contains(out, "NEW") {
		t.Fatalf("stale output = %q (want OLD present, NEW absent)", out)
	}
}

// TestDetectIdentityClaude verifies Claude Code is recognized from its env vars, with the
// version parsed out of the exec path. (t.Setenv overrides whatever the test host has set.)
func TestDetectIdentityClaude(t *testing.T) {
	t.Setenv("ARCA_ACTOR", "")
	t.Setenv("AI_AGENT", "")
	t.Setenv("CURSOR_TRACE_ID", "")
	t.Setenv("CLAUDECODE", "1")
	t.Setenv("CLAUDE_CODE_SESSION_ID", "sess-123")
	t.Setenv("CLAUDE_CODE_EXECPATH", "/opt/homebrew/Caskroom/claude-code/2.1.181/claude")
	id := detectIdentity()
	if id.Agent != "claude-code" || id.Session != "sess-123" || id.Version != "2.1.181" {
		t.Fatalf("got %+v", id)
	}
}

// TestDetectIdentityGeneric verifies the fallback parser for the generic AI_AGENT convention
// (name_version_agent), used for agents arca doesn't special-case.
func TestDetectIdentityGeneric(t *testing.T) {
	t.Setenv("ARCA_ACTOR", "")
	t.Setenv("CLAUDECODE", "")
	t.Setenv("CLAUDE_CODE_SESSION_ID", "")
	t.Setenv("CURSOR_TRACE_ID", "")
	t.Setenv("AI_AGENT", "myagent_1-2-3_agent")
	id := detectIdentity()
	if id.Agent != "myagent" || id.Version != "1.2.3" {
		t.Fatalf("got %+v", id)
	}
}

// TestNoPrintAndInject covers the AI-safety policy surface:
//   - inject resolves a normal arca:// reference;
//   - a --no-print secret is refused by both get and inject (it must not reach stdout);
//   - but exec can still inject it into a subprocess (here we only echo its length, never the
//     value — "secretval" is 9 chars).
func TestNoPrintAndInject(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "plainval", "set", "NORMAL")
	runArca(t, "secretval", "set", "LOCKED", "--no-print")

	if out := runArca(t, "endpoint=arca://NORMAL\n", "inject"); !strings.Contains(out, "endpoint=plainval") {
		t.Fatalf("inject = %q", out)
	}
	if err := runArcaErr("", "get", "LOCKED"); err == nil {
		t.Fatal("expected get on --no-print to fail")
	}
	if err := runArcaErr("x=arca://LOCKED", "inject"); err == nil {
		t.Fatal("expected inject of --no-print to fail")
	}
	if out := runArca(t, "", "exec", "--only", "LOCKED", "--", "sh", "-c", "echo got=${#LOCKED}"); !strings.Contains(out, "got=9") {
		t.Fatalf("exec no-print = %q", out)
	}
}
