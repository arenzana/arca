package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/store"
)

// runArca executes the root command with args, feeding stdin and capturing stdout.
func runArca(t *testing.T, stdin string, args ...string) string {
	t.Helper()

	oldIn := os.Stdin
	ir, iw, _ := os.Pipe()
	go func() { io.WriteString(iw, stdin); iw.Close() }()
	os.Stdin = ir
	defer func() { os.Stdin = oldIn; ir.Close() }()

	oldOut := os.Stdout
	or, ow, _ := os.Pipe()
	os.Stdout = ow
	done := make(chan string, 1)
	go func() { var b bytes.Buffer; io.Copy(&b, or); done <- b.String() }()

	root := newRoot()
	root.SetArgs(args)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.Execute()

	ow.Close()
	os.Stdout = oldOut
	out := <-done
	if err != nil {
		t.Fatalf("arca %s: %v", strings.Join(args, " "), err)
	}
	return out
}

func sandbox(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SOPS_AGE_KEY_FILE", "") // force a generated identity
	t.Setenv("ARCA_STORE", filepath.Join(dir, "store.json"))
	t.Setenv("ARCA_AUDIT", filepath.Join(dir, "audit.db"))
	t.Setenv("ARCA_IDENTITY", filepath.Join(dir, "id.txt"))
	return dir
}

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

	// rotate keeps created_at, replaces the value
	runArca(t, "newsecret", "rotate", "API_TOKEN")
	s2, _ := store.Load(filepath.Join(dir, "store.json"))
	if !s2.Secrets["API_TOKEN"].CreatedAt.Equal(created) {
		t.Fatal("rotate changed created_at")
	}
	if out := runArca(t, "", "get", "API_TOKEN"); out != "newsecret" {
		t.Fatalf("after rotate, get = %q", out)
	}

	// audit recorded the actor and a rotation
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
