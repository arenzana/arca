package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/store"
	"github.com/arenzana/arca/internal/xdg"
)

// withTTYCapture is withTTYResponse plus a file that records what was written to the fake
// terminal, so a test can assert on the prompt the operator actually sees (SEC-07 / audit M1).
// The returned path is complete after the prompted call returns (approve / requireOperator
// close the write handle).
func withTTYCapture(t *testing.T, answer string) string {
	t.Helper()
	dir := t.TempDir()
	inPath := filepath.Join(dir, "tty-in")
	if err := os.WriteFile(inPath, []byte(answer+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "tty-out")
	if err := os.WriteFile(outPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := openTTY
	t.Cleanup(func() { openTTY = old })
	openTTY = func() (in, out *os.File, err error) {
		f, err := os.Open(inPath)
		if err != nil {
			return nil, nil, err
		}
		w, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			f.Close()
			return nil, nil, err
		}
		return f, w, nil
	}
	return outPath
}

// TestShowSanitizesName covers FU-3: `show` must sanitize the secret name it prints, so a poisoned
// store key containing a terminal escape can't inject into the operator's terminal.
func TestShowSanitizesName(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "GOOD")
	s, err := store.Load(xdg.StorePath())
	if err != nil {
		t.Fatal(err)
	}
	bad := "EVIL\x1b]0;pwned\x07"
	s.Secrets[bad] = s.Secrets["GOOD"] // poison a name directly, bypassing set's validation
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	out := runArca(t, "", "show", bad)
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Fatalf("show leaked a terminal escape from a poisoned name: %q", out)
	}
}

// TestSanitize covers the control-character stripper: escapes and other control bytes are removed,
// ordinary printable text and multi-byte Unicode are preserved, and clean text is returned as-is.
func TestSanitize(t *testing.T) {
	in := "ok\x1b[2Jbad\x07\rmore\x1b]0;title\x07 café 日本 \x9b"
	got := sanitize(in)
	for _, bad := range []rune{0x1b, 0x07, '\r', 0x9b} {
		if strings.ContainsRune(got, bad) {
			t.Fatalf("sanitize left control char %#x: %q", bad, got)
		}
	}
	if !strings.Contains(got, "café") || !strings.Contains(got, "日本") {
		t.Fatalf("sanitize dropped legitimate text: %q", got)
	}
	if s := "clean text 123"; sanitize(s) != s {
		t.Fatalf("sanitize altered clean text: %q", sanitize(s))
	}
}

// TestRenderStripsEscapes covers SEC-07 end-to-end: a crafted description/tag and a crafted actor
// (from the environment) must not carry terminal escapes into `show` / `ls` / `log` output.
func TestRenderStripsEscapes(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	evil := "\x1b]0;pwned\x07\x1b[2Jhidden"
	runArca(t, "v", "set", "X", "--desc", evil, "--tag", "a\x1bb")

	for _, name := range []string{"show", "ls"} {
		var out string
		if name == "show" {
			out = runArca(t, "", "show", "X")
		} else {
			out = runArca(t, "", "ls")
		}
		if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
			t.Fatalf("%s output carried a terminal escape: %q", name, out)
		}
	}

	// The audit log's actor/agent columns come from the environment (attacker-controlled for an
	// agent) — they must be sanitized too.
	t.Setenv("ARCA_ACTOR", "actor\x1b[31m\x1b]0;x\x07")
	runArca(t, "", "get", "X")
	if out := runArca(t, "", "log"); strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Fatalf("log output carried an escape from a crafted actor: %q", out)
	}
}

// TestApproverWhoStripsEscapes covers audit M1 on the approval descriptor: $AI_AGENT / session /
// $ARCA_ACTOR are attacker-controlled for a detected agent and must not carry terminal controls
// into the string approve() interpolates onto /dev/tty.
func TestApproverWhoStripsEscapes(t *testing.T) {
	t.Setenv("ARCA_ACTOR", "")
	t.Setenv("CLAUDECODE", "")
	t.Setenv("CLAUDE_CODE_SESSION_ID", "")
	t.Setenv("CLAUDE_CODE_EXECPATH", "")
	t.Setenv("CURSOR_TRACE_ID", "")
	t.Setenv("AI_AGENT", "evil\x1b[2J\x1b[Hagent")
	w := approverWho()
	if strings.ContainsRune(w, 0x1b) {
		t.Fatalf("approverWho leaked ESC from $AI_AGENT: %q", w)
	}
	if !strings.Contains(w, "evil") || !strings.Contains(w, "agent") {
		t.Fatalf("approverWho dropped legitimate text: %q", w)
	}

	t.Setenv("AI_AGENT", "")
	t.Setenv("ARCA_ACTOR", "alice\x1b]0;pwned\x07")
	w = approverWho()
	if strings.ContainsRune(w, 0x1b) || strings.ContainsRune(w, 0x07) {
		t.Fatalf("approverWho leaked a control from $ARCA_ACTOR: %q", w)
	}
	if !strings.Contains(w, "alice") {
		t.Fatalf("approverWho dropped the actor: %q", w)
	}
}

// TestApprovePromptStripsEscapes is the end-to-end M1 check on approve(): a crafted `who` must
// not put an ESC (or BEL) on the operator's terminal. The name is already %q-escaped; who is not.
func TestApprovePromptStripsEscapes(t *testing.T) {
	sandbox(t)
	outPath := withTTYCapture(t, "y")
	if err := approve("SECRET", "who\x1b[2J\x1b[Hpwned\x07"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.ContainsRune(got, 0x1b) || strings.ContainsRune(got, 0x07) {
		t.Fatalf("approve prompt leaked a terminal control: %q", got)
	}
	if !strings.Contains(got, "pwned") || !strings.Contains(got, "SECRET") {
		t.Fatalf("approve prompt dropped legitimate text: %q", got)
	}
}

// TestRequireOperatorPromptStripsEscapes is the same check on the control-plane prompt: grant
// command/agent strings, secret names, and policy values all land in `question`.
func TestRequireOperatorPromptStripsEscapes(t *testing.T) {
	sandbox(t)
	outPath := withTTYCapture(t, "y")
	q := "Issue a grant for X (command terraform\x1b[2J\x1b[H apply)?"
	if err := requireOperator("grant", q); err != nil {
		t.Fatalf("requireOperator: %v", err)
	}
	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.ContainsRune(got, 0x1b) {
		t.Fatalf("requireOperator prompt leaked ESC: %q", got)
	}
	if !strings.Contains(got, "terraform") || !strings.Contains(got, "apply") {
		t.Fatalf("requireOperator prompt dropped legitimate text: %q", got)
	}
}

// TestSanitizeJSONBytes covers FU-6: raw DEL/C1 runes are stripped from marshaled JSON, while
// Go's own \u00XX escapes for C0 (already safe in the byte stream) are left intact.
func TestSanitizeJSONBytes(t *testing.T) {
	in := []byte("{\"description\": \"evil\x7f\u009b31mred\"}")
	out := string(sanitizeJSONBytes(in))
	if strings.ContainsRune(out, 0x7f) || strings.ContainsRune(out, 0x9b) {
		t.Fatalf("DEL/C1 survived sanitizeJSONBytes: %q", out)
	}
	if out != "{\"description\": \"evil31mred\"}" {
		t.Fatalf("unexpected result %q", out)
	}
	clean := []byte(`{"a":"plain \x1b escaped"}`)
	if got := sanitizeJSONBytes(clean); string(got) != string(clean) {
		t.Fatalf("clean JSON was altered: %q", got)
	}
}

// TestLsJSONSanitized proves the FU-6 gap end-to-end: DEL and C1 control characters planted in a
// description must not survive into `ls --json` output.
func TestLsJSONSanitized(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "S", "--desc", "bad\u009b31mdesc\x7f!")
	out := runArca(t, "", "ls", "--json")
	if strings.ContainsRune(out, 0x9b) || strings.ContainsRune(out, 0x7f) {
		t.Fatalf("ls --json leaked raw DEL/C1: %q", out)
	}
	if !strings.Contains(out, "bad31mdesc!") {
		t.Fatalf("description mangled beyond control-char removal: %q", out)
	}
}
