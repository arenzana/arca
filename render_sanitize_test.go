package main

import (
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/store"
)

// TestShowSanitizesName covers FU-3: `show` must sanitize the secret name it prints, so a poisoned
// store key containing a terminal escape can't inject into the operator's terminal.
func TestShowSanitizesName(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "GOOD")
	s, err := store.Load(storePath())
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
