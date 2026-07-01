package main

import (
	"strings"
	"testing"
)

func TestStyledTable(t *testing.T) {
	out := styledTable([]string{"NAME", "OP"}, [][]string{{"TOKEN", "read"}, {"KEY", "exec"}})
	for _, want := range []string{"NAME", "OP", "TOKEN", "read", "KEY", "exec"} {
		if !strings.Contains(out, want) {
			t.Fatalf("styled table missing %q:\n%s", want, out)
		}
	}
	// A bordered table has box-drawing characters.
	if !strings.ContainsAny(out, "─│╭╰") {
		t.Fatalf("expected a bordered table, got:\n%s", out)
	}
}

func TestStyledOp(t *testing.T) {
	// Every op category renders to a non-empty string that still contains the op text.
	for _, op := range []string{"read", "set", "canary", "grant", "somethingelse"} {
		if got := styledOp(op); !strings.Contains(got, op) {
			t.Fatalf("styledOp(%q) = %q", op, got)
		}
	}
}
