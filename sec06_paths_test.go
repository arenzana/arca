package main

import (
	"strings"
	"testing"
)

// TestApprovalInjectPath complements TestApprovalGate: it exercises the interactive-approval success
// path on `inject` (a require-approval reference resolves only after a human confirms), and the
// refusal path with no terminal — the mocked TTY lets us drive both without a real console (SEC-06).
func TestApprovalInjectPath(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "secret", "set", "GATED", "--require-approval")

	// No terminal → inject can't release the gated reference.
	withNoTTY(t)
	if err := runArcaErr("x=arca://GATED\n", "inject"); err == nil {
		t.Fatal("inject of a require-approval secret should be refused without a terminal")
	}

	// A human answering "y" lets the reference resolve; "n" declines.
	withTTYResponse(t, "y")
	if out := runArca(t, "x=arca://GATED\n", "inject"); !strings.Contains(out, "secret") {
		t.Fatalf("approved inject did not resolve the reference: %q", out)
	}
	withTTYResponse(t, "n")
	if err := runArcaErr("x=arca://GATED\n", "inject"); err == nil {
		t.Fatal("declining at the terminal should leave the reference unresolved and fail")
	}
}
