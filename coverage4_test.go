package main

import (
	"strings"
	"testing"
)

// TestRotateAndShowFull covers rotate's --rotate-after/--expires-at success branches and every
// metadata-rendering branch of `show` (tags, description, rotate-after, expiry, policies, meta).
func TestRotateAndShowFull(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "A")
	runArca(t, "v2", "rotate", "A", "--rotate-after", "2999-01-01")
	runArca(t, "v3", "rotate", "A", "--expires-at", "2999-01-01")

	runArca(t, "v", "set", "B",
		"--tag", "t1", "--desc", "d", "--rotate-after", "2999-01-01",
		"--ttl", "1h", "--meta", "k=v", "--no-print", "--require-approval")
	out := runArca(t, "", "show", "B")
	for _, want := range []string{"t1", "d", "rotate after", "expires", "meta.k", "no-print", "requires approval"} {
		if !strings.Contains(out, want) {
			t.Errorf("show missing %q in: %q", want, out)
		}
	}
}

// TestRmMissing covers rm's not-found branch.
func TestRmMissing(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := runArcaErr("", "rm", "NOPE"); err == nil {
		t.Fatal("expected rm of a missing secret to fail")
	}
}
