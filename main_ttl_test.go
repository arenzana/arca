package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseTTL(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"30m", 30 * time.Minute, true},
		{"12h", 12 * time.Hour, true},
		{"7d", 7 * 24 * time.Hour, true},
		{"2w", 14 * 24 * time.Hour, true},
		{"1.5d", 36 * time.Hour, true},
		{"500ms", 500 * time.Millisecond, true},
		{"", 0, false},
		{"abc", 0, false},
		{"5x", 0, false},
		{"d", 0, false},
	}
	for _, c := range cases {
		got, err := parseTTL(c.in)
		switch {
		case c.ok && (err != nil || got != c.want):
			t.Errorf("parseTTL(%q) = %v, %v; want %v", c.in, got, err, c.want)
		case !c.ok && err == nil:
			t.Errorf("parseTTL(%q) expected an error, got %v", c.in, got)
		}
	}
}

// TestTTLLifecycle drives the full ephemeral-secret behavior through the CLI: a live TTL is
// usable; an expired secret is refused on every access path; show/stale surface it; and
// rotate --ttl revives it.
func TestTTLLifecycle(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	// --ttl creates a future expiry: the secret is usable.
	runArca(t, "live", "set", "EPH", "--ttl", "1h")
	if out := runArca(t, "", "get", "EPH"); out != "live" {
		t.Fatalf("get EPH = %q", out)
	}

	// --expires-at in the past: every read/use path refuses it.
	runArca(t, "dead", "set", "OLD", "--expires-at", "2020-01-01")
	for _, args := range [][]string{
		{"get", "OLD"},
		{"exec", "--only", "OLD", "--", "true"},
	} {
		if err := runArcaErr("", args...); err == nil {
			t.Fatalf("expected %v to fail on an expired secret", args)
		}
	}
	if err := runArcaErr("x = \"arca://OLD\"\n", "inject"); err == nil {
		t.Fatal("expected inject to refuse an expired secret")
	}

	// show surfaces the expiry + EXPIRED state; stale lists it.
	if out := runArca(t, "", "show", "OLD"); !strings.Contains(out, "EXPIRED") {
		t.Fatalf("show OLD = %q", out)
	}
	if out := runArca(t, "", "stale"); !strings.Contains(out, "OLD") || !strings.Contains(out, "EXPIRED") {
		t.Fatalf("stale = %q", out)
	}

	// rotate --ttl refreshes expiry: the expired secret becomes usable again.
	runArca(t, "fresh", "rotate", "OLD", "--ttl", "1h")
	if out := runArca(t, "", "get", "OLD"); out != "fresh" {
		t.Fatalf("after rotate --ttl get OLD = %q", out)
	}

	// flag validation
	if err := runArcaErr("v", "set", "BAD", "--ttl", "1h", "--expires-at", "2030-01-01"); err == nil {
		t.Fatal("expected error when both --ttl and --expires-at are given")
	}
	if err := runArcaErr("v", "set", "BAD", "--ttl", "0s"); err == nil {
		t.Fatal("expected error for non-positive ttl")
	}
	if err := runArcaErr("v", "set", "BAD", "--expires-at", "nonsense"); err == nil {
		t.Fatal("expected error for bad expires-at")
	}
}

// TestMCPExpiry confirms the MCP surface honors expiry: list marks it, read/run refuse it.
func TestMCPExpiry(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "dead", "set", "OLD", "--expires-at", "2020-01-01")

	if out := text(t, call(t, mcpListSecrets, nil)); !strings.Contains(out, `"expired": true`) {
		t.Fatalf("list_secrets did not mark expiry: %q", out)
	}
	if !call(t, mcpReadSecret, map[string]any{"name": "OLD"}).IsError {
		t.Fatal("expected read_secret to refuse an expired secret")
	}
	if !call(t, mcpRunWithSecrets, map[string]any{"command": "true", "secrets": []any{"OLD"}}).IsError {
		t.Fatal("expected run_with_secrets to refuse an expired secret")
	}
}
