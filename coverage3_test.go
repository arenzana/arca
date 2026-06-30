package main

import (
	"strings"
	"testing"
)

// TestInjectErrors covers inject's firstErr branches: unknown ref, --no-print ref, expired ref,
// and a successful resolution.
func TestInjectErrors(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "okval", "set", "OK")
	runArca(t, "v", "set", "LOCKED", "--no-print")
	runArca(t, "v", "set", "OLD", "--expires-at", "2020-01-01")
	for _, in := range []string{"x = arca://NOPE\n", "x = arca://LOCKED\n", "x = arca://OLD\n"} {
		if err := runArcaErr(in, "inject"); err == nil {
			t.Errorf("expected inject to fail for %q", strings.TrimSpace(in))
		}
	}
	if out := runArca(t, "x = arca://OK\n", "inject"); !strings.Contains(out, "okval") {
		t.Fatalf("inject ok = %q", out)
	}
}

// TestGetEnvFlags covers get's -n / --no-log flags and env's --no-export.
func TestGetEnvFlags(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "val", "set", "A")

	if out := runArca(t, "", "get", "A", "-n"); out != "val\n" {
		t.Fatalf("get -n = %q", out)
	}
	if out := runArca(t, "", "env", "--no-export"); !strings.Contains(out, "A=") || strings.Contains(out, "export ") {
		t.Fatalf("env --no-export = %q", out)
	}
	// --no-log on a fresh secret must leave no read event.
	runArca(t, "v2", "set", "B")
	runArca(t, "", "get", "B", "--no-log")
	if out := runArca(t, "", "log", "B"); strings.Contains(out, "read") {
		t.Fatalf("--no-log still recorded a read: %q", out)
	}
}

// TestMCPListSecretsLastRead covers the last-read enrichment branch in list_secrets.
func TestMCPListSecretsLastRead(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")
	runArca(t, "", "get", "API") // populate last_read
	if out := text(t, call(t, mcpListSecrets, nil)); !strings.Contains(out, "last_read") {
		t.Fatalf("expected last_read in list_secrets: %q", out)
	}
}

// TestLsReadsAndStaleWithin covers ls --reads and stale --within.
func TestLsReadsAndStaleWithin(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "A", "--rotate-after", "2999-01-01")
	runArca(t, "", "get", "A")
	if out := runArca(t, "", "ls", "--reads"); !strings.Contains(out, "A") {
		t.Fatalf("ls --reads = %q", out)
	}
	if out := runArca(t, "", "stale", "--within", "400000"); !strings.Contains(out, "A") {
		t.Fatalf("stale --within = %q", out)
	}
}
