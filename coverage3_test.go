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
	// --no-log on a fresh secret must leave no read event for a non-agent caller at a terminal
	// (the human anchor is the TTY, not env detection — SEC-06).
	for _, k := range []string{"CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CURSOR_TRACE_ID", "AI_AGENT"} {
		t.Setenv(k, "")
	}
	withTTYResponse(t, "")
	runArca(t, "v2", "set", "B")
	runArca(t, "", "get", "B", "--no-log")
	if out := runArca(t, "", "log", "B"); strings.Contains(out, "read") {
		t.Fatalf("--no-log still recorded a read: %q", out)
	}
	// Without a controlling terminal --no-log is ignored even for an agent-clean env: an agent
	// can scrub its markers, but it can't conjure a terminal.
	withNoTTY(t)
	runArca(t, "v2b", "set", "B2")
	runArca(t, "", "get", "B2", "--no-log")
	if out := runArca(t, "", "log", "B2"); !strings.Contains(out, "read") {
		t.Fatalf("--no-log without a terminal should still record a read: %q", out)
	}
	// And an agent cannot suppress its own read record, terminal or not.
	withTTYResponse(t, "")
	t.Setenv("AI_AGENT", "claude-code")
	runArca(t, "v3", "set", "C")
	runArca(t, "", "get", "C", "--no-log")
	if out := runArca(t, "", "log", "C"); !strings.Contains(out, "read") {
		t.Fatalf("agent --no-log should still record a read: %q", out)
	}
}

// TestMCPListSecretsNoLastRead covers FU-1 (SEC-09 completion): the MCP list_secrets tool must NOT
// expose per-secret last-read time, because it advances when a handle is used and would let an agent
// correlate a before/after list_secrets to recover which secret an opaque handle wraps.
func TestMCPListSecretsNoLastRead(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")
	runArca(t, "", "get", "API") // would populate last_read
	if out := text(t, call(t, mcpListSecrets, nil)); strings.Contains(out, "last_read") {
		t.Fatalf("list_secrets must not expose last_read to an agent (handle deanonymization): %q", out)
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
