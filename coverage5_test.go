package main

import (
	"strings"
	"testing"
)

// TestMCPRunWithSecretsExitPaths covers run_with_secrets' exit-handling branches: a non-zero
// exit surfaces exit_code (not a tool error), and a missing command is a tool error.
func TestMCPRunWithSecretsExitPaths(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "longvalue", "set", "API") // >= minRedactLen so run isn't refused for a short value

	r := call(t, mcpRunWithSecrets, map[string]any{
		"command": "sh", "args": []any{"-c", "exit 3"}, "secrets": []any{"API"},
	})
	if r.IsError {
		t.Fatal("a non-zero exit should be reported via exit_code, not a tool error")
	}
	if out := text(t, r); !strings.Contains(out, `"exit_code": 3`) {
		t.Fatalf("expected exit_code 3 in: %q", out)
	}

	if !call(t, mcpRunWithSecrets, map[string]any{
		"command": "no-such-cmd-xyzzy", "secrets": []any{"API"},
	}).IsError {
		t.Fatal("expected a missing command to produce a tool error")
	}
}
