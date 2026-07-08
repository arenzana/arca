package main

import (
	"strings"
	"testing"
)

// TestMCPRunRefusesShortSecret covers FU-7: the MCP run tools must refuse when an injected value is
// too short to reliably redact from the command's output — on the CLI a skipped value is warned to
// the operator, but over MCP the warning is invisible and the output flows into the model context.
func TestMCPRunRefusesShortSecret(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "ab", "set", "SHORT") // 2 chars, < minRedactLen
	if !call(t, mcpRunWithSecrets, map[string]any{"command": "true", "secrets": []any{"SHORT"}}).IsError {
		t.Fatal("run_with_secrets must refuse a value too short to redact")
	}
}

// TestNoLogDoesNotEvadeRateLimit covers SEC-12: --no-log must not let a human bypass a rate limit,
// because the audit log is what the limit counts. A non-rate-limited secret still honors --no-log.
func TestNoLogDoesNotEvadeRateLimit(t *testing.T) {
	sandbox(t)
	withTTYResponse(t, "") // --no-log is honored only at a terminal (SEC-06)
	runArca(t, "", "init")
	runArca(t, "longvalue", "set", "R", "--rate", "1/1h")
	runArca(t, "", "get", "R", "--no-log")                         // use 1 — recorded despite --no-log
	if err := runArcaErr("", "get", "R", "--no-log"); err == nil { // use 2 — must be refused
		t.Fatal("--no-log let a rate-limited secret exceed its limit")
	}
	runArca(t, "v2", "set", "N")
	runArca(t, "", "get", "N", "--no-log")
	if out := runArca(t, "", "log", "N"); strings.Contains(out, "read") {
		t.Fatalf("--no-log recorded a read on a non-rate-limited secret: %q", out)
	}
}
