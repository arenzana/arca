package main

import (
	"strings"
	"testing"
)

func TestAgentStrict(t *testing.T) {
	t.Setenv("ARCA_AGENT_STRICT", "")
	mcpStrictFlag = false
	if agentStrict() {
		t.Fatal("strict should be off by default")
	}
	if agentDenied(false) {
		t.Fatal("non-strict must never deny")
	}
	t.Setenv("ARCA_AGENT_STRICT", "1")
	if !agentStrict() {
		t.Fatal("ARCA_AGENT_STRICT=1 should enable strict")
	}
	if !agentDenied(false) {
		t.Fatal("strict must deny an unexposed secret")
	}
	if agentDenied(true) {
		t.Fatal("strict must allow an exposed secret")
	}
	t.Setenv("ARCA_AGENT_STRICT", "")
	mcpStrictFlag = true
	if !agentStrict() {
		t.Fatal("--strict flag should enable strict")
	}
	mcpStrictFlag = false
}

func TestAgentAllowDenyLs(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "PUBLIC_API")
	runArca(t, "v2", "set", "B2_MASTER_KEY")

	if out := runArca(t, "", "agent", "ls"); strings.TrimSpace(out) != "" {
		t.Fatalf("nothing should be exposed initially, got %q", out)
	}
	runArca(t, "", "agent", "allow", "PUBLIC_API")
	if out := runArca(t, "", "agent", "ls"); !strings.Contains(out, "PUBLIC_API") || strings.Contains(out, "B2_MASTER_KEY") {
		t.Fatalf("agent ls should show only PUBLIC_API, got %q", out)
	}
	runArca(t, "", "agent", "deny", "PUBLIC_API")
	if out := runArca(t, "", "agent", "ls"); strings.Contains(out, "PUBLIC_API") {
		t.Fatalf("PUBLIC_API should be denied again, got %q", out)
	}
	if err := runArcaErr("", "agent", "allow", "NOPE"); err == nil {
		t.Fatal("allow on a missing secret should error")
	}
}

// TestAgentStrictGatesMCP is the load-bearing test: under strict mode the MCP tools must hide and
// refuse unexposed secrets, and serve only the ones explicitly allowed.
func TestAgentStrictGatesMCP(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "publicval", "set", "PUBLIC_API")
	runArca(t, "supersecret", "set", "B2_MASTER_KEY")
	runArca(t, "", "agent", "allow", "PUBLIC_API")

	t.Setenv("ARCA_AGENT_STRICT", "1")

	// read_secret: allowed one returns its value; denied one is refused with the hint.
	if got := text(t, call(t, mcpReadSecret, map[string]any{"name": "PUBLIC_API"})); got != "publicval" {
		t.Fatalf("allowed read_secret = %q, want publicval", got)
	}
	res := call(t, mcpReadSecret, map[string]any{"name": "B2_MASTER_KEY"})
	if !res.IsError || !strings.Contains(text(t, res), "not exposed to agents") {
		t.Fatalf("denied read_secret should error with the hint, got %q (isErr=%v)", text(t, res), res.IsError)
	}
	// show_secret is gated too.
	if !call(t, mcpShowSecret, map[string]any{"name": "B2_MASTER_KEY"}).IsError {
		t.Fatal("show_secret on an unexposed secret should be denied in strict mode")
	}
	// run_with_secrets refuses to inject an unexposed secret.
	if !call(t, mcpRunWithSecrets, map[string]any{"command": "true", "secrets": []any{"B2_MASTER_KEY"}}).IsError {
		t.Fatal("run_with_secrets on an unexposed secret should be denied in strict mode")
	}
	// list_secrets hides the unexposed one.
	list := text(t, call(t, mcpListSecrets, map[string]any{}))
	if !strings.Contains(list, "PUBLIC_API") || strings.Contains(list, "B2_MASTER_KEY") {
		t.Fatalf("list_secrets should show only exposed secrets, got:\n%s", list)
	}

	// Non-strict: everything is visible again (back-compat).
	t.Setenv("ARCA_AGENT_STRICT", "")
	list = text(t, call(t, mcpListSecrets, map[string]any{}))
	if !strings.Contains(list, "B2_MASTER_KEY") {
		t.Fatalf("non-strict list_secrets should show all secrets, got:\n%s", list)
	}
	if got := text(t, call(t, mcpReadSecret, map[string]any{"name": "B2_MASTER_KEY"})); got != "supersecret" {
		t.Fatalf("non-strict read_secret should work, got %q", got)
	}
}
