package main

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// callTool builds a CallToolRequest with the given arguments.
func callTool(args map[string]any) mcp.CallToolRequest {
	var req mcp.CallToolRequest
	req.Params.Arguments = args
	return req
}

// call invokes an MCP tool handler and fails the test on a transport error.
func call(t *testing.T, h func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error), args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := h(context.Background(), callTool(args))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// text extracts the text payload of a tool result.
func text(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("empty tool result")
	}
	tc, ok := res.Content[0].(mcp.TextContent)
	if !ok {
		t.Fatalf("not text content: %T", res.Content[0])
	}
	return tc.Text
}

// TestMCPHandle covers the opaque-handle path: an agent runs a command via a handle without the
// secret's name or value, the command scope is enforced, and printed values are redacted.
func TestMCPHandle(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "topsecret", "set", "API") // 9 chars

	id := strings.TrimSpace(runArca(t, "", "handle", "create", "API", "--as", "TOK", "--command", "sh *", "--ttl", "1h"))
	if !strings.HasPrefix(id, "hdl_") {
		t.Fatalf("handle id = %q", id)
	}

	// The command runs with the value in $TOK; arca returns output, never the value.
	out := text(t, call(t, mcpRunWithHandle, map[string]any{
		"handle": id, "command": "sh", "args": []any{"-c", "echo len=${#TOK}"},
	}))
	if !strings.Contains(out, "len=9") || strings.Contains(out, "topsecret") {
		t.Fatalf("run_with_handle = %q", out)
	}

	// A command that prints the value has it redacted, not leaked.
	red := text(t, call(t, mcpRunWithHandle, map[string]any{
		"handle": id, "command": "sh", "args": []any{"-c", "echo secret is $TOK"},
	}))
	if strings.Contains(red, "topsecret") {
		t.Fatalf("run_with_handle leaked the value: %q", red)
	}
	if !strings.Contains(red, "«arca:TOK»") {
		t.Fatalf("expected redaction marker, got %q", red)
	}

	// A command outside the handle's scope, an unknown handle, and a missing handle are refused.
	if !call(t, mcpRunWithHandle, map[string]any{"handle": id, "command": "psql"}).IsError {
		t.Fatal("a command not matching the handle scope should error")
	}
	if !call(t, mcpRunWithHandle, map[string]any{"handle": "hdl_bogus", "command": "sh"}).IsError {
		t.Fatal("an unknown handle should error")
	}
	if !call(t, mcpRunWithHandle, map[string]any{"command": "sh"}).IsError {
		t.Fatal("a missing handle should error")
	}

	// A handle whose target secret was removed errors clearly.
	runArca(t, "v", "set", "GONE")
	gid := strings.TrimSpace(runArca(t, "", "handle", "create", "GONE", "--command", "sh *", "--ttl", "1h"))
	runArca(t, "", "rm", "GONE")
	if !call(t, mcpRunWithHandle, map[string]any{"handle": gid, "command": "sh", "args": []any{"-c", "true"}}).IsError {
		t.Fatal("a handle whose secret is gone should error")
	}

	// A rate-limited secret is throttled through a handle too.
	runArca(t, "v", "set", "RL", "--rate", "1/1h")
	rid := strings.TrimSpace(runArca(t, "", "handle", "create", "RL", "--as", "RLV", "--command", "sh *", "--ttl", "1h"))
	call(t, mcpRunWithHandle, map[string]any{"handle": rid, "command": "sh", "args": []any{"-c", "true"}}) // use 1
	if !call(t, mcpRunWithHandle, map[string]any{"handle": rid, "command": "sh", "args": []any{"-c", "true"}}).IsError {
		t.Fatal("a rate-limited secret should be throttled via a handle")
	}

	// A canary behind a handle still trips (and is allowed, as a decoy).
	runArca(t, "", "canary", "TRAP")
	cid := strings.TrimSpace(runArca(t, "", "handle", "create", "TRAP", "--as", "TRAPV", "--command", "sh *", "--ttl", "1h"))
	call(t, mcpRunWithHandle, map[string]any{"handle": cid, "command": "sh", "args": []any{"-c", "true"}})

	// A command that can't be executed surfaces a run error.
	bid := strings.TrimSpace(runArca(t, "", "handle", "create", "API", "--command", "nope*", "--ttl", "1h"))
	if !call(t, mcpRunWithHandle, map[string]any{"handle": bid, "command": "nope_missing_xyz"}).IsError {
		t.Fatal("an unrunnable command should surface an error")
	}
}

func TestMCPTools(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "topsecret", "set", "API", "--tag", "demo") // value is 9 chars
	runArca(t, "x", "set", "LOCKED", "--no-print")
	ctx := context.Background()
	_ = ctx

	// list_secrets: metadata only, never the value
	if out := text(t, call(t, mcpListSecrets, nil)); !strings.Contains(out, "API") || strings.Contains(out, "topsecret") {
		t.Fatalf("list_secrets leaked or missing: %q", out)
	}

	// show_secret: metadata; missing -> error
	if out := text(t, call(t, mcpShowSecret, map[string]any{"name": "API"})); !strings.Contains(out, "demo") {
		t.Fatalf("show_secret = %q", out)
	}
	if !call(t, mcpShowSecret, map[string]any{"name": "NOPE"}).IsError {
		t.Fatal("expected error for missing secret")
	}

	// run_with_secrets: injects, returns command output (never the value)
	out := text(t, call(t, mcpRunWithSecrets, map[string]any{
		"command": "sh", "args": []any{"-c", "echo len=${#API}"}, "secrets": []any{"API"},
	}))
	if !strings.Contains(out, "len=9") || strings.Contains(out, "topsecret") {
		t.Fatalf("run_with_secrets = %q", out)
	}
	if !call(t, mcpRunWithSecrets, map[string]any{"command": "true", "secrets": []any{"GHOST"}}).IsError {
		t.Fatal("expected error for missing secret")
	}
	if !call(t, mcpRunWithSecrets, map[string]any{"secrets": []any{"API"}}).IsError {
		t.Fatal("expected error for missing command")
	}
	if !call(t, mcpRunWithSecrets, map[string]any{"command": "true"}).IsError {
		t.Fatal("expected error for missing secrets")
	}

	// read_secret: reveals; refused for no-print; missing -> error
	if out := text(t, call(t, mcpReadSecret, map[string]any{"name": "API"})); out != "topsecret" {
		t.Fatalf("read_secret = %q", out)
	}
	if !call(t, mcpReadSecret, map[string]any{"name": "LOCKED"}).IsError {
		t.Fatal("expected read_secret to refuse a --no-print secret")
	}
	if !call(t, mcpReadSecret, map[string]any{"name": "NOPE"}).IsError {
		t.Fatal("expected read_secret error for missing secret")
	}

	// audit_log
	if out := text(t, call(t, mcpAuditLog, map[string]any{"name": "API", "limit": float64(5)})); !strings.Contains(out, "API") {
		t.Fatalf("audit_log = %q", out)
	}

	// registration wires every tool onto a server without panicking
	registerMCPTools(server.NewMCPServer("arca", "test"))
}

// TestMCPApprovalAndStore covers the policy/error paths: an approval-gated secret is denied,
// and tools error cleanly when there is no store.
func TestMCPApprovalAndStore(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "GATED", "--require-approval")

	t.Setenv("ARCA_APPROVAL", "deny")
	if !call(t, mcpReadSecret, map[string]any{"name": "GATED"}).IsError {
		t.Fatal("expected read_secret to be denied by approval")
	}
	if !call(t, mcpRunWithSecrets, map[string]any{"command": "true", "secrets": []any{"GATED"}}).IsError {
		t.Fatal("expected run_with_secrets to be denied by approval")
	}

	// With no store, the store-opening tools must error (not panic).
	t.Setenv("ARCA_STORE", t.TempDir()+"/missing.json")
	for _, r := range []*mcp.CallToolResult{
		call(t, mcpListSecrets, nil),
		call(t, mcpShowSecret, map[string]any{"name": "X"}),
		call(t, mcpReadSecret, map[string]any{"name": "X"}),
		call(t, mcpRunWithSecrets, map[string]any{"command": "true", "secrets": []any{"X"}}),
	} {
		if !r.IsError {
			t.Fatal("expected an error result without a store")
		}
	}
}
