// MCP server: exposes arca to AI agents as audited, policy-respecting tools over stdio.
//
// The design goal is "use without revealing": an agent runs commands with secrets injected
// (run_with_secrets) or inspects metadata (list/show) without the raw value ever entering the
// model's context. read_secret is the explicit, policy-gated, audited escape hatch for when a
// value genuinely must be returned. Every tool honours --no-print, --require-approval, and the
// fail-closed audit, just like the CLI.
//
// NOTE: handlers must never write to stdout (that's the JSON-RPC channel) — they only return
// results. All output goes through the returned CallToolResult.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/crypto"
)

func newMCP() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run an MCP server exposing arca to AI agents over stdio",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s := server.NewMCPServer("arca", version)
			registerMCPTools(s)
			return server.ServeStdio(s)
		},
	}
}

// registerMCPTools wires arca's capabilities onto an MCP server.
func registerMCPTools(s *server.MCPServer) {
	s.AddTool(mcp.NewTool("list_secrets",
		mcp.WithDescription("List secret names and metadata (tags, description, policy, timestamps, last read). Never returns values.")),
		mcpListSecrets)

	s.AddTool(mcp.NewTool("show_secret",
		mcp.WithDescription("Show one secret's metadata (never the value)."),
		mcp.WithString("name", mcp.Required(), mcp.Description("secret name"))),
		mcpShowSecret)

	s.AddTool(mcp.NewTool("run_with_secrets",
		mcp.WithDescription("Run a command with the named secrets injected as environment variables; returns the command's output and exit code. Secret VALUES are never returned — prefer this over read_secret."),
		mcp.WithString("command", mcp.Required(), mcp.Description("executable to run")),
		mcp.WithArray("args", mcp.Description("command arguments"), mcp.Items(map[string]any{"type": "string"})),
		mcp.WithArray("secrets", mcp.Required(), mcp.Description("names of the secrets to inject as env vars"), mcp.Items(map[string]any{"type": "string"}))),
		mcpRunWithSecrets)

	s.AddTool(mcp.NewTool("read_secret",
		mcp.WithDescription("Reveal a secret's value into the response. Refused for --no-print secrets, gated by human approval for --require-approval, and always audited. Use only when the value must enter the model context; otherwise prefer run_with_secrets."),
		mcp.WithString("name", mcp.Required(), mcp.Description("secret name"))),
		mcpReadSecret)

	s.AddTool(mcp.NewTool("audit_log",
		mcp.WithDescription("Recent access events, optionally filtered to one secret."),
		mcp.WithString("name", mcp.Description("filter to a single secret")),
		mcp.WithNumber("limit", mcp.Description("max events (default 20)"))),
		mcpAuditLog)
}

// argString / argStrings read tool arguments defensively from the request map.
func argString(req mcp.CallToolRequest, key string) string {
	if v, ok := req.GetArguments()[key].(string); ok {
		return v
	}
	return ""
}

func argStrings(req mcp.CallToolRequest, key string) []string {
	raw, ok := req.GetArguments()[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// jsonResult marshals v to pretty JSON as a tool text result.
func jsonResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(b)), nil
}

func mcpListSecrets(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s, err := openStore()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	a, _ := audit.Open(auditPath())
	if a != nil {
		defer a.Close()
	}
	type meta struct {
		Name            string   `json:"name"`
		Tags            []string `json:"tags,omitempty"`
		Description     string   `json:"description,omitempty"`
		NoPrint         bool     `json:"no_print,omitempty"`
		RequireApproval bool     `json:"require_approval,omitempty"`
		Updated         string   `json:"updated"`
		LastRead        string   `json:"last_read,omitempty"`
	}
	out := []meta{}
	for _, name := range s.Names() {
		sec := s.Secrets[name]
		m := meta{
			Name: name, Tags: sec.Tags, Description: sec.Description,
			NoPrint: sec.NoPrint, RequireApproval: sec.RequireApproval,
			Updated: sec.UpdatedAt.UTC().Format(time.RFC3339),
		}
		if a != nil {
			if lr, _, _ := a.LastRead(name); !lr.IsZero() {
				m.LastRead = lr.UTC().Format(time.RFC3339)
			}
		}
		out = append(out, m)
	}
	return jsonResult(out)
}

func mcpShowSecret(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := argString(req, "name")
	s, err := openStore()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	sec := s.Secrets[name]
	if sec == nil {
		return mcp.NewToolResultError("no such secret: " + name), nil
	}
	return jsonResult(map[string]any{
		"name": name, "tags": sec.Tags, "description": sec.Description,
		"no_print": sec.NoPrint, "require_approval": sec.RequireApproval,
		"created": sec.CreatedAt.UTC().Format(time.RFC3339),
		"updated": sec.UpdatedAt.UTC().Format(time.RFC3339),
	})
}

func mcpReadSecret(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name := argString(req, "name")
	s, err := openStore()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	sec := s.Secrets[name]
	if sec == nil {
		return mcp.NewToolResultError("no such secret: " + name), nil
	}
	if sec.NoPrint {
		return mcp.NewToolResultError(name + " is marked --no-print; use run_with_secrets"), nil
	}
	if err := gate(sec, name); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	ids, err := loadIDs()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	plain, err := crypto.Decrypt(sec.Value, ids)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := logAudit("read", name, "mcp"); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(plain)), nil
}

func mcpRunWithSecrets(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	command := argString(req, "command")
	if command == "" {
		return mcp.NewToolResultError("command is required"), nil
	}
	names := argStrings(req, "secrets")
	if len(names) == 0 {
		return mcp.NewToolResultError("secrets is required (name the secrets to inject)"), nil
	}
	s, err := openStore()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	ids, err := loadIDs()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	env := os.Environ()
	for _, name := range names {
		sec := s.Secrets[name]
		if sec == nil {
			return mcp.NewToolResultError("no such secret: " + name), nil
		}
		if err := gate(sec, name); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		plain, err := crypto.Decrypt(sec.Value, ids)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		env = append(env, name+"="+string(plain))
		if err := logAudit("exec", name, command); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
	}
	cmd := exec.CommandContext(ctx, command, argStrings(req, "args")...)
	cmd.Env = env
	out, runErr := cmd.CombinedOutput()
	exitCode := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		exitCode = ee.ExitCode()
	} else if runErr != nil {
		return mcp.NewToolResultError(fmt.Sprintf("run %s: %v", command, runErr)), nil
	}
	return jsonResult(map[string]any{"output": string(out), "exit_code": exitCode})
}

func mcpAuditLog(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := 20
	if v, ok := req.GetArguments()["limit"].(float64); ok && v > 0 {
		limit = int(v)
	}
	a, err := audit.Open(auditPath())
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer a.Close()
	evs, err := a.Recent(argString(req, "name"), limit)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return jsonResult(evs)
}
