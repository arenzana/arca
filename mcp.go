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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/secretname"
)

func newMCP() *cobra.Command {
	c := &cobra.Command{
		Use:   "mcp",
		Short: "Run an MCP server exposing arca to AI agents over stdio",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// Core dumps are already disabled for the whole binary in main(); the MCP server is
			// the sharpest case (it holds injected values for its entire lifetime and the agent
			// picks the command that can crash it), but it is not a special case.
			warnAgentExposure()
			s := server.NewMCPServer("arca", appVersion())
			registerMCPTools(s)
			// NewStdioServer+Listen rather than ServeStdio so stdin goes through
			// cappedLineReader: mcp-go's ReadString has no per-message bound, and
			// one multi-GB JSON-RPC line would grow the heap without limit.
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			defer cancel()
			return server.NewStdioServer(s).Listen(ctx, &cappedLineReader{r: os.Stdin}, os.Stdout)
		},
	}
	c.Flags().BoolVar(&mcpStrictFlag, "strict", false, "deny-by-default: agents only see secrets marked `arca agent allow` (recommended)")
	return c
}

// warnAgentExposure prints, to stderr (never the stdio JSON-RPC channel), what the agent can reach.
// Under --strict it confirms the deny-by-default scope; otherwise it warns loudly that EVERY secret
// is exposed and points at the fix — the warn half of the warn-then-flip rollout.
func warnAgentExposure() {
	if agentStrict() {
		n := 0
		if s, err := openStore(); err == nil {
			for _, name := range s.Names() {
				if s.Secrets[name].AgentExposed {
					n++
				}
			}
		}
		fmt.Fprintf(os.Stderr, "arca mcp: strict mode — agents can see %d explicitly-exposed secret(s) (manage with `arca agent`)\n", n)
		return
	}
	fmt.Fprintln(os.Stderr, "arca mcp: ⚠ NON-STRICT — every secret in the store is visible/usable to the connected agent.")
	fmt.Fprintln(os.Stderr, "          Run with --strict (or ARCA_AGENT_STRICT=1) and `arca agent allow NAME` to expose only what an agent needs.")
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
		mcp.WithDescription("Run a command with the named secrets injected as environment variables; returns the command's output and exit code. arca does not return the secret value itself, but the command you choose can print it — pick a command that uses the secret without echoing it. (--no-print only blocks reveal via get/inject/env, not a command you control.) Prefer this over read_secret."),
		mcp.WithString("command", mcp.Required(), mcp.Description("executable to run")),
		mcp.WithArray("args", mcp.Description("command arguments"), mcp.Items(map[string]any{"type": "string"})),
		mcp.WithArray("secrets", mcp.Required(), mcp.Description("names of the secrets to inject as env vars"), mcp.Items(map[string]any{"type": "string"}))),
		mcpRunWithSecrets)

	s.AddTool(mcp.NewTool("run_with_handle",
		mcp.WithDescription("Run a command using an opaque capability handle (hdl_…) instead of a secret name. The handle, issued out-of-band by the operator, injects a secret as an env var without revealing the secret's name or value; its command scope and expiry are enforced. Output is redacted. Use this when you were given a handle rather than a secret name."),
		mcp.WithString("handle", mcp.Required(), mcp.Description("the capability handle (hdl_…)")),
		mcp.WithString("command", mcp.Required(), mcp.Description("executable to run")),
		mcp.WithArray("args", mcp.Description("command arguments"), mcp.Items(map[string]any{"type": "string"}))),
		mcpRunWithHandle)

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

// jsonResult marshals v to pretty JSON as a tool text result. The bytes pass through
// sanitizeJSONBytes so metadata control characters that Go's encoder leaves raw (DEL/C1)
// can't ride a tool result into an agent's transcript or a terminal that renders it (FU-6).
func jsonResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(sanitizeJSONBytes(b))), nil
}

func mcpListSecrets(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s, err := openStore()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	// Deliberately NOT exposing per-secret last-read time to the agent: it advances when a handle is
	// used (the underlying exec bumps the real secret's last-read), which lets an agent holding only
	// an opaque hdl_… correlate a before/after list_secrets and recover which secret the handle wraps
	// — defeating the handle's name-hiding (SEC-09). The operator still sees full read history via the
	// CLI (`arca ls --reads`, `arca log`).
	type meta struct {
		Name            string   `json:"name"`
		Tags            []string `json:"tags,omitempty"`
		Description     string   `json:"description,omitempty"`
		NoPrint         bool     `json:"no_print,omitempty"`
		RequireApproval bool     `json:"require_approval,omitempty"`
		Disabled        bool     `json:"disabled,omitempty"`
		Updated         string   `json:"updated"`
		ExpiresAt       string   `json:"expires_at,omitempty"`
		Expired         bool     `json:"expired,omitempty"`
	}
	now := time.Now()
	out := []meta{}
	for _, name := range s.Names() {
		sec := s.Secrets[name]
		if agentDenied(sec.AgentExposed) { // strict mode: agents only see explicitly-exposed secrets
			continue
		}
		m := meta{
			Name: name, Tags: sec.Tags, Description: sec.Description,
			NoPrint: sec.NoPrint, RequireApproval: sec.RequireApproval,
			Disabled: sec.Disabled,
			Updated:  sec.UpdatedAt.UTC().Format(time.RFC3339),
		}
		if sec.ExpiresAt != nil {
			m.ExpiresAt = sec.ExpiresAt.UTC().Format(time.RFC3339)
			m.Expired = sec.Expired(now)
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
	// Strict mode must not distinguish "no such secret" from "not exposed": the pair of
	// messages is an existence oracle over the hidden namespace (an agent could dictionary-
	// probe names it isn't allowed to see). A nil secret counts as unexposed, so under
	// --strict both cases return the same generic refusal; non-strict keeps the precise
	// messages (nothing is hidden there anyway).
	if agentDenied(sec != nil && sec.AgentExposed) {
		return mcp.NewToolResultError(fmt.Sprintf(agentDenyHint, name)), nil
	}
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
	// See mcpShowSecret: nil counts as unexposed so strict mode has no existence oracle.
	if agentDenied(sec != nil && sec.AgentExposed) {
		return mcp.NewToolResultError(fmt.Sprintf(agentDenyHint, name)), nil
	}
	if sec == nil {
		return mcp.NewToolResultError("no such secret: " + name), nil
	}
	if sec.NoPrint {
		return mcp.NewToolResultError(name + " is marked --no-print; use run_with_secrets"), nil
	}
	if err := gate(sec, name, ""); err != nil {
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
	// The value rides into the client's JSON: invalid UTF-8 breaks the encoding.
	// Redirect binary values to run_with_secrets, which never serializes the value.
	if !utf8.Valid(plain) {
		return mcp.NewToolResultError(name + " is not valid UTF-8 and cannot ride the MCP JSON channel; use run_with_secrets (which never serializes the value)"), nil
	}
	if err := logUse("read", name, "mcp", sec); err != nil {
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
	cmdline := strings.TrimSpace(command + " " + strings.Join(argStrings(req, "args"), " "))
	env := scrubChildEnv(os.Environ())
	var pats []redactPattern
	for _, name := range dedupeNames(names) {
		sec := s.Secrets[name]
		// See mcpShowSecret: nil counts as unexposed so strict mode has no existence oracle.
		if agentDenied(sec != nil && sec.AgentExposed) {
			return mcp.NewToolResultError(fmt.Sprintf(agentDenyHint, name)), nil
		}
		if sec == nil {
			return mcp.NewToolResultError("no such secret: " + name), nil
		}
		// Defense in depth: refuse to inject a name that isn't a valid identifier (poisoned store).
		if err := secretname.Validate(name); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if err := gate(sec, name, cmdline); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		plain, err := crypto.Decrypt(sec.Value, ids)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		env = envWith(env, name, string(plain))
		pats = append(pats, redactPattern{name: name, value: plain})
	}
	// The redactability refusal runs BEFORE the use is recorded: a run that never
	// executes must not consume grant/rate budget (audit Info: MCP exec accounting).
	if n := tooShortToRedact(pats); n != "" {
		return mcp.NewToolResultError(fmt.Sprintf("refusing to run: %s is too short (<%d chars) to reliably redact from the command's output", n, minRedactLen)), nil
	}
	for _, p := range pats {
		if err := logUse("exec", p.name, command, s.Secrets[p.name]); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
	}
	out, exitCode, err := runRedacted(ctx, command, argStrings(req, "args"), env,
		buildRedactPatterns(pats, false, os.Stderr))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("run %s: %v", command, err)), nil
	}
	return jsonResult(map[string]any{"output": out, "exit_code": exitCode})
}

// runRedacted runs a command with env, capturing combined stdout+stderr with any secret value in
// pats replaced by its marker — so a command that prints an injected secret can't leak it into the
// model's response. stdout and stderr use separate redacting writers (each written by one os/exec
// goroutine) to avoid a data race, then are concatenated.
//
// The agent picks the command, so both of the resources it consumes are bounded here (see
// mcplimits.go): captured output is capped per stream, and the child gets a wall-clock deadline.
// Unlike `arca exec`, which streams to the operator's stdout, these tools have to hold the output
// in memory to return it — so without a cap the agent would control arca's heap.
func runRedacted(ctx context.Context, command string, args, env []string, pats []redactPattern) (string, int, error) {
	timeout := mcpExecTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...) //#nosec G204 -- the command is the agent's explicit request; running it with injected secrets is this tool's purpose
	cmd.Env = env
	// Killing the child does not necessarily free its output pipes: any grandchild that inherited
	// them keeps Wait blocked, which would defeat the deadline. WaitDelay bounds that wait.
	cmd.WaitDelay = mcpWaitDelay

	// The cap wraps the destination buffers, i.e. DOWNSTREAM of redaction. It must not sit between
	// the child and the redactWriter: that writer deliberately holds back up to maxLen-1 bytes so a
	// secret split across two writes still matches (redact.go), and cutting its input could emit a
	// partial secret at the boundary. Capping its output means only already-redacted bytes are ever
	// discarded.
	limit := mcpMaxOutput()
	var outB, errB bytes.Buffer
	capOut := &capWriter{dst: &outB, limit: limit}
	capErr := &capWriter{dst: &errB, limit: limit}
	rwOut := newRedactWriter(capOut, pats)
	rwErr := newRedactWriter(capErr, pats)
	cmd.Stdout, cmd.Stderr = rwOut, rwErr

	runErr := cmd.Run()
	// Flush before inspecting the outcome: the final scan of each held-back tail happens here, and
	// skipping it on the error paths would leave an unscanned tail unredacted.
	_ = rwOut.Flush()
	_ = rwErr.Flush()

	// A deadline kill surfaces as a signal death, which would otherwise be reported as the
	// ordinary exit code -1 and hide the fact that the command never finished. Cancellation is
	// reported separately: the caller's context going away (server shutdown) is not a timeout,
	// and saying so would send the agent chasing a limit that was never reached.
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "", 0, fmt.Errorf("command exceeded the %s limit and was killed (raise with %s, ceiling %s)",
			timeout, envMCPTimeout, maxMCPTimeout)
	case errors.Is(ctx.Err(), context.Canceled):
		return "", 0, fmt.Errorf("command was cancelled before it finished: %w", ctx.Err())
	}

	exitCode := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		exitCode = ee.ExitCode()
	} else if runErr != nil {
		return "", 0, runErr
	}
	return outB.String() + errB.String() + truncationNotice(limit, capOut, capErr), exitCode, nil
}

// mcpRunWithHandle runs a command using an opaque handle instead of a secret name: the agent never
// learns which secret it is, nor its value. The handle carries the scope (command glob, expiry) and
// the env-var name the value is injected under. Output is redacted like run_with_secrets.
func mcpRunWithHandle(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	id := argString(req, "handle")
	command := argString(req, "command")
	if id == "" || command == "" {
		return mcp.NewToolResultError("handle and command are required"), nil
	}
	args := argStrings(req, "args")
	cmdline := strings.TrimSpace(command + " " + strings.Join(args, " "))
	h, err := resolveHandle(id, cmdline)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	s, err := openStore()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	sec := s.Secrets[h.Secret]
	if sec == nil {
		return mcp.NewToolResultError("handle target no longer exists"), nil
	}
	// The handle is the authorization to *use* the secret, so grant/approval gating is bypassed;
	// but a canary trips, the kill switch and expiry are refused, and a rate limit still applies.
	// This mirrors gate() (main.go) in the same order, deliberately: the checks a handle skips are
	// the ones a handle replaces (grant, approval), and nothing else. See gate() before adding
	// anything here. A canary trip that cannot be recorded fails the call (D2) — this path bypasses
	// gate(), so it carries that fail-closed rule itself rather than inheriting it.
	if isCanary(h.Secret, sec) {
		if err := tripCanary(h.Secret); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
	}
	// A handle is minted before an incident; `arca disable` happens during one. Checking Disabled
	// only at mint time would therefore close nothing — the capability an operator is racing to
	// contain is always one that already exists. Refuse at use (SEC-13 kill switch).
	if sec.Disabled {
		return mcp.NewToolResultError("the secret behind this handle is disabled"), nil
	}
	if sec.Expired(time.Now()) {
		return mcp.NewToolResultError("the secret behind this handle has expired"), nil
	}
	if sec.RateLimit > 0 {
		if err := checkRateLimit(sec, h.Secret); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
	}
	ids, err := loadIDs()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	// Re-validate the env name at injection time (as exec/env/run_with_secrets do), so a tampered
	// handles.json can't inject a reserved name like LD_PRELOAD/PATH into the child (FU-2 / SEC-01).
	if err := secretname.Validate(h.EnvName); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	plain, err := crypto.Decrypt(sec.Value, ids)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	env := envWith(scrubChildEnv(os.Environ()), h.EnvName, string(plain))
	pats := []redactPattern{{name: h.EnvName, value: plain}}
	// The redactability refusal runs BEFORE the use is recorded: a run that never
	// executes must not consume rate budget (audit Info: MCP exec accounting).
	if n := tooShortToRedact(pats); n != "" {
		return mcp.NewToolResultError(fmt.Sprintf("refusing to run: the secret is too short (<%d chars) to reliably redact from the command's output", minRedactLen)), nil
	}
	if err := logUseNoGrant("exec", h.Secret, id, sec); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	out, exitCode, err := runRedacted(ctx, command, args, env,
		buildRedactPatterns(pats, false, os.Stderr))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("run %s: %v", command, err)), nil
	}
	return jsonResult(map[string]any{"output": out, "exit_code": exitCode})
}

func mcpAuditLog(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := 20
	if v, ok := req.GetArguments()["limit"].(float64); ok && v > 0 {
		// Clamp as a float BEFORE the int conversion: an out-of-range float→int conversion is
		// implementation-defined (math.MinInt64 on amd64), and SQLite treats LIMIT -1 as no
		// limit at all — audit_log {limit: 1e18} would otherwise dump the entire audit
		// database into one tool result.
		if v > 500 {
			v = 500
		}
		limit = int(v)
	}
	a, err := audit.Open(auditPath())
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer a.Close()
	name := argString(req, "name")
	// Strict mode: the audit log records secret names in cleartext for every op, so an
	// unfiltered audit_log lets an agent enumerate secrets it isn't exposed to — defeating
	// deny-by-default for metadata. Scope the tool to exposed secrets only, and answer a
	// name filter for a hidden (or nonexistent) secret with the same generic refusal as the
	// other tools so the filter can't be used as an existence oracle either.
	var exposed map[string]bool // nil in non-strict mode: no filtering (legacy behavior)
	if agentStrict() {
		s, err := openStore()
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		exposed = make(map[string]bool, len(s.Secrets))
		for n, sec := range s.Secrets {
			if sec.AgentExposed {
				exposed[n] = true
			}
		}
		if name != "" && !strings.HasPrefix(name, "hdl_") && !exposed[name] {
			return mcp.NewToolResultError(fmt.Sprintf(agentDenyHint, name)), nil
		}
	}
	evs, err := a.Recent(name, limit)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	// Don't reveal the real secret name behind a handle. A handle-issued exec records the secret's
	// name with the handle id (hdl_…) as caller, so an agent could otherwise call audit_log and read
	// back the hdl_… → name mapping that the handle exists to hide (SEC-09). Mask such events' name
	// to the handle id the agent already holds.
	views := make([]eventView, 0, len(evs))
	for _, e := range evs {
		name := e.Name
		if strings.HasPrefix(e.Caller, "hdl_") {
			name = e.Caller
		} else if exposed != nil && e.Name != "" && !exposed[e.Name] {
			continue // strict: never name a secret the agent isn't exposed to
		}
		views = append(views, eventView{
			Time: e.TS, Op: e.Op, Name: name, Agent: e.Agent,
			Version: e.Version, Session: e.Session, Actor: e.Actor, Caller: e.Caller,
		})
	}
	return jsonResult(views)
}
