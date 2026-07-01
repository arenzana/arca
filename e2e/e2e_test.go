//go:build e2e

// Package e2e exercises the built arca binary as a black box: it compiles arca, runs it as a
// subprocess through the full CLI lifecycle and the MCP stdio server, and asserts real behavior
// (exit codes, output, encryption at rest, policies). This is what proves a release actually
// works. Run with:  go test -tags e2e ./e2e/...
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// bin is the path to the freshly built arca binary, set by TestMain.
var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "arca-e2e")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	bin = filepath.Join(dir, "arca")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = ".." // module root (parent of e2e/)
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.Stderr.WriteString("e2e: build failed: " + err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// box is a sandboxed arca invocation environment (its own store/audit/identity).
type box struct {
	env []string
	dir string
}

func sandbox(t *testing.T) box {
	d := t.TempDir()
	return box{dir: d, env: []string{
		"ARCA_STORE=" + filepath.Join(d, "store.json"),
		"ARCA_AUDIT=" + filepath.Join(d, "audit.db"),
		"ARCA_IDENTITY=" + filepath.Join(d, "id.txt"),
		"XDG_STATE_HOME=" + filepath.Join(d, "state"), // keep grants.json + session keys out of $HOME
	}}
}

// dedupeEnv collapses KEY=value pairs so a later occurrence overrides an earlier one — this
// lets b.env and `extra` reliably override an ambient variable (e.g. clearing CLAUDECODE).
func dedupeEnv(pairs []string) []string {
	idx := map[string]int{}
	out := []string{}
	for _, kv := range pairs {
		k, _, _ := strings.Cut(kv, "=")
		if i, ok := idx[k]; ok {
			out[i] = kv
		} else {
			idx[k] = len(out)
			out = append(out, kv)
		}
	}
	return out
}

func (b box) runEnv(t *testing.T, extra []string, stdin string, args ...string) (out, errOut string, code int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = dedupeEnv(append(append(os.Environ(), b.env...), extra...))
	cmd.Stdin = strings.NewReader(stdin)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("arca %v: %v\nstderr: %s", args, err, e.String())
	}
	return o.String(), e.String(), code
}

func (b box) run(t *testing.T, stdin string, args ...string) (string, string, int) {
	return b.runEnv(t, nil, stdin, args...)
}

func (b box) must(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	out, errOut, code := b.run(t, stdin, args...)
	if code != 0 {
		t.Fatalf("arca %v exited %d\nstderr: %s", args, code, errOut)
	}
	return out
}

func needsSh(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
}

func TestVersion(t *testing.T) {
	if out := sandbox(t).must(t, "", "--version"); !strings.Contains(out, "arca version") {
		t.Fatalf("version = %q", out)
	}
}

func TestLifecycle(t *testing.T) {
	needsSh(t)
	b := sandbox(t)
	b.must(t, "", "init")
	b.must(t, "s3cr3t-value", "set", "API", "--tag", "demo", "--desc", "the api token", "--rotate-after", "2020-01-01")

	// get returns the value; the store holds age ciphertext, not the plaintext.
	if out := b.must(t, "", "get", "API"); out != "s3cr3t-value" {
		t.Fatalf("get = %q", out)
	}
	store, _ := os.ReadFile(filepath.Join(b.dir, "store.json"))
	if strings.Contains(string(store), "s3cr3t-value") {
		t.Fatal("plaintext value found in store.json")
	}
	if !strings.Contains(string(store), "BEGIN AGE ENCRYPTED FILE") {
		t.Fatal("store does not contain age ciphertext")
	}

	if out := b.must(t, "", "ls"); !strings.Contains(out, "API") {
		t.Fatalf("ls = %q", out)
	}
	if out := b.must(t, "", "show", "API"); !strings.Contains(out, "the api token") {
		t.Fatalf("show = %q", out)
	}
	if out := b.must(t, "", "stale"); !strings.Contains(out, "API") {
		t.Fatalf("stale = %q", out)
	}

	// rotate keeps it usable
	b.must(t, "rotated-value", "rotate", "API")
	if out := b.must(t, "", "get", "API"); out != "rotated-value" {
		t.Fatalf("after rotate get = %q", out)
	}

	// exec injects into a subprocess (value used, never printed by arca)
	if out := b.must(t, "", "exec", "--only", "API", "--", "sh", "-c", "echo len=${#API}"); !strings.Contains(out, "len=13") {
		t.Fatalf("exec = %q", out)
	}
	// inject resolves arca:// references
	if out := b.must(t, "tok = \"arca://API\"\n", "inject"); !strings.Contains(out, `tok = "rotated-value"`) {
		t.Fatalf("inject = %q", out)
	}
	// log shows the history
	if out := b.must(t, "", "log", "API"); !strings.Contains(out, "API") || !strings.Contains(out, "exec") {
		t.Fatalf("log = %q", out)
	}
	// rm
	b.must(t, "", "rm", "API")
	if _, _, code := b.run(t, "", "get", "API"); code == 0 {
		t.Fatal("expected get to fail after rm")
	}
}

func TestPolicies(t *testing.T) {
	needsSh(t)
	b := sandbox(t)
	b.must(t, "", "init")

	// --no-print: get refuses, exec works
	b.must(t, "hidden", "set", "LOCKED", "--no-print")
	if _, _, code := b.run(t, "", "get", "LOCKED"); code == 0 {
		t.Fatal("expected get to refuse a --no-print secret")
	}
	if out := b.must(t, "", "exec", "--only", "LOCKED", "--", "sh", "-c", "echo len=${#LOCKED}"); !strings.Contains(out, "len=6") {
		t.Fatalf("exec no-print = %q", out)
	}

	// --require-approval: denied with no terminal.
	b.must(t, "v", "set", "GATED", "--require-approval")
	if _, _, code := b.run(t, "", "get", "GATED"); code == 0 {
		t.Fatal("expected get to be denied (no terminal to approve)")
	}
	// ARCA_APPROVAL=allow works only for a non-agent caller (agent env cleared)...
	nonAgent := []string{"ARCA_APPROVAL=allow", "CLAUDECODE=", "CLAUDE_CODE_SESSION_ID=", "CURSOR_TRACE_ID=", "AI_AGENT="}
	if out, _, code := b.runEnv(t, nonAgent, "", "get", "GATED"); code != 0 || out != "v" {
		t.Fatalf("approved get (non-agent) = %q code=%d", out, code)
	}
	// ...but an AI agent cannot self-approve via the inherited env var.
	if _, _, code := b.runEnv(t, []string{"ARCA_APPROVAL=allow", "AI_AGENT=claude-code"}, "", "get", "GATED"); code == 0 {
		t.Fatal("expected an agent to be refused self-approval")
	}
}

func TestFailClosedAudit(t *testing.T) {
	b := sandbox(t)
	b.must(t, "", "init")
	b.must(t, "plain", "set", "PLAIN")

	// corrupt the audit db
	if err := os.WriteFile(filepath.Join(b.dir, "audit.db"), []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	// default is fail-closed: get aborts when it can't audit
	if _, _, code := b.run(t, "", "get", "PLAIN"); code == 0 {
		t.Fatal("expected fail-closed get to abort with a broken audit log")
	}
	// opt out → best-effort for a non-agent caller: get proceeds
	bestEffort := []string{"ARCA_STRICT_AUDIT=0", "CLAUDECODE=", "CLAUDE_CODE_SESSION_ID=", "CURSOR_TRACE_ID=", "AI_AGENT="}
	if out, _, code := b.runEnv(t, bestEffort, "", "get", "PLAIN"); code != 0 || out != "plain" {
		t.Fatalf("best-effort get = %q code=%d", out, code)
	}
	// an agent stays fail-closed even with ARCA_STRICT_AUDIT=0
	if _, _, code := b.runEnv(t, []string{"ARCA_STRICT_AUDIT=0", "AI_AGENT=claude-code"}, "", "get", "PLAIN"); code == 0 {
		t.Fatal("expected an agent to remain fail-closed despite ARCA_STRICT_AUDIT=0")
	}
}

func TestTTL(t *testing.T) {
	needsSh(t)
	b := sandbox(t)
	b.must(t, "", "init")

	// a live TTL is usable
	b.must(t, "live", "set", "EPH", "--ttl", "1h")
	if out := b.must(t, "", "get", "EPH"); out != "live" {
		t.Fatalf("get EPH = %q", out)
	}

	// an expired secret is refused on get and exec
	b.must(t, "dead", "set", "OLD", "--expires-at", "2020-01-01")
	if _, _, code := b.run(t, "", "get", "OLD"); code == 0 {
		t.Fatal("expected get on an expired secret to fail")
	}
	if _, _, code := b.run(t, "", "exec", "--only", "OLD", "--", "true"); code == 0 {
		t.Fatal("expected exec on an expired secret to fail")
	}
	if out := b.must(t, "", "stale"); !strings.Contains(out, "OLD") || !strings.Contains(out, "EXPIRED") {
		t.Fatalf("stale = %q", out)
	}

	// rotate --ttl revives it
	b.must(t, "fresh", "rotate", "OLD", "--ttl", "1h")
	if out := b.must(t, "", "get", "OLD"); out != "fresh" {
		t.Fatalf("after rotate --ttl get OLD = %q", out)
	}
}

func TestJSONAndRecipients(t *testing.T) {
	b := sandbox(t)
	b.must(t, "", "init")
	b.must(t, "v", "set", "API", "--tag", "demo")

	var ls []map[string]any
	if err := json.Unmarshal([]byte(b.must(t, "", "ls", "--json")), &ls); err != nil {
		t.Fatalf("ls --json: %v", err)
	}
	if len(ls) != 1 || ls[0]["name"] != "API" {
		t.Fatalf("ls --json = %v", ls)
	}

	if out := b.must(t, "", "recipients"); strings.TrimSpace(out) == "" {
		t.Fatal("recipients listing was empty")
	}
	if _, _, code := b.run(t, "", "recipients", "add", "not-a-key"); code == 0 {
		t.Fatal("expected an invalid recipient to be rejected")
	}
}

// TestConcurrentSet launches many `arca set` processes at once; the store lock must serialize
// them so every secret lands (without locking, the read-modify-write would lose updates).
func TestConcurrentSet(t *testing.T) {
	b := sandbox(t)
	b.must(t, "", "init")

	const n = 8
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := exec.Command(bin, "set", fmt.Sprintf("K%d", i))
			cmd.Env = append(os.Environ(), b.env...)
			cmd.Stdin = strings.NewReader("v")
			errs <- cmd.Run()
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatalf("a concurrent set failed (lock timeout too short?): %v", e)
		}
	}

	out := b.must(t, "", "ls")
	for i := 0; i < n; i++ {
		if !strings.Contains(out, fmt.Sprintf("K%d", i)) {
			t.Errorf("lost update: K%d missing from the store", i)
		}
	}
}

func TestMCPServer(t *testing.T) {
	needsSh(t)
	b := sandbox(t)
	b.must(t, "", "init")
	b.must(t, "topsecret", "set", "API") // 9 chars

	cmd := exec.Command(bin, "mcp")
	cmd.Env = append(os.Environ(), b.env...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_secrets","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run_with_secrets","arguments":{"command":"sh","args":["-c","echo len=${#API}"],"secrets":["API"]}}}`,
	} {
		io.WriteString(stdin, m+"\n")
	}
	stdin.Close()
	_ = cmd.Wait()

	var sawTools, sawList, sawRun bool
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var resp struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
		}
		if json.Unmarshal([]byte(line), &resp) != nil {
			continue
		}
		s := string(resp.Result)
		switch resp.ID {
		case 2:
			sawTools = strings.Contains(s, "run_with_secrets") && strings.Contains(s, "list_secrets")
		case 3:
			sawList = strings.Contains(s, "API") && !strings.Contains(s, "topsecret")
		case 4:
			sawRun = strings.Contains(s, "len=9") && !strings.Contains(s, "topsecret")
		}
	}
	if !sawTools {
		t.Fatalf("tools/list missing expected tools:\n%s", out.String())
	}
	if !sawList {
		t.Fatal("list_secrets wrong or leaked a value")
	}
	if !sawRun {
		t.Fatal("run_with_secrets wrong or leaked a value")
	}
}

// TestHandles drives the opaque-handle flow through the real binary: a handle is minted for a
// secret, then an agent runs a command via run_with_handle over MCP using only the handle — never
// the secret's name or value.
func TestHandles(t *testing.T) {
	needsSh(t)
	b := sandbox(t)
	b.must(t, "", "init")
	b.must(t, "topsecret", "set", "API") // 9 chars

	id := strings.TrimSpace(b.must(t, "", "handle", "create", "API", "--as", "TOK", "--command", "sh *", "--ttl", "1h"))
	if !strings.HasPrefix(id, "hdl_") {
		t.Fatalf("handle id = %q", id)
	}
	if out := b.must(t, "", "handle", "ls"); !strings.Contains(out, id) {
		t.Fatalf("handle ls = %q", out)
	}

	cmd := exec.Command(bin, "mcp")
	cmd.Env = append(os.Environ(), b.env...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_with_handle","arguments":{"handle":"` + id + `","command":"sh","args":["-c","echo len=${#TOK}"]}}}`,
	} {
		io.WriteString(stdin, m+"\n")
	}
	stdin.Close()
	_ = cmd.Wait()

	var sawRun bool
	for _, line := range strings.Split(out.String(), "\n") {
		var resp struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
		}
		if strings.TrimSpace(line) == "" || json.Unmarshal([]byte(line), &resp) != nil {
			continue
		}
		if resp.ID == 2 {
			s := string(resp.Result)
			sawRun = strings.Contains(s, "len=9") && !strings.Contains(s, "topsecret")
		}
	}
	if !sawRun {
		t.Fatalf("run_with_handle over MCP failed or leaked: %s", out.String())
	}
}

// TestMCPMalformed feeds the real MCP server a garbage line and an unknown-tool call, then a valid
// request — the server must survive the junk (not crash) and still answer the later valid call.
func TestMCPMalformed(t *testing.T) {
	b := sandbox(t)
	b.must(t, "", "init")
	b.must(t, "topsecret", "set", "API")

	cmd := exec.Command(bin, "mcp")
	cmd.Env = append(os.Environ(), b.env...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`this is not json at all {{{`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"no_such_tool","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"show_secret","arguments":{"name":"API"}}}`,
	} {
		io.WriteString(stdin, m+"\n")
	}
	stdin.Close()
	_ = cmd.Wait()

	var answered bool
	for _, line := range strings.Split(out.String(), "\n") {
		var resp struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
		}
		if strings.TrimSpace(line) == "" || json.Unmarshal([]byte(line), &resp) != nil {
			continue
		}
		if resp.ID == 3 && strings.Contains(string(resp.Result), "API") {
			answered = true
		}
	}
	if !answered {
		t.Fatalf("MCP server did not survive malformed input and answer a later valid request:\n%s", out.String())
	}
}

// TestRateLimit drives the per-secret rate cap through the real binary: N uses succeed within the
// window and the next is refused.
func TestRateLimit(t *testing.T) {
	b := sandbox(t)
	b.must(t, "", "init")
	b.must(t, "topsecret", "set", "API", "--rate", "2/1h")
	b.must(t, "", "get", "API")
	b.must(t, "", "get", "API")
	if _, _, code := b.run(t, "", "get", "API"); code == 0 {
		t.Fatal("the third use in the window should be rate-limited")
	}
}

// TestGrants drives the just-in-time grant flow through the real binary: a require-grant secret is
// unusable until a matching, command-scoped, bounded grant is issued, and the grant-authorized
// uses land in the signed audit log (which still verifies).
func TestGrants(t *testing.T) {
	needsSh(t)
	b := sandbox(t)
	b.must(t, "", "init")
	b.must(t, "deployval", "set", "DEPLOY", "--require-grant")

	// No grant: exec and get both fail.
	if _, _, code := b.run(t, "", "exec", "--only", "DEPLOY", "--", "true"); code == 0 {
		t.Fatal("exec without a grant should fail")
	}
	if _, _, code := b.run(t, "", "get", "DEPLOY"); code == 0 {
		t.Fatal("get of a require-grant secret should fail")
	}

	// Grant 'true*' for two uses; a non-matching command is refused, matching is allowed twice.
	b.must(t, "", "grant", "DEPLOY", "--command", "true*", "--uses", "2", "--ttl", "15m")
	if _, _, code := b.run(t, "", "exec", "--only", "DEPLOY", "--", "sh", "-c", "echo x"); code == 0 {
		t.Fatal("a command not matching the grant pattern should fail")
	}
	b.must(t, "", "exec", "--only", "DEPLOY", "--", "true")
	b.must(t, "", "exec", "--only", "DEPLOY", "--", "true")
	if _, _, code := b.run(t, "", "exec", "--only", "DEPLOY", "--", "true"); code == 0 {
		t.Fatal("the third use should be refused (grant exhausted)")
	}

	if out := b.must(t, "", "grants"); !strings.Contains(out, "DEPLOY") {
		t.Fatalf("grants list = %q, want DEPLOY", out)
	}

	// The grant-authorized exec events are in the tamper-evident log, which still verifies.
	if _, errOut, code := b.run(t, "", "log", "--verify"); code != 0 || !strings.Contains(errOut, "OK") {
		t.Fatalf("log --verify: code=%d stderr=%q", code, errOut)
	}

	b.must(t, "", "revoke", "DEPLOY")
	if _, _, code := b.run(t, "", "revoke", "DEPLOY"); code == 0 {
		t.Fatal("revoking a non-existent grant should fail")
	}
}
