package main

import (
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/store"
)

// execArca runs the root command with args, feeding stdin and capturing stdout.
//
// The commands read os.Stdin directly (readValue, inject) and write output to os.Stdout (get,
// inject, env, log, --json), so we temporarily swap those process globals around a single
// Execute(). We back them with temp files rather than os.Pipe: a file has no reader/writer race,
// which keeps the harness deterministic on Windows (where a pipe whose peer closes early fails
// the write with "the pipe is being closed").
//
// Both globals are restored before returning, so tests must not run in parallel.
func execArca(stdin string, args ...string) (string, error) {
	inF, err := os.CreateTemp("", "arca-in-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(inF.Name())
	if _, err := inF.WriteString(stdin); err != nil {
		inF.Close()
		return "", err
	}
	if _, err := inF.Seek(0, 0); err != nil {
		inF.Close()
		return "", err
	}
	outF, err := os.CreateTemp("", "arca-out-*")
	if err != nil {
		inF.Close()
		return "", err
	}
	defer os.Remove(outF.Name())

	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inF, outF
	defer func() {
		os.Stdin, os.Stdout = oldIn, oldOut
		inF.Close()
		outF.Close()
	}()

	root := newRoot()
	root.SetArgs(args)
	root.SetOut(io.Discard) // silence cobra's own usage/output; we only care about os.Stdout
	root.SetErr(io.Discard)
	err = root.Execute()

	_ = outF.Sync()
	_, _ = outF.Seek(0, 0)
	b, _ := io.ReadAll(outF)
	return string(b), err
}

// runArca is execArca for the happy path: it fails the test on any command error.
func runArca(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	out, err := execArca(stdin, args...)
	if err != nil {
		t.Fatalf("arca %s: %v", strings.Join(args, " "), err)
	}
	return out
}

// runArcaErr is for the cases where an error is the expected outcome (e.g. get on --no-print).
func runArcaErr(stdin string, args ...string) error {
	_, err := execArca(stdin, args...)
	return err
}

// sandbox points every arca path at a temp dir and forces a freshly generated identity, so a
// test never touches the developer's real store, audit db, or sops key.
func sandbox(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("SOPS_AGE_KEY_FILE", "") // ignore any real sops key → init generates one
	t.Setenv("ARCA_STORE", filepath.Join(dir, "store.json"))
	t.Setenv("ARCA_AUDIT", filepath.Join(dir, "audit.db"))
	t.Setenv("ARCA_IDENTITY", filepath.Join(dir, "id.txt"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state")) // keep session signing keys out of $HOME
	return dir
}

// TestEndToEnd walks the primary lifecycle through the real command tree: init → set → get →
// rotate → get, asserting along the way that the stored value is encrypted (not cleartext),
// that rotate preserves created_at, and that the audit log captured the rotation and the actor.
func TestEndToEnd(t *testing.T) {
	dir := sandbox(t)
	t.Setenv("ARCA_ACTOR", "test-agent")

	runArca(t, "", "init")
	runArca(t, "hunter2", "set", "API_TOKEN", "--tag", "demo", "--desc", "d")

	if out := runArca(t, "", "get", "API_TOKEN"); out != "hunter2" {
		t.Fatalf("get returned %q, want hunter2", out)
	}

	s, err := store.Load(filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	sec := s.Secrets["API_TOKEN"]
	if sec == nil {
		t.Fatal("secret not stored")
	}
	if strings.Contains(sec.Value, "hunter2") {
		t.Fatal("value is stored in cleartext!")
	}
	created := sec.CreatedAt

	// rotate keeps created_at, replaces the value.
	runArca(t, "newsecret", "rotate", "API_TOKEN")
	s2, _ := store.Load(filepath.Join(dir, "store.json"))
	if !s2.Secrets["API_TOKEN"].CreatedAt.Equal(created) {
		t.Fatal("rotate changed created_at")
	}
	if out := runArca(t, "", "get", "API_TOKEN"); out != "newsecret" {
		t.Fatalf("after rotate, get = %q", out)
	}

	// The audit log must show a rotation and the explicit actor.
	a, _ := audit.Open(filepath.Join(dir, "audit.db"))
	defer a.Close()
	evs, _ := a.Recent("API_TOKEN", 50)
	var sawRotate, sawActor bool
	for _, e := range evs {
		if e.Op == "rotate" {
			sawRotate = true
		}
		if e.Actor == "test-agent" {
			sawActor = true
		}
	}
	if !sawRotate {
		t.Fatal("rotate was not audited")
	}
	if !sawActor {
		t.Fatal("actor was not recorded")
	}
}

// TestStale checks the rotation-due filter: a past rotate_after is listed, a far-future one is
// not.
func TestStale(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "OLD", "--rotate-after", "2000-01-01")
	runArca(t, "v", "set", "NEW", "--rotate-after", "2999-01-01")

	out := runArca(t, "", "stale")
	if !strings.Contains(out, "OLD") || strings.Contains(out, "NEW") {
		t.Fatalf("stale output = %q (want OLD present, NEW absent)", out)
	}
}

// TestDetectIdentityClaude verifies Claude Code is recognized from its env vars, with the
// version parsed out of the exec path. (t.Setenv overrides whatever the test host has set.)
func TestDetectIdentityClaude(t *testing.T) {
	t.Setenv("ARCA_ACTOR", "")
	t.Setenv("AI_AGENT", "")
	t.Setenv("CURSOR_TRACE_ID", "")
	t.Setenv("CLAUDECODE", "1")
	t.Setenv("CLAUDE_CODE_SESSION_ID", "sess-123")
	t.Setenv("CLAUDE_CODE_EXECPATH", "/opt/homebrew/Caskroom/claude-code/2.1.181/claude")
	id := detectIdentity()
	if id.Agent != "claude-code" || id.Session != "sess-123" || id.Version != "2.1.181" {
		t.Fatalf("got %+v", id)
	}
}

// TestActorFallback verifies the audit actor falls back to the OS user when $ARCA_ACTOR is unset,
// while an explicit $ARCA_ACTOR still wins.
func TestActorFallback(t *testing.T) {
	if osUser() == "" {
		t.Skip("no OS user resolvable in this environment")
	}
	for _, e := range []string{"ARCA_ACTOR", "CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CURSOR_TRACE_ID", "AI_AGENT"} {
		t.Setenv(e, "")
	}
	if id := detectIdentity(); id.Actor == "" || id.Actor != osUser() {
		t.Fatalf("actor = %q, want the OS user %q", id.Actor, osUser())
	}
	t.Setenv("ARCA_ACTOR", "explicit")
	if detectIdentity().Actor != "explicit" {
		t.Fatal("an explicit $ARCA_ACTOR should take precedence over the OS user")
	}
}

// TestPsCommand exercises both branches of the ps-based parent lookup (it runs on Linux too, so
// the CI coverage platform covers what /proc otherwise shadows).
func TestPsCommand(t *testing.T) {
	_ = psCommand(os.Getpid()) // success path (ps present on Linux/macOS); value is host-dependent
	if got := psCommand(-999999); got != "" {
		t.Fatalf("psCommand(bogus pid) = %q, want empty", got)
	}
}

// TestPolicyInteraction checks that per-secret policies compose in the right gate order: a secret
// that is both a canary and rate-limited trips the canary on *every* access attempt (even the one
// the rate limiter then refuses), and the throttle is recorded.
func TestPolicyInteraction(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")
	runArca(t, "decoyvalue", "set", "BAIT", "--canary", "--rate", "1/1h")

	runArca(t, "", "get", "BAIT") // use 1: canary trips, allowed
	if err := runArcaErr("", "get", "BAIT"); err == nil {
		t.Fatal("the second use should be rate-limited")
	}

	a, _ := audit.Open(filepath.Join(dir, "audit.db"))
	_, canaryN, _ := a.LastOp("BAIT", "canary")
	_, rlN, _ := a.LastOp("BAIT", "ratelimit")
	a.Close()
	if canaryN < 2 {
		t.Fatalf("canary should trip on both attempts (incl. the throttled one), got %d", canaryN)
	}
	if rlN == 0 {
		t.Fatal("the rate-limit refusal should be recorded")
	}
}

// TestRm covers removing a secret and the missing-secret error.
func TestRm(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "X")
	runArca(t, "", "rm", "X")
	if err := runArcaErr("", "get", "X"); err == nil {
		t.Fatal("a removed secret should be gone")
	}
	if err := runArcaErr("", "rm", "NOPE"); err == nil {
		t.Fatal("removing a missing secret should error")
	}
}

// TestStrictAudit covers the fail-closed default and the agent-can't-weaken-it invariant.
func TestStrictAudit(t *testing.T) {
	for _, e := range []string{"CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CURSOR_TRACE_ID", "AI_AGENT"} {
		t.Setenv(e, "")
	}
	t.Setenv("ARCA_STRICT_AUDIT", "") // default is strict
	if !strictAudit() {
		t.Fatal("auditing should be strict by default")
	}
	t.Setenv("ARCA_STRICT_AUDIT", "0") // a non-agent may opt into best-effort
	if strictAudit() {
		t.Fatal("a non-agent should be able to relax strict auditing")
	}
	// A detected agent cannot weaken it, even with the lax override set.
	t.Setenv("CLAUDECODE", "1")
	t.Setenv("CLAUDE_CODE_SESSION_ID", "s")
	if !strictAudit() {
		t.Fatal("a detected agent must not be able to disable fail-closed auditing")
	}
}

// TestDetectIdentityGeneric verifies the fallback parser for the generic AI_AGENT convention
// (name_version_agent), used for agents arca doesn't special-case.
func TestDetectIdentityGeneric(t *testing.T) {
	t.Setenv("ARCA_ACTOR", "")
	t.Setenv("CLAUDECODE", "")
	t.Setenv("CLAUDE_CODE_SESSION_ID", "")
	t.Setenv("CURSOR_TRACE_ID", "")
	t.Setenv("AI_AGENT", "myagent_1-2-3_agent")
	id := detectIdentity()
	if id.Agent != "myagent" || id.Version != "1.2.3" {
		t.Fatalf("got %+v", id)
	}
}

// TestNoPrintAndInject covers the AI-safety policy surface:
//   - inject resolves a normal arca:// reference;
//   - a --no-print secret is refused by both get and inject (it must not reach stdout);
//   - but exec can still inject it into a subprocess (here we only echo its length, never the
//     value — "secretval" is 9 chars).
func TestNoPrintAndInject(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "plainval", "set", "NORMAL")
	runArca(t, "secretval", "set", "LOCKED", "--no-print")

	if out := runArca(t, "endpoint=arca://NORMAL\n", "inject"); !strings.Contains(out, "endpoint=plainval") {
		t.Fatalf("inject = %q", out)
	}
	if err := runArcaErr("", "get", "LOCKED"); err == nil {
		t.Fatal("expected get on --no-print to fail")
	}
	if err := runArcaErr("x=arca://LOCKED", "inject"); err == nil {
		t.Fatal("expected inject of --no-print to fail")
	}
	if out := runArca(t, "", "exec", "--only", "LOCKED", "--", "sh", "-c", "echo got=${#LOCKED}"); !strings.Contains(out, "got=9") {
		t.Fatalf("exec no-print = %q", out)
	}
}

// TestExecRedaction covers output redaction: a command that prints an injected secret has the
// value replaced (default = the secret's name; --reveal = a partial mask), the catch is audited,
// and --redact off restores the raw value.
func TestExecRedaction(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")
	runArca(t, "hunter2secret", "set", "PASSWORD") // 13 chars, above the scan floor

	// Default: captured stdout (a temp file in the harness) is redacted to the name.
	out := runArca(t, "", "exec", "--only", "PASSWORD", "--", "sh", "-c", "echo using hunter2secret now")
	if strings.Contains(out, "hunter2secret") {
		t.Fatalf("secret leaked into output: %q", out)
	}
	if !strings.Contains(out, "«arca:PASSWORD»") {
		t.Fatalf("expected redaction marker, got %q", out)
	}

	// The catch is recorded as a potential leak.
	a, _ := audit.Open(filepath.Join(dir, "audit.db"))
	evs, _ := a.Recent("PASSWORD", 50)
	a.Close()
	var sawRedact bool
	for _, e := range evs {
		if e.Op == "redact" {
			sawRedact = true
		}
	}
	if !sawRedact {
		t.Fatal("a redacted secret was not audited")
	}

	// --reveal shows a partial mask but still never the whole value.
	rev := runArca(t, "", "exec", "--reveal", "--only", "PASSWORD", "--", "sh", "-c", "echo using hunter2secret now")
	if strings.Contains(rev, "hunter2secret") {
		t.Fatalf("--reveal leaked the full value: %q", rev)
	}
	if !strings.Contains(rev, "hu") || !strings.Contains(rev, "ret") || !strings.Contains(rev, "*") {
		t.Fatalf("--reveal output = %q, want a partial mask", rev)
	}

	// --redact off passes the value straight through.
	off := runArca(t, "", "exec", "--redact", "off", "--only", "PASSWORD", "--", "sh", "-c", "echo using hunter2secret now")
	if !strings.Contains(off, "hunter2secret") {
		t.Fatalf("--redact off should not redact, got %q", off)
	}

	// An invalid mode is rejected.
	if err := runArcaErr("", "exec", "--redact", "bogus", "--only", "PASSWORD", "--", "true"); err == nil {
		t.Fatal("expected an invalid --redact value to error")
	}
}

// TestLogVerify drives the integrity check through the CLI: after real operations the signed,
// chained log verifies clean; tampering with the DB makes `log --verify` fail.
func TestLogVerify(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "get", "A")
	runArca(t, "v2", "set", "B")

	// A healthy log verifies (verify writes its summary to stderr and returns nil).
	if err := runArcaErr("", "log", "--verify"); err != nil {
		t.Fatalf("verify on a clean log should pass: %v", err)
	}

	// Editing an event out of band must be detected.
	db, err := sql.Open("sqlite", filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE events SET name='TAMPERED' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if err := runArcaErr("", "log", "--verify"); err == nil {
		t.Fatal("verify should fail on a tampered log")
	}
}

// TestCanaryValue checks the decoy templates produce realistically-shaped tokens.
func TestCanaryValue(t *testing.T) {
	for tmpl, prefix := range map[string]string{"stripe": "sk_live_", "github": "ghp_", "aws": "AKIA", "slack": "xoxb-"} {
		v, err := canaryValue(tmpl)
		if err != nil {
			t.Fatalf("%s: %v", tmpl, err)
		}
		if !strings.HasPrefix(v, prefix) {
			t.Fatalf("%s -> %q, want prefix %q", tmpl, v, prefix)
		}
	}
	if v, _ := canaryValue("generic"); len(v) < 20 {
		t.Fatalf("generic decoy too short: %q", v)
	}
	if _, err := canaryValue("bogus"); err == nil {
		t.Fatal("an unknown template should error")
	}
}

// TestCanary covers the tripwire: planting a decoy, using it (via get and via exec) records a
// distinct signed "canary" audit event, and `canary --list` reflects the trip.
func TestCanary(t *testing.T) {
	dir := sandbox(t)
	// Run as a detected agent so a trip is attributed to the agent/session (the real case).
	t.Setenv("CLAUDECODE", "1")
	t.Setenv("CLAUDE_CODE_SESSION_ID", "sess-test")
	runArca(t, "", "init")

	// Early validation: an invalid name and an unknown template are rejected.
	if err := runArcaErr("", "canary", "bad-name"); err == nil {
		t.Fatal("an invalid canary name should error")
	}
	if err := runArcaErr("", "canary", "OK", "--template", "bogus"); err == nil {
		t.Fatal("an unknown template should error")
	}

	// Plant a github-shaped decoy; reading it returns the realistic value AND trips.
	runArca(t, "", "canary", "TRAP", "--template", "github")
	if out := runArca(t, "", "get", "TRAP"); !strings.HasPrefix(out, "ghp_") {
		t.Fatalf("decoy value = %q, want a ghp_ prefix", out)
	}

	a, _ := audit.Open(filepath.Join(dir, "audit.db"))
	evs, _ := a.Recent("TRAP", 50)
	a.Close()
	var sawCanary bool
	for _, e := range evs {
		if e.Op == "canary" {
			sawCanary = true
		}
	}
	if !sawCanary {
		t.Fatal("using a canary was not recorded as a trip")
	}

	if list := runArca(t, "", "canary", "--list"); !strings.Contains(list, "TRAP") || !strings.Contains(list, "TRIPPED") {
		t.Fatalf("canary --list = %q, want TRAP shown as TRIPPED", list)
	}

	// show (metadata, no value) doesn't trip; env (which uses every secret) does.
	runArca(t, "", "show", "TRAP")
	runArca(t, "", "env")

	// set --canary marks an ordinary secret; using it via exec trips too.
	runArca(t, "plainvalue", "set", "TRAP2", "--canary")
	runArca(t, "", "exec", "--only", "TRAP2", "--", "true")
	a2, _ := audit.Open(filepath.Join(dir, "audit.db"))
	_, n, _ := a2.LastOp("TRAP2", "canary")
	a2.Close()
	if n == 0 {
		t.Fatal("exec of a canary did not trip")
	}
}

// TestCanaryUnidentified trips a canary with no agent/actor in the environment, exercising the
// "unidentified caller" attribution path.
func TestCanaryUnidentified(t *testing.T) {
	dir := sandbox(t)
	for _, e := range []string{"CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CURSOR_TRACE_ID", "AI_AGENT", "ARCA_ACTOR"} {
		t.Setenv(e, "")
	}
	runArca(t, "", "init")
	runArca(t, "decoyval", "set", "BAIT", "--canary")
	runArca(t, "", "get", "BAIT")

	a, _ := audit.Open(filepath.Join(dir, "audit.db"))
	_, n, _ := a.LastOp("BAIT", "canary")
	a.Close()
	if n == 0 {
		t.Fatal("canary did not trip for an unidentified caller")
	}
}

// TestCanaryList covers the listing: a non-canary is excluded, and an untripped canary shows as
// "armed" (the no-trips branch).
func TestCanaryList(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "ORDINARY") // not a canary
	runArca(t, "", "canary", "FRESH")  // a canary, never used

	out := runArca(t, "", "canary", "--list")
	if strings.Contains(out, "ORDINARY") {
		t.Fatalf("a non-canary should not be listed: %q", out)
	}
	if !strings.Contains(out, "FRESH") || !strings.Contains(out, "armed") {
		t.Fatalf("an untripped canary should show as armed: %q", out)
	}
}

// TestParseRate covers the --rate N/DURATION parser.
func TestParseRate(t *testing.T) {
	if n, w, err := parseRate("10/2h"); err != nil || n != 10 || w != "2h" {
		t.Fatalf("parseRate(10/2h) = %d,%q,%v", n, w, err)
	}
	for _, bad := range []string{"", "10", "abc/1h", "0/1h", "-1/1h", "5/notaduration"} {
		if _, _, err := parseRate(bad); err == nil {
			t.Fatalf("parseRate(%q) should error", bad)
		}
	}
}

// TestRateLimit covers the per-secret rate cap: N uses are allowed within the window, the next is
// refused and recorded, and clearing the rate lifts the cap.
func TestRateLimit(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")
	runArca(t, "topsecret", "set", "API", "--rate", "2/1h")

	if out := runArca(t, "", "show", "API"); !strings.Contains(out, "rate-limited (2 per 1h)") {
		t.Fatalf("show should surface the rate policy, got %q", out)
	}

	runArca(t, "", "get", "API")
	runArca(t, "", "get", "API")
	if err := runArcaErr("", "get", "API"); err == nil {
		t.Fatal("the third use in the window should be rate-limited")
	}

	a, _ := audit.Open(filepath.Join(dir, "audit.db"))
	_, n, _ := a.LastOp("API", "ratelimit")
	a.Close()
	if n == 0 {
		t.Fatal("a throttled access was not recorded")
	}

	// Clearing the rate lifts the cap.
	runArca(t, "topsecret", "set", "API", "--rate", "")
	runArca(t, "", "get", "API")
}

// TestRateLimitDefaultWindow covers a secret whose RateWindow is unset (e.g. hand-edited), which
// defaults to 1h in enforcement and display.
func TestRateLimitDefaultWindow(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")

	s, err := store.Load(filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.Secrets["API"].RateLimit = 1
	s.Secrets["API"].RateWindow = "" // triggers the 1h default
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	if out := runArca(t, "", "show", "API"); !strings.Contains(out, "per 1h") {
		t.Fatalf("show should default the window to 1h, got %q", out)
	}
	runArca(t, "", "get", "API") // use 1
	if err := runArcaErr("", "get", "API"); err == nil {
		t.Fatal("the second use should be throttled under the default window")
	}
}

// TestRateLimitBadWindow covers the parse-failure fallback: an unparseable window still enforces
// (falling back to 1h) rather than erroring the access.
func TestRateLimitBadWindow(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")
	s, err := store.Load(filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.Secrets["API"].RateLimit = 1
	s.Secrets["API"].RateWindow = "bogus"
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "get", "API") // use 1
	if err := runArcaErr("", "get", "API"); err == nil {
		t.Fatal("a bad window should still throttle (fallback to 1h), not error open")
	}
}

// TestGrants covers the JIT/command-scoped grant lifecycle: a require-grant secret is unusable
// without a matching grant, a grant authorizes a command pattern for a bounded number of uses,
// and revoke removes it.
func TestGrants(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "sekret", "set", "DEPLOY", "--require-grant")

	// No grant: exec is denied, and get is refused (no command to authorize against).
	if err := runArcaErr("", "exec", "--only", "DEPLOY", "--", "true"); err == nil {
		t.Fatal("exec without a grant should be denied")
	}
	if err := runArcaErr("", "get", "DEPLOY"); err == nil {
		t.Fatal("get of a require-grant secret should be denied")
	}

	// Grant 'true*' for 2 uses. A non-matching command is denied; matching is allowed twice.
	runArca(t, "", "grant", "DEPLOY", "--command", "true*", "--uses", "2", "--ttl", "15m")
	if err := runArcaErr("", "exec", "--only", "DEPLOY", "--", "sh", "-c", "echo x"); err == nil {
		t.Fatal("a command not matching the grant pattern should be denied")
	}
	runArca(t, "", "exec", "--only", "DEPLOY", "--", "true")
	runArca(t, "", "exec", "--only", "DEPLOY", "--", "true")
	if err := runArcaErr("", "exec", "--only", "DEPLOY", "--", "true"); err == nil {
		t.Fatal("the third use should be refused (grant exhausted)")
	}

	if out := runArca(t, "", "grants"); !strings.Contains(out, "DEPLOY") {
		t.Fatalf("grants list = %q, want DEPLOY", out)
	}

	runArca(t, "", "revoke", "DEPLOY")
	if err := runArcaErr("", "revoke", "DEPLOY"); err == nil {
		t.Fatal("revoking a non-existent grant should error")
	}
}

// TestGrantExpiryAndAgent covers the time and agent constraints by manipulating the grant store
// directly (package-internal helpers).
func TestGrantExpiryAndAgent(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "sekret", "set", "DEPLOY", "--require-grant")
	runArca(t, "", "grant", "DEPLOY", "--ttl", "1h")

	// Backdate the grant: an expired grant is refused.
	grants, err := loadGrants()
	if err != nil {
		t.Fatal(err)
	}
	g := grants["DEPLOY"]
	g.ExpiresAt = time.Now().Add(-time.Hour)
	grants["DEPLOY"] = g
	if err := saveGrants(grants); err != nil {
		t.Fatal(err)
	}
	if err := runArcaErr("", "exec", "--only", "DEPLOY", "--", "true"); err == nil {
		t.Fatal("an expired grant should be refused")
	}
	if out := runArca(t, "", "grants"); !strings.Contains(out, "expired") {
		t.Fatalf("grants list should mark the backdated grant expired: %q", out)
	}

	// Re-grant restricted to a different agent; the (non-agent) caller is refused.
	runArca(t, "", "grant", "DEPLOY", "--ttl", "1h", "--agent", "some-other-agent")
	if err := runArcaErr("", "exec", "--only", "DEPLOY", "--", "true"); err == nil {
		t.Fatal("a grant restricted to another agent should be refused")
	}
}

// TestGrantValidation covers grant input validation, the advisory notes, and the listing of
// unlimited / any-command grants.
func TestGrantValidation(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	runArca(t, "", "grants") // empty: "no active grants"

	if err := runArcaErr("", "grant", "bad-name", "--ttl", "1h"); err == nil {
		t.Fatal("an invalid name should error")
	}
	if err := runArcaErr("", "grant", "X"); err == nil {
		t.Fatal("a grant without --ttl should error")
	}
	if err := runArcaErr("", "grant", "X", "--ttl", "nonsense"); err == nil {
		t.Fatal("a bad --ttl should error")
	}

	// Granting a not-yet-existing secret, and a plain (non-require-grant) secret, both succeed
	// with an advisory note. The plain grant is unlimited (uses=0) and any-command.
	runArca(t, "", "grant", "GHOST", "--ttl", "1h")
	runArca(t, "sv", "set", "PLAIN")
	runArca(t, "", "grant", "PLAIN", "--ttl", "1h")

	if out := runArca(t, "", "grants"); !strings.Contains(out, "GHOST") || !strings.Contains(out, "unlimited") {
		t.Fatalf("grants list = %q, want GHOST and an unlimited entry", out)
	}
}

// TestImportDotenv covers the default (dotenv) import path: blanks/comments are skipped, the
// `export ` prefix and surrounding quotes are stripped, an invalid name is refused, and every
// imported secret is recorded in the audit log (a bulk load must not be a blind spot).
func TestImportDotenv(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")

	in := "# a comment\n\nexport TOKEN=\"abc123\"\nDB_URL='postgres://x'\nJUSTAWORD\nbad-name=nope\n"
	runArca(t, in, "import")

	if out := runArca(t, "", "get", "TOKEN"); out != "abc123" {
		t.Fatalf("TOKEN = %q, want abc123", out)
	}
	if out := runArca(t, "", "get", "DB_URL"); out != "postgres://x" {
		t.Fatalf("DB_URL = %q", out)
	}
	if err := runArcaErr("", "get", "bad-name"); err == nil {
		t.Fatal("an invalid name must not be imported")
	}

	a, _ := audit.Open(filepath.Join(dir, "audit.db"))
	defer a.Close()
	evs, _ := a.Recent("TOKEN", 50)
	var sawImport bool
	for _, e := range evs {
		if e.Op == "import" {
			sawImport = true
		}
	}
	if !sawImport {
		t.Fatal("import was not audited")
	}
}

// TestImportJSON covers `import --json`: string values pass through (including a multi-line
// PEM that dotenv could not carry), numbers and booleans are stringified, and null / nested
// values are skipped rather than stored.
func TestImportJSON(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	pem := "-----BEGIN KEY-----\nline1\nline2\n-----END KEY-----"
	js := `{
	  "API_KEY": "k-123",
	  "PORT": 8080,
	  "ENABLED": true,
	  "TLS_KEY": "` + strings.ReplaceAll(pem, "\n", `\n`) + `",
	  "bad-name": "skipme",
	  "NOPE_NULL": null,
	  "NOPE_OBJ": {"x": 1}
	}`
	runArca(t, js, "import", "--json")

	if err := runArcaErr("", "get", "bad-name"); err == nil {
		t.Fatal("an invalid name in JSON must be skipped")
	}
	// Malformed JSON is a hard error, not a silent no-op.
	if err := runArcaErr("{not json", "import", "--json"); err == nil {
		t.Fatal("expected --json on malformed input to fail")
	}

	cases := map[string]string{
		"API_KEY": "k-123",
		"PORT":    "8080",
		"ENABLED": "true",
		"TLS_KEY": pem,
	}
	for name, want := range cases {
		if out := runArca(t, "", "get", name); out != want {
			t.Fatalf("get %s = %q, want %q", name, out, want)
		}
	}
	for _, name := range []string{"NOPE_NULL", "NOPE_OBJ"} {
		if err := runArcaErr("", "get", name); err == nil {
			t.Fatalf("%s should have been skipped, not stored", name)
		}
	}
}

// TestImportOptions covers the ergonomics flags: --dry-run writes nothing, an existing secret
// is skipped unless --overwrite is given, --prefix namespaces the imported names, and --tag
// attaches tags.
func TestImportOptions(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	// --dry-run must not create anything.
	runArca(t, "DRY=1\n", "import", "--dry-run")
	if err := runArcaErr("", "get", "DRY"); err == nil {
		t.Fatal("--dry-run must not write a secret")
	}

	// First real import creates the secret.
	runArca(t, "K=v1\n", "import")
	if out := runArca(t, "", "get", "K"); out != "v1" {
		t.Fatalf("K = %q, want v1", out)
	}
	// Re-importing without --overwrite leaves the existing value untouched.
	runArca(t, "K=v2\n", "import")
	if out := runArca(t, "", "get", "K"); out != "v1" {
		t.Fatalf("without --overwrite K = %q, want unchanged v1", out)
	}
	// With --overwrite it is replaced.
	runArca(t, "K=v2\n", "import", "--overwrite")
	if out := runArca(t, "", "get", "K"); out != "v2" {
		t.Fatalf("with --overwrite K = %q, want v2", out)
	}

	// --prefix namespaces the name; --tag attaches tags.
	runArca(t, "TOKEN=abc\n", "import", "--prefix", "STRIPE_", "--tag", "billing,prod")
	if out := runArca(t, "", "get", "STRIPE_TOKEN"); out != "abc" {
		t.Fatalf("prefixed get = %q, want abc", out)
	}
	if show := runArca(t, "", "show", "STRIPE_TOKEN", "--json"); !strings.Contains(show, "billing") || !strings.Contains(show, "prod") {
		t.Fatalf("expected tags in show output, got %q", show)
	}
}
