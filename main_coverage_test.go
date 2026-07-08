package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/store"
)

// TestInitForceAndExisting covers init's refusal to clobber and the --force override.
func TestInitForceAndExisting(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := runArcaErr("", "init"); err == nil {
		t.Fatal("expected init to refuse an existing store")
	}
	runArca(t, "", "init", "--force")
}

// TestLsShowRm covers listing (default, --tag filter, --reads), show (with metadata + missing),
// and rm (existing + missing).
func TestLsShowRm(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "ALPHA", "--tag", "x,y", "--desc", "first", "--meta", "k=v", "--rotate-after", "2030-01-01")
	runArca(t, "v2", "set", "BETA")

	if out := runArca(t, "", "ls"); !strings.Contains(out, "ALPHA") || !strings.Contains(out, "BETA") {
		t.Fatalf("ls = %q", out)
	}
	if out := runArca(t, "", "ls", "--tag", "x"); !strings.Contains(out, "ALPHA") || strings.Contains(out, "BETA") {
		t.Fatalf("ls --tag = %q", out)
	}
	runArca(t, "", "get", "ALPHA") // produce a read so --reads has data
	if out := runArca(t, "", "ls", "--reads"); !strings.Contains(out, "ALPHA") {
		t.Fatalf("ls --reads = %q", out)
	}

	if out := runArca(t, "", "show", "ALPHA"); !strings.Contains(out, "first") || !strings.Contains(out, "meta.k") || !strings.Contains(out, "rotate after") {
		t.Fatalf("show = %q", out)
	}
	if err := runArcaErr("", "show", "NOPE"); err == nil {
		t.Fatal("expected show of missing secret to fail")
	}

	runArca(t, "", "rm", "BETA")
	if err := runArcaErr("", "rm", "BETA"); err == nil {
		t.Fatal("expected rm of missing secret to fail")
	}
}

// TestShowNoPrintPolicy verifies the policy line surfaces in show.
func TestShowNoPrintPolicy(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "LOCK", "--no-print")
	if out := runArca(t, "", "show", "LOCK"); !strings.Contains(out, "no-print") {
		t.Fatalf("show should note no-print policy: %q", out)
	}
}

// TestImportAndEnv covers dotenv import (comments/blanks/quotes/export) and env output,
// including that --no-print secrets are skipped and --no-export drops the prefix.
func TestImportAndEnv(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "FOO=bar\nexport BAZ=\"qux\"\n# comment\n\n", "import")
	if out := runArca(t, "", "get", "FOO"); out != "bar" {
		t.Fatalf("imported FOO = %q", out)
	}
	if out := runArca(t, "", "get", "BAZ"); out != "qux" {
		t.Fatalf("imported BAZ = %q", out)
	}

	runArca(t, "s", "set", "HIDDEN", "--no-print")
	if out := runArca(t, "", "env"); !strings.Contains(out, "export FOO='bar'") || strings.Contains(out, "HIDDEN") {
		t.Fatalf("env = %q", out)
	}
	if out := runArca(t, "", "env", "--no-export"); !strings.Contains(out, "FOO='bar'") || strings.Contains(out, "export ") {
		t.Fatalf("env --no-export = %q", out)
	}
}

// TestLogCommand covers the log table and the per-name filter.
func TestLogCommand(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "L1")
	runArca(t, "", "get", "L1")
	if out := runArca(t, "", "log"); !strings.Contains(out, "L1") || !strings.Contains(out, "read") {
		t.Fatalf("log = %q", out)
	}
	if out := runArca(t, "", "log", "L1", "--limit", "1"); !strings.Contains(out, "L1") {
		t.Fatalf("log L1 = %q", out)
	}
}

// TestExecAndInjectErrors covers exec --only, the missing-secret error paths for exec/inject,
// and get's -n / --no-log flags. (The non-zero child-exit path calls os.Exit and is therefore
// not exercised here.)
func TestExecAndInjectErrors(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "OK")

	if out := runArca(t, "", "exec", "--only", "OK", "--", "sh", "-c", "echo v=$OK"); !strings.Contains(out, "v=v") {
		t.Fatalf("exec = %q", out)
	}
	if err := runArcaErr("", "exec", "--only", "MISSING", "--", "true"); err == nil {
		t.Fatal("expected exec of missing secret to fail")
	}
	if err := runArcaErr("x=arca://MISSING", "inject"); err == nil {
		t.Fatal("expected inject of missing reference to fail")
	}
	if out := runArca(t, "", "get", "OK", "-n"); out != "v\n" {
		t.Fatalf("get -n = %q", out)
	}
	runArca(t, "", "get", "OK", "--no-log")
}

// TestRotateErrorsAndStaleVariants covers rotate's missing-secret error and the stale filters
// (default overdue, --missing, --within).
func TestRotateErrorsAndStaleVariants(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := runArcaErr("v", "rotate", "GHOST"); err == nil {
		t.Fatal("expected rotate of missing secret to fail")
	}
	runArca(t, "v", "set", "R")
	runArca(t, "v2", "rotate", "R", "--rotate-after", "2000-01-01")
	runArca(t, "v", "set", "SOON", "--rotate-after", "2999-01-01")
	runArca(t, "v", "set", "NONE")

	if out := runArca(t, "", "stale"); !strings.Contains(out, "R") {
		t.Fatalf("stale = %q", out)
	}
	if out := runArca(t, "", "stale", "--missing"); !strings.Contains(out, "NONE") {
		t.Fatalf("stale --missing = %q", out)
	}
	if out := runArca(t, "", "stale", "--within", "1000000"); !strings.Contains(out, "SOON") {
		t.Fatalf("stale --within = %q", out)
	}
}

// TestDetectIdentityCursorAndNone covers the Cursor branch and the no-agent case.
func TestDetectIdentityCursorAndNone(t *testing.T) {
	t.Setenv("ARCA_ACTOR", "")
	t.Setenv("AI_AGENT", "")
	t.Setenv("CLAUDECODE", "")
	t.Setenv("CLAUDE_CODE_SESSION_ID", "")
	t.Setenv("CURSOR_TRACE_ID", "trace-9")
	if id := detectIdentity(); id.Agent != "cursor" || id.Session != "trace-9" {
		t.Fatalf("cursor: %+v", id)
	}
	t.Setenv("CURSOR_TRACE_ID", "")
	if got := detectIdentity(); got.Agent != "" {
		t.Fatalf("expected no agent, got %+v", got)
	}
}

// TestAuditFailureModes covers fail-closed (default) vs best-effort auditing. With a corrupt
// audit db, operations abort by default (and a read won't disclose); opting out via
// ARCA_STRICT_AUDIT=0 lets them proceed despite the broken log.
func TestAuditFailureModes(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")
	if err := os.WriteFile(filepath.Join(dir, "audit.db"), []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Default: fail-closed — abort when the access can't be audited.
	if err := runArcaErr("v", "set", "K"); err == nil {
		t.Fatal("expected set to fail under default (strict) auditing")
	}
	if err := runArcaErr("", "get", "K"); err == nil {
		t.Fatal("expected get to fail-closed under default auditing")
	}
	// Opt out → best-effort (non-agent, at a terminal): the broken audit log is swallowed and
	// the op proceeds. The lax override is TTY-anchored (SEC-06), so fake a terminal.
	for _, k := range []string{"CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CURSOR_TRACE_ID", "AI_AGENT"} {
		t.Setenv(k, "")
	}
	t.Setenv("ARCA_STRICT_AUDIT", "0")
	withTTYResponse(t, "")
	runArca(t, "v", "set", "K2")
	if out := runArca(t, "", "get", "K2"); out != "v" {
		t.Fatalf("best-effort get = %q", out)
	}
	// An AI agent cannot weaken fail-closed auditing, even with ARCA_STRICT_AUDIT=0.
	t.Setenv("AI_AGENT", "claude-code")
	if err := runArcaErr("v", "set", "K3"); err == nil {
		t.Fatal("expected an agent to remain fail-closed despite ARCA_STRICT_AUDIT=0")
	}
}

// TestImportScannerError covers the scanner-error branch: a line longer than the 1 MiB buffer.
func TestImportScannerError(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	big := "K=" + strings.Repeat("x", 2_000_000) // exceeds the scanner buffer
	if err := runArcaErr(big, "import"); err == nil {
		t.Fatal("expected import to fail on an over-long line")
	}
}

// TestDetectIdentityGenericNoVersion covers AI_AGENT with no version segment.
func TestDetectIdentityGenericNoVersion(t *testing.T) {
	t.Setenv("ARCA_ACTOR", "")
	t.Setenv("CLAUDECODE", "")
	t.Setenv("CLAUDE_CODE_SESSION_ID", "")
	t.Setenv("CURSOR_TRACE_ID", "")
	t.Setenv("AI_AGENT", "soloagent")
	if id := detectIdentity(); id.Agent != "soloagent" || id.Version != "" {
		t.Fatalf("got %+v", id)
	}
}

// TestApproverWho covers all three branches of the approval-prompt descriptor deterministically
// (so coverage doesn't depend on whether the suite happens to run under an AI agent).
func TestApproverWho(t *testing.T) {
	// agent branch — name/version/session formatting
	t.Setenv("ARCA_ACTOR", "")
	t.Setenv("AI_AGENT", "")
	t.Setenv("CURSOR_TRACE_ID", "")
	t.Setenv("CLAUDECODE", "1")
	t.Setenv("CLAUDE_CODE_SESSION_ID", "abcdef1234567890")
	t.Setenv("CLAUDE_CODE_EXECPATH", "/x/claude-code/9.9.9/claude")
	if w := approverWho(); !strings.Contains(w, "claude-code/9.9.9") || !strings.Contains(w, "abcdef12") {
		t.Fatalf("agent descriptor = %q", w)
	}
	// actor branch
	t.Setenv("CLAUDECODE", "")
	t.Setenv("CLAUDE_CODE_SESSION_ID", "")
	t.Setenv("ARCA_ACTOR", "alice")
	if w := approverWho(); w != "alice" {
		t.Fatalf("actor descriptor = %q", w)
	}
	// fallback branch: with no agent and no explicit actor, the OS user stands in (or the literal
	// "this process" when even that can't be resolved).
	t.Setenv("ARCA_ACTOR", "")
	want := osUser()
	if want == "" {
		want = "this process"
	}
	if w := approverWho(); w != want {
		t.Fatalf("fallback descriptor = %q, want %q", w, want)
	}
}

// TestHelpers exercises the small pure helpers directly.
func TestHelpers(t *testing.T) {
	if !contains([]string{"a", "b"}, "b") || contains([]string{"a"}, "z") {
		t.Fatal("contains")
	}
	if shellQuote("a'b") != `'a'\''b'` {
		t.Fatalf("shellQuote = %s", shellQuote("a'b"))
	}
	if shortID("0123456789") != "01234567" || shortID("abc") != "abc" {
		t.Fatal("shortID")
	}
	if firstSemver("x/2.1.181/y") != "2.1.181" || firstSemver("none") != "" {
		t.Fatal("firstSemver")
	}
	if !envSet("PATH") || envSet("ARCA_DEFINITELY_UNSET_XYZ") {
		t.Fatal("envSet")
	}
}

// TestPathResolution covers env overrides, XDG defaults, and the SOPS/HOME fallbacks.
func TestPathResolution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX absolute paths; the XDG/env resolution logic is identical cross-OS")
	}
	t.Setenv("ARCA_STORE", "/tmp/s.json")
	t.Setenv("ARCA_AUDIT", "/tmp/a.db")
	t.Setenv("ARCA_IDENTITY", "/tmp/id")
	if storePath() != "/tmp/s.json" || auditPath() != "/tmp/a.db" || identityPath() != "/tmp/id" {
		t.Fatal("env override paths")
	}

	t.Setenv("ARCA_STORE", "")
	t.Setenv("ARCA_AUDIT", "")
	t.Setenv("ARCA_IDENTITY", "")
	t.Setenv("SOPS_AGE_KEY_FILE", "")
	t.Setenv("XDG_CONFIG_HOME", "/x/cfg")
	t.Setenv("XDG_STATE_HOME", "/x/state")
	if configDir() != "/x/cfg/arca" || stateDir() != "/x/state/arca" {
		t.Fatalf("xdg dirs: %s %s", configDir(), stateDir())
	}
	if storePath() != "/x/cfg/arca/store.json" || auditPath() != "/x/state/arca/audit.db" || identityPath() != "/x/cfg/arca/identity.txt" {
		t.Fatal("default paths")
	}

	t.Setenv("SOPS_AGE_KEY_FILE", "/sops/key")
	if identityPath() != "/sops/key" {
		t.Fatalf("identity sops fallback = %s", identityPath())
	}

	t.Setenv("XDG_CONFIG_HOME", "")
	home, _ := os.UserHomeDir()
	if configDir() != filepath.Join(home, ".config", "arca") {
		t.Fatalf("home fallback = %s", configDir())
	}
}

// TestCommandsWithoutStore hits the "no store" early-return in every command that opens it.
func TestCommandsWithoutStore(t *testing.T) {
	sandbox(t) // deliberately NOT initialized → store is missing
	cases := [][]string{
		{"ls"}, {"show", "X"}, {"rm", "X"}, {"import"}, {"env"},
		{"stale"}, {"get", "X"}, {"set", "X"}, {"rotate", "X"},
		{"inject"}, {"exec", "--", "true"},
	}
	for _, args := range cases {
		if err := runArcaErr("", args...); err == nil {
			t.Errorf("expected an error without a store: arca %s", strings.Join(args, " "))
		}
	}
}

// TestMissingIdentity hits the "can't load the decryption key" path in the commands that
// decrypt, by removing the identity after init.
func TestMissingIdentity(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "K")
	if err := os.Remove(filepath.Join(dir, "id.txt")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"get", "K"}, {"env"}, {"exec", "--only", "K", "--", "true"}} {
		if err := runArcaErr("", args...); err == nil {
			t.Errorf("expected an error with a missing identity: arca %s", strings.Join(args, " "))
		}
	}
	if err := runArcaErr("x=arca://K", "inject"); err == nil {
		t.Error("expected inject to fail with a missing identity")
	}
}

// TestInitReuseIdentity covers init's "reuse the existing key" branch (vs generating one).
func TestInitReuseIdentity(t *testing.T) {
	dir := sandbox(t)
	idStr, _, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id.txt"), []byte(idStr+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "init") // must reuse the pre-existing identity
	s, err := store.Load(filepath.Join(dir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Recipients) != 1 {
		t.Fatalf("recipients = %v", s.Recipients)
	}
}

// TestApprovalGate covers the --require-approval policy: show notes it, denial blocks every release
// path (get/exec/inject/env), there is no env pre-approval (SEC-06), and a terminal confirmation
// lets it through.
func TestApprovalGate(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "secret", "set", "GATED", "--require-approval")
	if out := runArca(t, "", "show", "GATED"); !strings.Contains(out, "requires approval") {
		t.Fatalf("show = %q", out)
	}

	t.Setenv("ARCA_APPROVAL", "deny")
	for _, c := range []struct {
		stdin string
		args  []string
	}{
		{"", []string{"get", "GATED"}},
		{"", []string{"exec", "--only", "GATED", "--", "true"}},
		{"x=arca://GATED", []string{"inject"}},
		{"", []string{"env"}},
	} {
		if err := runArcaErr(c.stdin, c.args...); err == nil {
			t.Errorf("expected approval denial: arca %s", strings.Join(c.args, " "))
		}
	}

	// SEC-06: there is no env pre-approval. Without a terminal, a release is refused even with
	// ARCA_APPROVAL unset — `allow` is no longer honored as a bypass. (withNoTTY makes "no terminal"
	// deterministic; a real CONIN$ on Windows would otherwise block on input.)
	withNoTTY(t)
	t.Setenv("ARCA_APPROVAL", "allow")
	if err := runArcaErr("", "get", "GATED"); err == nil {
		t.Fatal("get of a require-approval secret must be refused without a terminal (no env bypass)")
	}
	// A human answering "y" at the (mocked) terminal approves; "n" declines.
	t.Setenv("ARCA_APPROVAL", "")
	withTTYResponse(t, "y")
	if out := runArca(t, "", "get", "GATED"); out != "secret" {
		t.Fatalf("approved get = %q", out)
	}
	withTTYResponse(t, "n")
	if err := runArcaErr("", "get", "GATED"); err == nil {
		t.Fatal("declining at the terminal should refuse the release")
	}
}

// TestInitMalformedIdentity covers init's reuse branch when the existing key won't parse.
func TestInitMalformedIdentity(t *testing.T) {
	dir := sandbox(t)
	if err := os.WriteFile(filepath.Join(dir, "id.txt"), []byte("AGE-SECRET-KEY-1NOPE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runArcaErr("", "init"); err == nil {
		t.Fatal("expected init to fail with a malformed identity")
	}
}

// TestBadRecipient covers the ParseRecipients error path: a store with a malformed recipient
// can't encrypt.
func TestBadRecipient(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")
	p := filepath.Join(dir, "store.json")
	b, _ := os.ReadFile(p)
	bad := strings.Replace(string(b), `"recipients": [`, `"recipients": ["not-a-recipient",`, 1)
	if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runArcaErr("v", "set", "X"); err == nil {
		t.Fatal("expected set to fail with a malformed recipient")
	}
}

// TestRotateBadRecipient covers rotate's ParseRecipients error path.
func TestRotateBadRecipient(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "R")
	p := filepath.Join(dir, "store.json")
	b, _ := os.ReadFile(p)
	bad := strings.Replace(string(b), `"recipients": [`, `"recipients": ["bad",`, 1)
	if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runArcaErr("v2", "rotate", "R"); err == nil {
		t.Fatal("expected rotate to fail with a bad recipient")
	}
}

// TestWrongKeyDecryptFails swaps in a different identity after storing, so every decrypt path
// (get/inject/env/exec) must fail.
func TestWrongKeyDecryptFails(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")
	runArca(t, "secret", "set", "K")
	other, _, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "id.txt"), []byte(other+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		stdin string
		args  []string
	}{
		{"", []string{"get", "K"}},
		{"x=arca://K", []string{"inject"}},
		{"", []string{"env"}},
		{"", []string{"exec", "--only", "K", "--", "true"}},
	} {
		if err := runArcaErr(c.stdin, c.args...); err == nil {
			t.Errorf("expected decrypt failure: arca %s", strings.Join(c.args, " "))
		}
	}
}

// TestBadRotateAfterDate covers the date-parse error branch in set and rotate.
func TestBadRotateAfterDate(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := runArcaErr("v", "set", "S", "--rotate-after", "not-a-date"); err == nil {
		t.Fatal("expected set to reject a bad rotate-after date")
	}
	runArca(t, "v", "set", "R")
	if err := runArcaErr("v2", "rotate", "R", "--rotate-after", "nope"); err == nil {
		t.Fatal("expected rotate to reject a bad rotate-after date")
	}
}

// TestExecNoCommand covers the "no command given" guard.
func TestExecNoCommand(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := runArcaErr("", "exec"); err == nil {
		t.Fatal("expected exec with no command to fail")
	}
}

// TestImportBadRecipient covers import's ParseRecipients error path.
func TestImportBadRecipient(t *testing.T) {
	dir := sandbox(t)
	runArca(t, "", "init")
	p := filepath.Join(dir, "store.json")
	b, _ := os.ReadFile(p)
	bad := strings.Replace(string(b), `"recipients": [`, `"recipients": ["bad-recipient",`, 1)
	if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runArcaErr("FOO=bar", "import"); err == nil {
		t.Fatal("expected import to fail with a bad recipient")
	}
}

// TestMainEntry covers main()'s happy path: --version makes Execute return nil, so os.Exit is
// not called and main returns normally.
func TestMainEntry(t *testing.T) {
	oldArgs, oldOut := os.Args, os.Stdout
	defer func() { os.Args, os.Stdout = oldArgs, oldOut }()
	// Use a temp file, not a pipe with a discarded read end: an unread pipe whose reader is
	// GC-closed mid-write breaks the write, which would make main() os.Exit(1) and kill the test
	// binary — an intermittent cross-OS flake.
	f, err := os.CreateTemp("", "arca-main-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	os.Stdout = f
	os.Args = []string{"arca", "--version"}
	main()
}

// FuzzShellQuote checks shellQuote never panics and always returns a single-quoted string,
// for any input — and doubles as arca's native-fuzzing target for OpenSSF Scorecard.
// FuzzFirstSemver ensures the version extractor never panics on arbitrary input.
func FuzzFirstSemver(f *testing.F) {
	f.Add("1.2.3")
	f.Add("/a/2.1.181/b")
	f.Add("....")
	f.Fuzz(func(t *testing.T, s string) { _ = firstSemver(s) })
}
