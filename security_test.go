package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arenzana/arca/internal/secretname"
	"github.com/arenzana/arca/internal/store"
	"github.com/arenzana/arca/internal/xdg"
)

// TestScrubChildEnv drops inherited backend credentials and leaves everything
// else, including an appended same-name injection (audit M7).
func TestScrubChildEnv(t *testing.T) {
	in := []string{
		"PATH=/bin",
		"ARCA_SYNC_ACCESS_KEY=inherited-ak",
		"ARCA_SYNC_SECRET_KEY=inherited-sk",
		"ARCA_SYNC_URL=s3://b/p",
		"ARCA_SYNC_AUTO=1",
		"AWS_ACCESS_KEY_ID=inherited-aws",
		"AWS_SECRET_ACCESS_KEY=inherited-aws-secret",
		"AWS_SESSION_TOKEN=inherited-tok",
		"HOME=/tmp",
	}
	got := scrubChildEnv(in)
	joined := strings.Join(got, "\n")
	for _, leak := range []string{
		"ARCA_SYNC_ACCESS_KEY=", "ARCA_SYNC_SECRET_KEY=",
		"AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY=", "AWS_SESSION_TOKEN=",
	} {
		if strings.Contains(joined, leak) {
			t.Fatalf("scrubChildEnv left %s: %q", leak, got)
		}
	}
	if !strings.Contains(joined, "PATH=/bin") || !strings.Contains(joined, "HOME=/tmp") {
		t.Fatalf("scrubChildEnv dropped a non-credential: %q", got)
	}
	if !strings.Contains(joined, "ARCA_SYNC_URL=") || !strings.Contains(joined, "ARCA_SYNC_AUTO=") {
		t.Fatalf("scrubChildEnv dropped a non-secret sync flag: %q", got)
	}

	// An explicit injection appended after the scrub must survive — that is the
	// documented `exec --only ARCA_SYNC_ACCESS_KEY` bootstrap.
	kept := append(scrubChildEnv(in), "ARCA_SYNC_ACCESS_KEY=from-store")
	if !strings.Contains(strings.Join(kept, "\n"), "ARCA_SYNC_ACCESS_KEY=from-store") {
		t.Fatalf("explicit injection was lost: %q", kept)
	}
}

// TestExecScrubsInheritedBackendCreds is the end-to-end M7 check: a child of
// `arca exec` must not see the operator's ARCA_SYNC_* / AWS_* credentials,
// unless the operator explicitly injected that name from the store.
func TestExecScrubsInheritedBackendCreds(t *testing.T) {
	sandbox(t)
	t.Setenv("ARCA_SYNC_ACCESS_KEY", "inherited-ak")
	t.Setenv("ARCA_SYNC_SECRET_KEY", "inherited-sk")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "inherited-aws")
	runArca(t, "", "init")
	runArca(t, "from-store", "set", "ARCA_SYNC_ACCESS_KEY")
	runArca(t, " innocuous", "set", "OK")

	out := runArca(t, "", "exec", "--redact", "off", "--only", "OK", "--", "sh", "-c",
		`printf 'ak=%s\nsk=%s\naws=%s\n' "$ARCA_SYNC_ACCESS_KEY" "$ARCA_SYNC_SECRET_KEY" "$AWS_SECRET_ACCESS_KEY"`)
	if strings.Contains(out, "inherited-") {
		t.Fatalf("exec leaked inherited backend credentials: %q", out)
	}

	out = runArca(t, "", "exec", "--redact", "off", "--only", "ARCA_SYNC_ACCESS_KEY", "--", "sh", "-c",
		`printf 'ak=%s\n' "$ARCA_SYNC_ACCESS_KEY"`)
	if !strings.Contains(out, "ak=from-store") {
		t.Fatalf("explicit --only injection of ARCA_SYNC_ACCESS_KEY was lost: %q", out)
	}
	if strings.Contains(out, "inherited-") {
		t.Fatalf("explicit injection still carried the inherited value: %q", out)
	}
}

// --- H1: secret-name validation -------------------------------------------------------------

func TestValidName(t *testing.T) {
	good := []string{"A", "_x", "API_TOKEN", "a1", "lower_case", "_", "MY_PATH", "PATHFINDER", "LDAP_URL"}
	bad := []string{"", "1a", "a-b", "a b", "a;b", "a=b", "PATH/x", "föö", "x;touch /tmp/p"}
	for _, n := range good {
		if err := secretname.Validate(n); err != nil {
			t.Errorf("secretname.Validate(%q) = %v, want nil", n, err)
		}
	}
	for _, n := range bad {
		if secretname.Validate(n) == nil {
			t.Errorf("secretname.Validate(%q) = nil, want error", n)
		}
	}
}

// TestValidNameRejectsReserved covers SEC-01: a name that is shaped like a valid identifier but
// would hijack a child process's environment when injected (PATH, LD_PRELOAD, DYLD_*, IFS, …)
// must be refused. Case-insensitive; the LD_/DYLD_ prefixes are dynamic.
func TestValidNameRejectsReserved(t *testing.T) {
	reserved := []string{
		"PATH", "path", "Path", "LD_PRELOAD", "ld_preload", "LD_LIBRARY_PATH",
		"DYLD_INSERT_LIBRARIES", "IFS", "BASH_ENV", "ENV", "SHELLOPTS", "PROMPT_COMMAND",
		"PS1", "PYTHONPATH", "NODE_OPTIONS", "PERL5LIB", "GIT_SSH_COMMAND", "EDITOR",
		"HOME", "SHELL", "TMPDIR", "XDG_CONFIG_HOME",
	}
	for _, n := range reserved {
		if err := secretname.Validate(n); err == nil {
			t.Errorf("secretname.Validate(%q) = nil, want reserved-name error", n)
		}
	}
	// Names that merely contain or extend a reserved token stay valid.
	for _, n := range []string{"LDAP", "LD", "DYLD", "MY_PATH", "PATH_TO_KEY", "ENVOY", "EDITORS"} {
		if err := secretname.Validate(n); err != nil {
			t.Errorf("secretname.Validate(%q) = %v, want nil (not reserved)", n, err)
		}
	}
}

// TestExecRefusesPoisonedReservedName covers the defense-in-depth re-check: even if a reserved
// name is smuggled directly into a git-synced store, `exec` must not inject it into the child
// (which would hijack the process, e.g. LD_PRELOAD loading an attacker .so).
func TestExecRefusesPoisonedReservedName(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "good-val", "set", "GOOD")

	// Poison the store directly, bypassing set's validation, with a reserved env name.
	s, err := store.Load(xdg.StorePath())
	if err != nil {
		t.Fatal(err)
	}
	s.Secrets["LD_PRELOAD"] = s.Secrets["GOOD"]
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	// exec must still run, but must NOT export LD_PRELOAD into the child.
	out := runArca(t, "", "exec", "--", "sh", "-c", "echo LD=[${LD_PRELOAD:-unset}]")
	if !strings.Contains(out, "LD=[unset]") {
		t.Fatalf("exec injected a poisoned reserved name into the child: %q", out)
	}
	// env must not emit it either.
	if e := runArca(t, "", "env"); strings.Contains(e, "LD_PRELOAD") {
		t.Fatalf("env emitted a poisoned reserved name: %q", e)
	}
}

func TestSetRejectsBadName(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	for _, bad := range []string{"x;touch", "a-b", "1abc", "", "a=b", "LD PRELOAD"} {
		if err := runArcaErr("v", "set", bad); err == nil {
			t.Errorf("set %q should be rejected", bad)
		}
	}
	runArca(t, "v", "set", "GOOD_NAME1") // a valid name still works
}

func TestImportSkipsBadNames(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "GOOD=1\nbad-name=2\n;evil=3\nALSO_GOOD=4\n", "import")
	out := runArca(t, "", "ls")
	if !strings.Contains(out, "GOOD") || !strings.Contains(out, "ALSO_GOOD") {
		t.Fatalf("import dropped valid keys: %q", out)
	}
	if strings.Contains(out, "bad-name") || strings.Contains(out, "evil") {
		t.Fatalf("import kept an invalid key: %q", out)
	}
}

// TestEnvExecSkipPoisonedName verifies the defense-in-depth skip: even if a store is
// hand-edited / git-synced to contain an invalid (injection-bearing) name, `env` won't emit it
// (it would otherwise inject under `eval "$(arca env)"`) and `exec` won't set it in the child.
func TestEnvExecSkipPoisonedName(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "good-val", "set", "GOOD")

	// Poison the store directly, bypassing set's validation.
	s, err := store.Load(xdg.StorePath())
	if err != nil {
		t.Fatal(err)
	}
	s.Secrets["x;touch"] = s.Secrets["GOOD"] // reuse the ciphertext under a malicious name
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	out := runArca(t, "", "env")
	if !strings.Contains(out, "GOOD=") {
		t.Fatalf("env dropped the good secret: %q", out)
	}
	if strings.Contains(out, "x;touch") {
		t.Fatalf("env emitted a poisoned name (shell-injection risk): %q", out)
	}
	if out := runArca(t, "", "exec", "--", "sh", "-c", "echo ok"); !strings.Contains(out, "ok") {
		t.Fatalf("exec with a poisoned store entry = %q", out)
	}
}

// --- H2: --require-approval needs a real human, not env / agent-detection (SEC-06) -----------

func TestApproveRequiresTerminal(t *testing.T) {
	sandbox(t) // isolates XDG etc.; also clears agent-detection env vars

	// deny always refuses (the env can only restrict).
	t.Setenv("ARCA_APPROVAL", "deny")
	if approve("X", "who") == nil {
		t.Fatal("ARCA_APPROVAL=deny should refuse")
	}

	// ARCA_APPROVAL=allow is NO LONGER a pre-approval: without a terminal, approval is refused —
	// there is no env bypass (SEC-06). This holds whether or not the caller looks like an agent.
	// (withNoTTY makes "no terminal" deterministic; a real CONIN$ on Windows would block on input.)
	withNoTTY(t)
	t.Setenv("ARCA_APPROVAL", "allow")
	if approve("X", "who") == nil {
		t.Fatal("ARCA_APPROVAL=allow must not pre-approve without a terminal")
	}
	t.Setenv("AI_AGENT", "claude-code")
	if approve("X", "who") == nil {
		t.Fatal("an agent must not self-approve")
	}

	// With a real (mocked) terminal, a human answering "y" approves and "n" declines — regardless of
	// ARCA_APPROVAL or agent detection.
	t.Setenv("ARCA_APPROVAL", "")
	withTTYResponse(t, "y")
	if err := approve("X", "who"); err != nil {
		t.Fatalf("a 'y' at the terminal should approve, got %v", err)
	}
	withTTYResponse(t, "n")
	if approve("X", "who") == nil {
		t.Fatal("an 'n' at the terminal should decline")
	}
}

// TestApproveTimesOut is audit L7: a silent terminal must fail closed, not hang.
func TestApproveTimesOut(t *testing.T) {
	sandbox(t)
	old := operatorTimeout
	operatorTimeout = 50 * time.Millisecond
	t.Cleanup(func() { operatorTimeout = old })
	// A pipe that never answers: openTTY returns a reader with no data.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	prev := openTTY
	t.Cleanup(func() { openTTY = prev })
	openTTY = func() (in, out *os.File, err error) {
		devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			return nil, nil, err
		}
		return r, devnull, nil
	}
	err = approve("X", "who")
	if err == nil || !strings.Contains(err.Error(), "within") {
		t.Fatalf("silent terminal = %v, want a timeout refusal", err)
	}
}

// TestSessionSeedRefusesCorrupt is audit L3: a truncated session key must not
// be silently regenerated (that would make every prior event fail verify).
func TestSessionSeedRefusesCorrupt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sess.key")
	if err := os.WriteFile(p, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadOrCreateSeed(p)
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt session seed = %v, want a refusal", err)
	}
}
