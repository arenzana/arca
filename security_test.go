package main

import (
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/store"
)

// --- H1: secret-name validation -------------------------------------------------------------

func TestValidName(t *testing.T) {
	good := []string{"A", "_x", "API_TOKEN", "a1", "lower_case", "_", "MY_PATH", "PATHFINDER", "LDAP_URL"}
	bad := []string{"", "1a", "a-b", "a b", "a;b", "a=b", "PATH/x", "föö", "x;touch /tmp/p"}
	for _, n := range good {
		if err := validName(n); err != nil {
			t.Errorf("validName(%q) = %v, want nil", n, err)
		}
	}
	for _, n := range bad {
		if validName(n) == nil {
			t.Errorf("validName(%q) = nil, want error", n)
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
	}
	for _, n := range reserved {
		if err := validName(n); err == nil {
			t.Errorf("validName(%q) = nil, want reserved-name error", n)
		}
	}
	// Names that merely contain or extend a reserved token stay valid.
	for _, n := range []string{"LDAP", "LD", "DYLD", "MY_PATH", "PATH_TO_KEY", "ENVOY", "EDITORS"} {
		if err := validName(n); err != nil {
			t.Errorf("validName(%q) = %v, want nil (not reserved)", n, err)
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
	s, err := store.Load(storePath())
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
	s, err := store.Load(storePath())
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

// --- H2: an AI agent cannot self-approve ----------------------------------------------------

func TestApproveAgentSelfApprove(t *testing.T) {
	// deny always refuses, agent or not
	t.Setenv("ARCA_APPROVAL", "deny")
	if approve("X", "who") == nil {
		t.Fatal("ARCA_APPROVAL=deny should refuse")
	}

	// allow + non-agent => approved
	t.Setenv("ARCA_APPROVAL", "allow")
	for _, k := range []string{"CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CURSOR_TRACE_ID", "AI_AGENT", "ARCA_ACTOR"} {
		t.Setenv(k, "")
	}
	if err := approve("X", "who"); err != nil {
		t.Fatalf("allow + non-agent should approve, got %v", err)
	}

	// allow + detected agent => refused (no self-approval), without touching /dev/tty
	t.Setenv("AI_AGENT", "claude-code")
	if approve("X", "who") == nil {
		t.Fatal("allow + agent must NOT self-approve")
	}
}
