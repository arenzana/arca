package main

import (
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/store"
)

// TestDisableEnableLifecycle drives disable/enable through every access path: a disabled secret is
// refused on get/exec/inject and skipped by env; ls/show surface it; the audit log records the
// intent; and enable makes it usable again.
func TestDisableEnableLifecycle(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v-alpha", "set", "ALPHA")
	runArca(t, "v-bravo", "set", "BRAVO")

	// Baseline: both usable.
	if out := runArca(t, "", "get", "ALPHA"); out != "v-alpha" {
		t.Fatalf("pre-disable get ALPHA = %q", out)
	}

	runArca(t, "", "disable", "ALPHA")

	// Every read/use path refuses the disabled secret...
	for _, args := range [][]string{
		{"get", "ALPHA"},
		{"exec", "--only", "ALPHA", "--", "true"},
	} {
		if err := runArcaErr("", args...); err == nil {
			t.Fatalf("expected %v to fail on a disabled secret", args)
		}
	}
	if err := runArcaErr("x = \"arca://ALPHA\"\n", "inject"); err == nil {
		t.Fatal("expected inject to refuse a disabled secret")
	}
	// ...while an untouched sibling still works on those same paths.
	if out := runArca(t, "", "get", "BRAVO"); out != "v-bravo" {
		t.Fatalf("get BRAVO after disabling ALPHA = %q", out)
	}
	if err := runArcaErr("", "exec", "--only", "BRAVO", "--", "true"); err != nil {
		t.Fatalf("exec BRAVO after disabling ALPHA: %v", err)
	}

	// show + ls surface the disabled state for a human scanning during an incident.
	if out := runArca(t, "", "show", "ALPHA"); !strings.Contains(out, "DISABLED") {
		t.Fatalf("show ALPHA did not surface disabled state: %q", out)
	}
	if out := runArca(t, "", "ls"); !strings.Contains(out, "[disabled]") {
		t.Fatalf("ls did not flag the disabled secret: %q", out)
	}

	// The audit log records intent (disable), not just an opaque expiry change.
	if out := runArca(t, "", "log", "ALPHA"); !strings.Contains(out, "disable") {
		t.Fatalf("audit log missing disable op: %q", out)
	}

	// enable lifts the disable: usable again on every path.
	runArca(t, "", "enable", "ALPHA")
	if out := runArca(t, "", "get", "ALPHA"); out != "v-alpha" {
		t.Fatalf("post-enable get ALPHA = %q", out)
	}
	if out := runArca(t, "", "log", "ALPHA"); !strings.Contains(out, "enable") {
		t.Fatalf("audit log missing enable op: %q", out)
	}
}

// TestEnvDoesNotAbortOnGatedSecret is the regression guard for the bug that started this: `env`
// must SKIP a secret the gate refuses (disabled/expired), not abort the whole command — otherwise
// one bad secret blanks out every export in `eval "$(arca env)"`. Covered for both a disabled
// secret and a hard-expired one.
func TestEnvDoesNotAbortOnGatedSecret(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v-good", "set", "GOOD")
	runArca(t, "v-disabled", "set", "GONE")
	runArca(t, "v-expired", "set", "OLD")
	runArca(t, "v-grant", "set", "GRANTED", "--require-grant")
	runArca(t, "", "disable", "GONE")
	runArca(t, "dead", "set", "OLD", "--expires-at", "2020-01-01")

	// env succeeds (no error) and still emits the usable secret...
	out, err := execArca("", "env")
	if err != nil {
		t.Fatalf("env aborted instead of skipping gated secrets: %v", err)
	}
	if !strings.Contains(out, "export GOOD=") {
		t.Fatalf("env dropped the usable secret: %q", out)
	}
	// ...but omits the disabled, expired, and require-grant ones (none can be released via env).
	for _, gone := range []string{"GONE", "OLD", "GRANTED"} {
		if strings.Contains(out, gone) {
			t.Fatalf("env emitted a gated secret %s: %q", gone, out)
		}
	}
}

// TestDisableEnablePreservesExpiry covers SEC-13: disable/enable is a distinct kill switch and must
// not clobber a real expiry. A secret with a legitimate future --ttl that is disabled then enabled
// keeps its expiry; and enabling a genuinely-expired secret does NOT silently un-expire it.
func TestDisableEnablePreservesExpiry(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "TOK", "--ttl", "30d")
	before, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	exp := before.Secrets["TOK"].ExpiresAt
	if exp == nil {
		t.Fatal("expected --ttl to set an expiry")
	}

	runArca(t, "", "disable", "TOK")
	if err := runArcaErr("", "get", "TOK"); err == nil {
		t.Fatal("disabled secret should be refused")
	}
	runArca(t, "", "enable", "TOK")

	after, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	sec := after.Secrets["TOK"]
	if sec.Disabled {
		t.Fatal("enable did not clear the disabled flag")
	}
	if sec.ExpiresAt == nil || !sec.ExpiresAt.Equal(*exp) {
		t.Fatalf("enable wiped the real expiry (SEC-13): before=%v after=%v", exp, sec.ExpiresAt)
	}
	if out := runArca(t, "", "get", "TOK"); out != "v" {
		t.Fatalf("post-enable get = %q (expiry is 30d out, should be usable)", out)
	}

	// Enabling a genuinely-expired secret must NOT clear its (intentional) past expiry.
	runArca(t, "dead", "set", "OLD", "--expires-at", "2020-01-01")
	runArca(t, "", "enable", "OLD")
	if err := runArcaErr("", "get", "OLD"); err == nil {
		t.Fatal("enable must not silently un-expire a secret with a real past expiry")
	}
}

// TestDisableEnableErrors covers the not-found paths.
func TestDisableEnableErrors(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	if err := runArcaErr("", "disable", "NOPE"); err == nil {
		t.Fatal("expected disable on a missing secret to fail")
	}
	if err := runArcaErr("", "enable", "NOPE"); err == nil {
		t.Fatal("expected enable on a missing secret to fail")
	}
}

// TestMCPDisable confirms the agent-facing MCP surface honors disable: list marks it, and both
// read_secret and run_with_secrets refuse it — the whole point of a fast kill switch is that an
// agent can't route around it.
func TestMCPDisable(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "topsecret", "set", "API")
	runArca(t, "", "disable", "API")

	if out := text(t, call(t, mcpListSecrets, nil)); !strings.Contains(out, `"disabled": true`) {
		t.Fatalf("list_secrets did not mark the disabled secret: %q", out)
	}
	if !call(t, mcpReadSecret, map[string]any{"name": "API"}).IsError {
		t.Fatal("expected read_secret to refuse a disabled secret")
	}
	if !call(t, mcpRunWithSecrets, map[string]any{"command": "true", "secrets": []any{"API"}}).IsError {
		t.Fatal("expected run_with_secrets to refuse a disabled secret")
	}
}
