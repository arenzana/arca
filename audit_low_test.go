package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/remote"
)

// Tests for the 2026-08-17 audit's Low findings that changed behaviour:
// L4 (env replace), L8 (--admit-recipients), L10 (import caps/precision),
// and the Info items (MCP stdin cap, MCP exec accounting).

// TestEnvWithReplacesInherited covers L4: an injected secret must REPLACE an
// inherited same-name variable, not append behind it (glibc getenv takes the
// first match, so the child would otherwise use the inherited value while the
// audit log claims the secret was released).
func TestEnvWithReplacesInherited(t *testing.T) {
	env := []string{"PATH=/bin", "API_KEY=inherited", "HOME=/tmp"}
	env = envWith(env, "API_KEY", "from-store")
	var found []string
	for _, e := range env {
		if strings.HasPrefix(e, "API_KEY=") {
			found = append(found, e)
		}
	}
	if len(found) != 1 || found[0] != "API_KEY=from-store" {
		t.Fatalf("API_KEY entries = %v, want exactly one from-store", found)
	}
	if !strings.Contains(strings.Join(env, "\n"), "PATH=/bin") {
		t.Fatalf("unrelated var was dropped: %v", env)
	}
}

// TestExecReplacesInheritedVar is the end-to-end L4 check: the child sees the
// store value, not the inherited one.
func TestExecReplacesInheritedVar(t *testing.T) {
	sandbox(t)
	t.Setenv("REPLACED", "inherited")
	runArca(t, "", "init")
	runArca(t, "from-store-value", "set", "REPLACED")
	out := runArca(t, "", "exec", "--redact", "off", "--only", "REPLACED", "--", "sh", "-c", `printf '%s' "$REPLACED"`)
	if out != "from-store-value" {
		t.Fatalf("child saw %q, want the store value", out)
	}
}

// TestExecOnlyDedupesNames covers the Info double-count: --only A,A must not
// consume the grant/rate budget twice for one logical use.
func TestExecOnlyDedupesNames(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "ONE", "--rate", "1/1h")
	// Two names for one injection: a single use, not two.
	runArca(t, "", "exec", "--only", "ONE,ONE", "--", "true")
	// A second, distinct exec is what hits the cap.
	if err := runArcaErr("", "exec", "--only", "ONE", "--", "true"); err == nil {
		t.Fatal("the second exec should be rate-limited")
	}
}

// TestStripDotenvQuotes covers L10's quote handling: one matching pair is
// stripped; a lone leading/trailing quote is part of the value.
func TestStripDotenvQuotes(t *testing.T) {
	cases := []struct{ in, want string }{
		{`"quoted"`, "quoted"},
		{`'single'`, "single"},
		{`"leading`, `"leading`},
		{`trailing"`, `trailing"`},
		{`"mismatch'`, `"mismatch'`},
		{`plain`, "plain"},
		{`""`, ""},
	}
	for _, c := range cases {
		if got := stripDotenvQuotes(c.in); got != c.want {
			t.Errorf("stripDotenvQuotes(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestJSONScalarPreservesNumberPrecision covers L10: a big integer or a
// high-precision decimal must not round-trip through float64.
func TestJSONScalarPreservesNumberPrecision(t *testing.T) {
	for _, raw := range []string{`9007199254740993`, `1.1000000000000000000000001`, `1e-400`} {
		got, ok := jsonScalar([]byte(raw))
		if !ok || got != raw {
			t.Errorf("jsonScalar(%s) = %q, %v — precision lost", raw, got, ok)
		}
	}
}

// TestImportDotenvTotalCap covers L10: the dotenv path enforces the same total
// size cap as the JSON path, not just the per-line buffer.
func TestImportDotenvTotalCap(t *testing.T) {
	big := strings.Repeat("A", 1024) + "=v\n"
	r := bytes.NewReader([]byte(strings.Repeat(big, (maxInputBytes/len(big))+2)))
	if _, err := parseDotenvSecrets(r); err == nil {
		t.Fatal("dotenv import past the total size cap should error")
	}
}

// TestCappedLineReader covers the MCP stdin cap: a message longer than the
// limit fails the read rather than buffering forever.
func TestCappedLineReader(t *testing.T) {
	// Short messages pass through untouched, including across the newline boundary.
	short := &cappedLineReader{r: strings.NewReader("one\ntwo\n")}
	buf := make([]byte, 64)
	if n, err := short.Read(buf); err != nil || n == 0 {
		t.Fatalf("short read = %d, %v", n, err)
	}
	// An over-long line errors once the cumulative bytes without a newline pass the cap.
	long := &cappedLineReader{r: strings.NewReader(strings.Repeat("x", maxMCPMessageBytes+16))}
	var err error
	for err == nil {
		_, err = long.Read(make([]byte, 1<<20))
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("over-long line = %v, want a cap error", err)
	}
}

// TestMCPRunRefusedRunDoesNotConsumeBudget covers the Info accounting fix: a
// run refused for an un-redactable short secret must not consume the rate cap.
func TestMCPRunRefusedRunDoesNotConsumeBudget(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "ab", "set", "TINY", "--rate", "1/1h") // 2 chars < minRedactLen: always refused
	runArca(t, "a-long-enough-value", "set", "FINE", "--rate", "1/1h")
	runArca(t, "", "agent", "allow", "TINY")
	runArca(t, "", "agent", "allow", "FINE")
	t.Setenv("ARCA_AGENT_STRICT", "1")

	// Refused (too short to redact): nothing runs and nothing counts.
	res := call(t, mcpRunWithSecrets, map[string]any{"command": "true", "secrets": []any{"TINY"}})
	if !strings.Contains(text(t, res), "too short") {
		t.Fatalf("want a too-short refusal, got %q", text(t, res))
	}
	// A refused run must not have spent TINY's single use: repeat the same
	// refused call and confirm the refusal is still "too short", not "rate limit".
	res = call(t, mcpRunWithSecrets, map[string]any{"command": "true", "secrets": []any{"TINY"}})
	if got := text(t, res); !strings.Contains(got, "too short") {
		t.Fatalf("second refused run = %q, want the same too-short refusal (budget must be untouched)", got)
	}
	// FINE's budget is intact too.
	res = call(t, mcpRunWithSecrets, map[string]any{"command": "true", "secrets": []any{"FINE"}})
	if got := text(t, res); strings.Contains(got, "rate limit") {
		t.Fatalf("a refused run consumed FINE's budget: %q", got)
	}
}

// TestAdmitRecipientsIsTheScopedOverride covers L8: the broadening refusal names
// --admit-recipients, and that flag admits a teammate's key WITHOUT relaxing the
// rollback floor.
func TestAdmitRecipientsIsTheScopedOverride(t *testing.T) {
	dir := sandbox(t)
	withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")

	// Machine A adds a recipient and pushes the broader store.
	aState := os.Getenv("XDG_STATE_HOME")
	_, rec2, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "recipients", "add", rec2)
	runArca(t, "", "reencrypt")
	runArca(t, "", "sync")

	// B has a local store (bootstrapped earlier), so the broadening refusal
	// fires — and it names the scoped flag.
	switchMachine(t, dir)
	runArca(t, "", "sync") // adopt the PRE-broadening store first
	t.Setenv("ARCA_STORE", filepath.Join(dir, "store.json"))
	t.Setenv("ARCA_AUDIT", filepath.Join(dir, "audit.db"))
	t.Setenv("XDG_STATE_HOME", aState)
	runArca(t, "", "sync") // A is at gen 4; B adopts it (B's local was behind)
	t.Setenv("ARCA_STORE", filepath.Join(dir, "machine-b", "store.json"))
	t.Setenv("ARCA_AUDIT", filepath.Join(dir, "machine-b", "audit.db"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "machine-b", "state"))

	// Now A broadens AGAIN so B's next pull adds a recipient B doesn't have.
	_, rec3, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARCA_STORE", filepath.Join(dir, "store.json"))
	t.Setenv("ARCA_AUDIT", filepath.Join(dir, "audit.db"))
	t.Setenv("XDG_STATE_HOME", aState)
	runArca(t, "", "recipients", "add", rec3)
	runArca(t, "", "reencrypt")
	runArca(t, "", "sync")

	t.Setenv("ARCA_STORE", filepath.Join(dir, "machine-b", "store.json"))
	t.Setenv("ARCA_AUDIT", filepath.Join(dir, "machine-b", "audit.db"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "machine-b", "state"))
	err = runArcaErr("", "sync")
	if err == nil || !strings.Contains(err.Error(), "--admit-recipients") {
		t.Fatalf("broadening refusal should name the scoped flag, got: %v", err)
	}
	runArca(t, "", "sync", "--admit-recipients") // admitted, narrowly
}

// TestAdmitRecipientsDoesNotWaiveRollback: the scoped flag must not also accept
// a rolled-back store.
func TestAdmitRecipientsDoesNotWaiveRollback(t *testing.T) {
	sandbox(t)
	fake := withFakeBackend(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "A")
	runArca(t, "", "sync")
	old, oldRev, _ := fake.Fetch(context.Background())
	runArca(t, "v2", "rotate", "A")
	runArca(t, "", "sync")
	if err := os.Remove(syncStatePath()); err != nil {
		t.Fatal(err)
	}
	fake.Corrupt(old, oldRev.Generation)
	fake.SetAuth(remote.StoreAuth{Signature: oldRev.Signature, Signer: oldRev.Signer})

	err := runArcaErr("", "sync", "--pull", "--admit-recipients")
	if err == nil || !strings.Contains(err.Error(), "ROLLBACK") {
		t.Fatalf("--admit-recipients must not waive the rollback floor, got: %v", err)
	}
}
