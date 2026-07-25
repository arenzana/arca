package main

import (
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/crypto"
)

// controlPlaneCommands are the six mutations that change the rules governing agents (T11/T12/R27).
// Each must refuse a detected agent, and must refuse any caller with no controlling terminal.
//
// The `args` deliberately reference secrets/keys that exist in the fixture, so a refusal proves the
// anchor fired rather than the command failing for an unrelated reason (missing secret, bad flag).
//
// `handle create` carries --override on purpose: minting against a gated secret is the exact shape
// of the R27 path (`arca handle create SECRET --ttl 720h --override` walks past the approval gate
// the other five anchors protect), so the test exercises it rather than the benign form.
func controlPlaneCommands(rogueKey string) []struct {
	name string
	args []string
} {
	return []struct {
		name string
		args []string
	}{
		{"grant", []string{"grant", "LOCKED", "--ttl", "1h", "--uses", "99"}},
		{"agent allow", []string{"agent", "allow", "LOCKED"}},
		{"enable", []string{"enable", "KILLED"}},
		{"recipients add", []string{"recipients", "add", rogueKey}},
		{"reencrypt", []string{"reencrypt"}},
		{"handle create", []string{"handle", "create", "LOCKED", "--ttl", "1h", "--override"}},
	}
}

// anchorFixture builds a store with the secrets the table above refers to.
func anchorFixture(t *testing.T) string {
	t.Helper()
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "sk-locked-value", "set", "LOCKED", "--require-grant")
	runArca(t, "sk-killed-value", "set", "KILLED")
	runArca(t, "", "disable", "KILLED")
	_, rogue, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return rogue
}

// TestControlPlaneRefusesDetectedAgent covers the cooperating case: an agent that advertises itself
// is refused with a message naming it. This half is advisory — an agent can scrub the markers — but
// it is what produces a comprehensible error in normal use.
func TestControlPlaneRefusesDetectedAgent(t *testing.T) {
	rogue := anchorFixture(t)
	t.Setenv("CLAUDECODE", "1")
	withTTYResponse(t, "y") // even WITH a terminal, a detected agent is refused

	for _, tc := range controlPlaneCommands(rogue) {
		t.Run(tc.name, func(t *testing.T) {
			err := runArcaErr("", tc.args...)
			if err == nil {
				t.Fatalf("arca %s succeeded for a detected agent; the control plane is not anchored",
					strings.Join(tc.args, " "))
			}
			if !strings.Contains(err.Error(), "claude-code") {
				t.Fatalf("refusal does not name the detected agent: %v", err)
			}
		})
	}
}

// TestControlPlaneRefusesWithoutTerminal covers the load-bearing half: an agent that scrubbed its
// environment markers to look like a human still cannot open a terminal that does not exist. This is
// the check that actually holds, because it does not trust the environment at all.
func TestControlPlaneRefusesWithoutTerminal(t *testing.T) {
	rogue := anchorFixture(t)
	withNoTTY(t) // no agent markers set — the caller looks entirely human

	for _, tc := range controlPlaneCommands(rogue) {
		t.Run(tc.name, func(t *testing.T) {
			err := runArcaErr("", tc.args...)
			if err == nil {
				t.Fatalf("arca %s succeeded with no controlling terminal", strings.Join(tc.args, " "))
			}
			if !strings.Contains(err.Error(), "terminal") {
				t.Fatalf("refusal does not explain the terminal requirement: %v", err)
			}
		})
	}
}

// TestControlPlaneAllowsOperator is the other side of the contract: a human at a terminal, with no
// agent markers, must still be able to run all five. A control that blocks the operator too is not
// a security win, it is a broken command.
func TestControlPlaneAllowsOperator(t *testing.T) {
	rogue := anchorFixture(t)
	withTTYResponse(t, "y")

	for _, tc := range controlPlaneCommands(rogue) {
		t.Run(tc.name, func(t *testing.T) {
			if err := runArcaErr("", tc.args...); err != nil {
				t.Fatalf("arca %s was refused for a human at a terminal: %v",
					strings.Join(tc.args, " "), err)
			}
		})
	}
}

// TestRestrictingCommandsStayUnanchored guards the deliberate carve-out. `agent deny`, `disable`,
// `recipients rm` and `handle revoke` only ever narrow access, so they must keep working without a
// terminal — arca's convention is that a caller may refuse its own access but never grant it.
// Anchoring them would cost convenience, stop nothing, and make quarantining a suspected secret or
// killing a leaked handle harder mid-incident, which is exactly when a terminal may not be available.
func TestRestrictingCommandsStayUnanchored(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "sk-value", "set", "ALPHA")

	_, second, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	// Setup uses the anchored commands, so it needs an operator terminal. The switch to withNoTTY
	// below is what the assertions actually run against (cleanup restores LIFO).
	withTTYResponse(t, "y")
	runArca(t, "", "agent", "allow", "ALPHA")
	runArca(t, "", "recipients", "add", second)
	handleID := strings.TrimSpace(runArca(t, "", "handle", "create", "ALPHA", "--ttl", "1h"))
	if handleID == "" {
		t.Fatal("handle create printed no id; the revoke case below would pass vacuously")
	}

	t.Setenv("CLAUDECODE", "1")
	withNoTTY(t)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"disable", []string{"disable", "ALPHA"}},
		{"agent deny", []string{"agent", "deny", "ALPHA"}},
		{"recipients rm", []string{"recipients", "rm", second}},
		{"handle revoke", []string{"handle", "revoke", handleID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := runArcaErr("", tc.args...); err != nil {
				t.Fatalf("arca %s should stay usable without a terminal (it only restricts): %v",
					strings.Join(tc.args, " "), err)
			}
		})
	}
}

// TestControlPlaneHasNoEnvBypass is the regression guard for the decision recorded in operator.go.
// ARCA_APPROVAL=allow was removed because an agent controls its own environment; re-introducing any
// env-var escape hatch for the control plane would hand the bypass straight back to the party being
// constrained. If someone later adds one, this fails.
func TestControlPlaneHasNoEnvBypass(t *testing.T) {
	rogue := anchorFixture(t)
	t.Setenv("CLAUDECODE", "1")
	withNoTTY(t)

	// Every variable a future author might plausibly reach for, plus the two that already exist and
	// are known to be refusal-only.
	for _, env := range []string{
		"ARCA_OPERATOR", "ARCA_ADMIN", "ARCA_ALLOW", "ARCA_FORCE", "ARCA_NON_INTERACTIVE",
		"ARCA_APPROVAL", "ARCA_AGENT_STRICT",
	} {
		for _, val := range []string{"1", "true", "yes", "allow", "operator"} {
			t.Setenv(env, val)
			for _, tc := range controlPlaneCommands(rogue) {
				if err := runArcaErr("", tc.args...); err == nil {
					t.Fatalf("%s=%s let `arca %s` through — an environment bypass for the control "+
						"plane was introduced; see operator.go", env, val, strings.Join(tc.args, " "))
				}
			}
		}
	}
}
