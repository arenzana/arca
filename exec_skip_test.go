package main

import (
	"strings"
	"testing"
)

// A bare `arca exec` sweeps the whole store as a convenience. Before this fix, one unusable
// secret anywhere in that sweep aborted the run with an error naming a secret the caller had not
// asked for, and the command never executed at all: a single expired credential took down every
// `exec` on the machine until someone noticed which one it was.
//
// `env` had the same defect and was fixed by skipping what it cannot release. These tests hold
// `exec` to the same rule, and to the two limits on it: an explicitly requested secret still
// errors, and a deliberate refusal is still fatal.

func execSkipFixture(t *testing.T) {
	t.Helper()
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "good", "set", "API_KEY")
	runArca(t, "stale", "set", "OLD_TOKEN", "--expires-at", "2020-01-01")
	runArca(t, "off", "set", "DEAD")
	runArca(t, "", "disable", "DEAD")
	runArca(t, "grantme", "set", "DEPLOY_KEY", "--require-grant")
}

func TestExecSkipsUnusableSecretsInTheSweep(t *testing.T) {
	execSkipFixture(t)
	withNoTTY(t)

	out, err := execArca("", "exec", "--", "sh", "-c", "echo COMMAND_RAN")
	if err != nil {
		t.Fatalf("one unusable secret must not abort a command that did not ask for it: %v", err)
	}
	if !strings.Contains(out, "COMMAND_RAN") {
		t.Fatalf("the command did not run:\n%s", out)
	}
}

// The usable secrets must still be injected. A "fix" that skipped everything would pass the test
// above and be worthless.
func TestExecStillInjectsTheUsableOnes(t *testing.T) {
	execSkipFixture(t)
	withNoTTY(t)

	// --redact off so the assertion sees the value rather than the marker.
	out, err := execArca("", "exec", "--redact", "off", "--", "sh", "-c", "echo got=$API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "got=good") {
		t.Fatalf("a healthy secret should still be injected:\n%s", out)
	}
}

// The limit that keeps the skip honest: naming a secret is a request for it, and silently running
// the command without it would be worse than failing, because the command may well "succeed"
// unauthenticated.
func TestExecOnlyStillErrorsOnAnUnusableSecret(t *testing.T) {
	execSkipFixture(t)
	withNoTTY(t)

	for _, name := range []string{"OLD_TOKEN", "DEAD"} {
		t.Run(name, func(t *testing.T) {
			err := runArcaErr("", "exec", "--only", name, "--", "true")
			if err == nil {
				t.Fatalf("--only %s must still fail: it was explicitly requested", name)
			}
		})
	}
}

// A require-grant secret is releasable through exec when a grant authorizes the command, so the
// skip must not swallow the path the flag exists to enable.
func TestExecInjectsRequireGrantWhenAGrantMatches(t *testing.T) {
	execSkipFixture(t)
	withTTYResponse(t, "y") // `grant` is a control-plane action and is terminal-anchored
	runArca(t, "", "grant", "DEPLOY_KEY", "--command", "sh *", "--uses", "2", "--ttl", "15m")

	out, err := execArca("", "exec", "--redact", "off", "--", "sh", "-c", "echo got=$DEPLOY_KEY")
	if err != nil {
		t.Fatalf("a granted secret must still be injected: %v", err)
	}
	if !strings.Contains(out, "got=grantme") {
		t.Fatalf("require-grant secret was skipped despite a matching grant:\n%s", out)
	}
}

// The other limit. gate() failures that represent a decision or a fail-closed guarantee stay
// fatal: only the "not releasable here" conditions are skipped, and an approval denial is a
// person saying no.
func TestExecStillFailsOnApprovalDenial(t *testing.T) {
	execSkipFixture(t)
	runArca(t, "guarded", "set", "NEEDS_OK", "--require-approval")
	withTTYResponse(t, "n") // the operator declines

	if err := runArcaErr("", "exec", "--", "true"); err == nil {
		t.Fatal("a declined approval must still fail the command, not be skipped")
	}
}

// The skips are reported, not silent. An operator who wonders why a variable is missing needs to
// be able to see which secret was dropped and why.
func TestExecNamesWhatItSkipped(t *testing.T) {
	execSkipFixture(t)
	withNoTTY(t)

	err := captureStderr(t, func() {
		if _, e := execArca("", "exec", "--", "true"); e != nil {
			t.Fatalf("exec failed: %v", e)
		}
	})
	for _, want := range []string{"OLD_TOKEN", "DEAD", "DEPLOY_KEY"} {
		if !strings.Contains(err, want) {
			t.Errorf("skipped %s without saying so:\n%s", want, err)
		}
	}
}
