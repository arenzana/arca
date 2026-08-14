package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ----------------------------------------------------------------------------
// T13/R28 — `set` and `generate` relaxing the policy on a secret that already exists.
// ----------------------------------------------------------------------------
//
// The six unconditional anchors are covered by operator_test.go. This file covers the conditional
// one, and the two halves it has to get right are equally load-bearing: every downgrade is refused
// without a terminal, and nothing else is. A predicate that over-fires puts a prompt on ordinary
// `set` traffic, and an operator who answers `y` without reading is the failure mode that costs the
// other six anchors their meaning.

// policyFixture builds one secret per policy field, each already carrying the protection that the
// downgrade cases below try to remove.
//
// Every case that is *expected to succeed* mutates its target, so no two such cases may share one.
// The first draft of this file reused PLAIN and RATED across the no-overshoot table and produced two
// failures that looked like predicate bugs and were not: a preceding row had tightened the very bit
// the next row asserted was already loose. A table whose rows mutate shared state is not a table of
// independent cases. The refusal tables can share targets, because a refused case changes nothing.
func policyFixture(t *testing.T) {
	t.Helper()
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "sk-approval", "set", "APPROVAL", "--require-approval")
	runArca(t, "sk-genapproval", "set", "GENAPPROVAL", "--require-approval")
	runArca(t, "sk-noprint", "set", "NOPRINT", "--no-print")
	runArca(t, "sk-grant", "set", "GRANT", "--require-grant")
	runArca(t, "sk-rated", "set", "RATED", "--rate", "10/1h")
	runArca(t, "sk-rated2", "set", "RATED2", "--rate", "10/1h")
	runArca(t, "sk-plain", "set", "PLAIN")
	runArca(t, "sk-plain2", "set", "PLAIN2")
	runArca(t, "sk-plain3", "set", "PLAIN3")
	runArca(t, "sk-plain4", "set", "PLAIN4")
	runArca(t, "", "canary", "DECOY") // plants and arms; the registry is what --canary=false clears
}

// downgrades is every invocation that leaves an existing secret less protected than it is now. Each
// must be refused without a controlling terminal.
//
// `--rate` appears twice on purpose. T13 named only the cleared spelling; an agent refused that one
// writes an absurdly high limit instead and holds the same capability, so the predicate compares
// rates rather than matching the empty string. Both spellings are pinned so a future simplification
// to `rate == ""` fails here rather than in the field.
func downgrades() []struct {
	name string
	args []string
} {
	return []struct {
		name string
		args []string
	}{
		{"clear require-approval", []string{"set", "APPROVAL", "--require-approval=false"}},
		{"clear no-print", []string{"set", "NOPRINT", "--no-print=false"}},
		{"clear require-grant", []string{"set", "GRANT", "--require-grant=false"}},
		{"clear rate", []string{"set", "RATED", "--rate", ""}},
		{"raise rate", []string{"set", "RATED", "--rate", "1000000/1s"}},
		{"disarm canary", []string{"set", "DECOY", "--canary=false"}},
		// Its own target: in TestPolicyDowngradeAllowedForOperator the `set` row above succeeds and
		// clears APPROVAL's bit, after which this row would relax nothing and pass vacuously.
		{"generate clears require-approval", []string{"generate", "GENAPPROVAL", "--require-approval=false"}},
	}
}

// TestPolicyDowngradeRefusedWithoutTerminal is the load-bearing half: an agent that scrubbed its
// environment markers still cannot open a terminal that does not exist.
//
// Every case passes a valid value on stdin, so a refusal cannot be the command failing for want of
// input — the only reason left is the anchor. The message check is what distinguishes the two.
func TestPolicyDowngradeRefusedWithoutTerminal(t *testing.T) {
	policyFixture(t)
	withNoTTY(t)

	for _, tc := range downgrades() {
		t.Run(tc.name, func(t *testing.T) {
			err := runArcaErr("sk-replacement", tc.args...)
			if err == nil {
				t.Fatalf("arca %s succeeded with no controlling terminal; the downgrade is not anchored",
					strings.Join(tc.args, " "))
			}
			if !strings.Contains(err.Error(), "terminal") {
				t.Fatalf("refusal does not explain the terminal requirement (so it may be an unrelated failure): %v", err)
			}
		})
	}
}

// TestPolicyDowngradeRefusedForDetectedAgent covers the cooperating case: a detected agent is
// refused even at a terminal, which is what produces a comprehensible error in normal use.
func TestPolicyDowngradeRefusedForDetectedAgent(t *testing.T) {
	policyFixture(t)
	t.Setenv("CLAUDECODE", "1")
	withTTYResponse(t, "y")

	for _, tc := range downgrades() {
		t.Run(tc.name, func(t *testing.T) {
			err := runArcaErr("sk-replacement", tc.args...)
			if err == nil {
				t.Fatalf("arca %s succeeded for a detected agent", strings.Join(tc.args, " "))
			}
			if !strings.Contains(err.Error(), "claude-code") {
				t.Fatalf("refusal does not name the detected agent: %v", err)
			}
		})
	}
}

// TestPolicyDowngradeAllowedForOperator is the other side of the contract. A control that blocks the
// human too is a broken command, not a security win.
func TestPolicyDowngradeAllowedForOperator(t *testing.T) {
	policyFixture(t)
	withTTYResponse(t, "y")

	for _, tc := range downgrades() {
		t.Run(tc.name, func(t *testing.T) {
			if err := runArcaErr("sk-replacement", tc.args...); err != nil {
				t.Fatalf("arca %s was refused for a human at a terminal: %v",
					strings.Join(tc.args, " "), err)
			}
		})
	}
}

// TestRefusedDowngradeLeavesTheValueIntact pins the reason the guard is placed where it is.
//
// The value write in both commands is unconditional and comes *before* the policy block, so a
// refusal that arrived after it would leave the caller having destroyed the secret it was refused
// permission to downgrade — an anchor that only adds damage. The guard therefore runs before the
// value is read at all, and this test fails if it is ever moved down.
func TestRefusedDowngradeLeavesTheValueIntact(t *testing.T) {
	policyFixture(t)
	withNoTTY(t)

	if err := runArcaErr("sk-replacement", "set", "RATED", "--rate", ""); err == nil {
		t.Fatal("the downgrade was not refused, so this test cannot say anything about ordering")
	}
	if got := strings.TrimSpace(runArca(t, "", "get", "RATED")); got != "sk-rated" {
		t.Fatalf("a refused downgrade changed the value: got %q, want %q — the guard is running after the write", got, "sk-rated")
	}
}

// TestCanaryStaysArmedAfterARefusedDisarm is the same ordering question for the decoy registry,
// which lives outside the store and is written after Save(). A refusal must leave the trap armed.
func TestCanaryStaysArmedAfterARefusedDisarm(t *testing.T) {
	policyFixture(t)
	withNoTTY(t)

	if err := runArcaErr("sk-replacement", "set", "DECOY", "--canary=false"); err == nil {
		t.Fatal("disarming the canary was not refused")
	}
	if !strings.Contains(runArca(t, "", "canary", "--list"), "DECOY") {
		t.Fatal("a refused --canary=false disarmed the decoy anyway; the registry write is not behind the guard")
	}
}

// TestPolicyAnchorDoesNotOverfire is the no-overshoot half, and it is the reason the predicate is
// conditional rather than a seventh unconditional anchor. Every case here must keep working headless.
func TestPolicyAnchorDoesNotOverfire(t *testing.T) {
	policyFixture(t)
	withNoTTY(t)

	for _, tc := range []struct {
		name string
		args []string
		why  string
	}{
		{"create with a loose policy", []string{"set", "NEW", "--require-approval=false"},
			"creating a secret with a loose policy is a choice, not a downgrade"},
		{"re-set the value only", []string{"set", "APPROVAL"},
			"no policy flag was given, so nothing is being relaxed"},
		{"tighten", []string{"set", "PLAIN", "--require-approval"},
			"tightening never needs a terminal"},
		{"tighten the rate", []string{"set", "RATED", "--rate", "1/1h"},
			"a lower cap is a tightening"},
		{"restate the same rate in another window", []string{"set", "RATED2", "--rate", "20/2h"},
			"20/2h is 10/1h; an equal rate is not a downgrade"},
		{"apply a rate where there was none", []string{"set", "PLAIN2", "--rate", "5/1h"},
			"a secret with no limit cannot have its limit relaxed"},
		{"arm a canary", []string{"set", "PLAIN3", "--canary"},
			"arming a decoy is a tightening"},
		{"re-clear a bit that is already clear", []string{"set", "PLAIN4", "--require-approval=false"},
			"the bit is already false, so this invocation relaxes nothing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := runArcaErr("sk-value", tc.args...); err != nil {
				t.Fatalf("arca %s was anchored, but %s: %v", strings.Join(tc.args, " "), tc.why, err)
			}
		})
	}
}

// TestPolicyPredicateCoversEveryPolicyFlag is the guard the comment in operator.go promises.
//
// policyDowngrades() knows a fixed set of flags. Nothing makes `set` or `generate` announce a new
// policy flag to it, so a future author who adds one gets a field that both commands can relax
// headless and a predicate that reads as though it covers everything. This reads the two command
// bodies and fails if either consults a `Changed(...)` flag that has not been classified here.
//
// Classification, not coverage: a flag is either policy (the predicate must weigh it) or not (it
// carries no protection). Adding a flag to `notPolicy` is a deliberate statement, which is the point.
func TestPolicyPredicateCoversEveryPolicyFlag(t *testing.T) {
	policy := map[string]bool{
		"no-print": true, "require-approval": true, "require-grant": true,
		"rate": true, "canary": true,
	}
	notPolicy := map[string]bool{
		// Metadata and value shape. None of these weakens a constraint on who may use the secret.
		"tag": true, "desc": true, "meta": true, "rotate-after": true,
		"length": true, "charset": true, "show": true,
		// Expiry is deliberately excluded here and filed separately: applyExpiry() is shared with a
		// third command, cannot clear an expiry, and "extend" needs its own comparison rule. See the
		// note in docs/THREAT-MODEL.md rather than widening this predicate silently.
		"ttl": true, "expires-at": true,
	}

	// Scan the whole package rather than a named list of files. A hardcoded list silently stops
	// guarding anything the moment the code moves: this test named main.go and generate.go, and
	// went on passing after `set` moved to cmd_secrets.go, checking only half of what it claimed.
	// Globbing means a future author can reorganize freely and still cannot smuggle in an
	// unclassified policy flag.
	re := regexp.MustCompile(`Changed\("([a-z-]+)"\)`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f) //#nosec G304 -- test-local glob of the package's own sources
		if err != nil {
			t.Fatalf("cannot read %s: %v", f, err)
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			seen[m[1]] = true
		}
	}
	if len(seen) == 0 {
		t.Fatal("found no Changed(\"...\") call sites; this test would pass vacuously")
	}

	var unclassified []string
	for flag := range seen {
		if !policy[flag] && !notPolicy[flag] {
			unclassified = append(unclassified, flag)
		}
	}
	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Fatalf("set/generate consult flags this test has not classified: %v\n"+
			"Decide for each whether it is a policy field. If it is, policyDowngrades() in operator.go "+
			"must weigh it — otherwise it can be relaxed on an existing secret with no operator terminal.",
			unclassified)
	}
}
