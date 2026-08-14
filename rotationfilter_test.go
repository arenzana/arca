package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// rotationFixture gives one secret with a rotation policy and one without, which is the only
// distinction the filter under test cares about.
func rotationFixture(t *testing.T) {
	t.Helper()
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v-rot", "set", "WITH_ROTATION", "--rotate-after", "2030-01-01")
	runArca(t, "v-norot", "set", "NO_ROTATION")
}

func TestLsNoRotationFiltersToSecretsWithoutAPolicy(t *testing.T) {
	rotationFixture(t)

	out := runArca(t, "", "ls", "--no-rotation")
	if !strings.Contains(out, "NO_ROTATION") {
		t.Fatalf("--no-rotation should list a secret with no rotation policy:\n%s", out)
	}
	if strings.Contains(out, "WITH_ROTATION") {
		t.Fatalf("--no-rotation should exclude a secret that has one:\n%s", out)
	}
	// Without the flag, ls is unfiltered.
	if all := runArca(t, "", "ls"); !strings.Contains(all, "WITH_ROTATION") {
		t.Fatalf("plain ls should still list everything:\n%s", all)
	}
}

// The filter has to mean the same thing on both output paths. Two copies of the predicate is how
// --json and the table drift into disagreeing about what they are listing.
func TestLsNoRotationAppliesToJSONToo(t *testing.T) {
	rotationFixture(t)

	var views []map[string]any
	if err := json.Unmarshal([]byte(runArca(t, "", "ls", "--no-rotation", "--json")), &views); err != nil {
		t.Fatalf("ls --no-rotation --json is not valid JSON: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("expected exactly the one unrotated secret, got %d entries", len(views))
	}
	if views[0]["name"] != "NO_ROTATION" {
		t.Fatalf("wrong secret in filtered JSON: %v", views[0]["name"])
	}
}

// --no-rotation composes with --tag rather than overriding it, which is the point of making it a
// filter on ls instead of a mode on stale.
func TestLsNoRotationComposesWithTag(t *testing.T) {
	rotationFixture(t)
	runArca(t, "v-tagged", "set", "TAGGED_NO_ROTATION", "--tag", "prod")

	out := runArca(t, "", "ls", "--no-rotation", "--tag", "prod")
	if !strings.Contains(out, "TAGGED_NO_ROTATION") {
		t.Fatalf("both filters should apply together:\n%s", out)
	}
	if strings.Contains(out, "NO_ROTATION\n") && !strings.Contains(out, "TAGGED_NO_ROTATION") {
		t.Fatalf("--tag should still exclude untagged secrets:\n%s", out)
	}
}

// The old spelling must not simply vanish into cobra's "unknown flag", which tells an operator
// nothing about where the behaviour went.
func TestStaleMissingPointsAtItsReplacement(t *testing.T) {
	rotationFixture(t)

	err := runArcaErr("", "stale", "--missing")
	if err == nil {
		t.Fatal("stale --missing should now fail with a migration message")
	}
	if !strings.Contains(err.Error(), "ls --no-rotation") {
		t.Fatalf("the error should name the replacement: %v", err)
	}
}

// The reason for the move. `stale --json` used to emit rotation rows normally and `ls` rows under
// --missing, so one command's documented-stable JSON had two shapes depending on a flag.
func TestStaleJSONHasASingleShape(t *testing.T) {
	rotationFixture(t)
	runArca(t, "v-due", "set", "DUE", "--rotate-after", "2000-01-01")

	var views []map[string]any
	if err := json.Unmarshal([]byte(runArca(t, "", "stale", "--json")), &views); err != nil {
		t.Fatalf("stale --json is not valid JSON: %v", err)
	}
	if len(views) == 0 {
		t.Fatal("expected the overdue secret to be listed")
	}
	// staleView, not secretView: rotation fields, and none of ls's metadata columns.
	for _, v := range views {
		if _, ok := v["status"]; !ok {
			t.Fatalf("stale --json should emit rotation rows (a status field), got: %v", v)
		}
		if _, ok := v["tags"]; ok {
			t.Fatalf("stale --json leaked an ls-shaped row: %v", v)
		}
	}
}
