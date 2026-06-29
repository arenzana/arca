package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/crypto"
)

func TestJSONOutput(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API", "--tag", "demo", "--desc", "d")
	runArca(t, "", "get", "API") // produce a read event for log/last_read

	var ls []map[string]any
	if err := json.Unmarshal([]byte(runArca(t, "", "ls", "--json")), &ls); err != nil {
		t.Fatalf("ls --json: %v", err)
	}
	if len(ls) != 1 || ls[0]["name"] != "API" {
		t.Fatalf("ls --json = %v", ls)
	}

	var show map[string]any
	if err := json.Unmarshal([]byte(runArca(t, "", "show", "API", "--json")), &show); err != nil {
		t.Fatalf("show --json: %v", err)
	}
	if show["name"] != "API" || show["description"] != "d" {
		t.Fatalf("show --json = %v", show)
	}

	var logEvents []map[string]any
	if err := json.Unmarshal([]byte(runArca(t, "", "log", "--json")), &logEvents); err != nil {
		t.Fatalf("log --json: %v", err)
	}
	if len(logEvents) == 0 || logEvents[0]["op"] == nil {
		t.Fatalf("log --json = %v", logEvents)
	}

	runArca(t, "v", "set", "OLD", "--rotate-after", "2020-01-01")
	var stale []map[string]any
	if err := json.Unmarshal([]byte(runArca(t, "", "stale", "--json")), &stale); err != nil {
		t.Fatalf("stale --json: %v", err)
	}
	found := false
	for _, r := range stale {
		if r["name"] == "OLD" {
			found = true
		}
	}
	if !found {
		t.Fatalf("stale --json missing OLD: %v", stale)
	}

	var miss []map[string]any
	if err := json.Unmarshal([]byte(runArca(t, "", "stale", "--missing", "--json")), &miss); err != nil {
		t.Fatalf("stale --missing --json: %v", err)
	}
}

func TestCompletion(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "ALPHA", "--tag", "x")
	runArca(t, "v", "set", "BETA", "--tag", "y")

	if names, _ := completeSecretNames(nil, nil, "AL"); len(names) != 1 || names[0] != "ALPHA" {
		t.Fatalf("completeSecretNames(AL) = %v", names)
	}
	if all, _ := completeSecretNames(nil, nil, ""); len(all) != 2 {
		t.Fatalf("completeSecretNames() = %v", all)
	}
	// already-typed names are excluded (so `exec --only A,B` won't re-offer A)
	if rest, _ := completeSecretNames(nil, []string{"ALPHA"}, ""); len(rest) != 1 || rest[0] != "BETA" {
		t.Fatalf("completeSecretNames(args=ALPHA) = %v", rest)
	}
	if tags, _ := completeTags(nil, nil, ""); len(tags) != 2 {
		t.Fatalf("completeTags() = %v", tags)
	}
}

func TestRecipients(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "secret", "set", "API")

	_, rec2, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	runArca(t, "", "recipients", "add", rec2)
	if lst := runArca(t, "", "recipients"); !strings.Contains(lst, rec2) {
		t.Fatalf("recipients = %q", lst)
	}
	// adding the same recipient again is a no-op (still works, no duplicate)
	runArca(t, "", "recipients", "add", rec2)

	// reencrypt re-wraps to both; the value still decrypts with our identity
	runArca(t, "", "reencrypt")
	if out := runArca(t, "", "get", "API"); out != "secret" {
		t.Fatalf("get after reencrypt = %q", out)
	}

	if err := runArcaErr("", "recipients", "add", "not-a-key"); err == nil {
		t.Fatal("expected invalid recipient to be rejected")
	}

	// removing every recipient is refused
	all := strings.Fields(runArca(t, "", "recipients"))
	if err := runArcaErr("", append([]string{"recipients", "rm"}, all...)...); err == nil {
		t.Fatal("expected refusal to remove all recipients")
	}

	// removing just rec2 leaves the original
	runArca(t, "", "recipients", "rm", rec2)
	if out := runArca(t, "", "recipients"); strings.Contains(out, rec2) {
		t.Fatalf("rec2 still present after rm: %q", out)
	}
}
