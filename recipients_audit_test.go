package main

import (
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/crypto"
)

// TestRecipientsAddIsAudited covers SEC-44: adding an age recipient grants permanent decryption
// rights to every secret in the store, on every machine the store reaches — and it wrote no audit
// event at all, so the log showed a `reencrypt` with no trace of the key it re-wrapped to. The event
// must name the key, or the log cannot answer "who was added?" during an incident.
func TestRecipientsAddIsAudited(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "topsecret", "set", "API")

	_, rogue, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "recipients", "add", rogue)

	log := runArca(t, "", "log", "--limit", "50")
	if !strings.Contains(log, "recipients-add") {
		t.Fatalf("adding a recipient wrote no recipients-add event:\n%s", log)
	}
	// The key itself must be in the record. An event that says only "a recipient was added" does
	// not let an operator tell an expected teammate key from an attacker's.
	if !strings.Contains(log, rogue) {
		t.Fatalf("recipients-add event does not name the added key %q:\n%s", rogue, log)
	}
}

// TestRecipientsAddAuditsEachKey covers the batch form: `recipients add A B` must record both, not
// one event for the batch — otherwise a second key rides in unrecorded alongside a legitimate one.
func TestRecipientsAddAuditsEachKey(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	_, first, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "recipients", "add", first, second)

	log := runArca(t, "", "log", "--limit", "50")
	for _, want := range []string{first, second} {
		if !strings.Contains(log, want) {
			t.Fatalf("batch add did not audit key %q:\n%s", want, log)
		}
	}
	if n := strings.Count(log, "recipients-add"); n != 2 {
		t.Fatalf("want 2 recipients-add events for a 2-key batch, got %d:\n%s", n, log)
	}
}

// TestRecipientsAddNoOpIsNotAudited guards against the opposite failure: re-adding a key that is
// already present changes nothing, so it must not manufacture an event. A log padded with no-op
// entries is harder to read during an incident, which is when it matters most.
func TestRecipientsAddNoOpIsNotAudited(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	_, key, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "recipients", "add", key)
	runArca(t, "", "recipients", "add", key) // second add is a no-op

	log := runArca(t, "", "log", "--limit", "50")
	if n := strings.Count(log, "recipients-add"); n != 1 {
		t.Fatalf("want exactly 1 recipients-add event after a duplicate add, got %d:\n%s", n, log)
	}
}

// TestRecipientsRelabelIsAudited covers the disguise path. Labels are how an operator recognizes a
// key during review (`who-can-read`, `exposure`, `doctor`), so relabeling an unfamiliar key to
// something trusted-looking defeats exactly that check. The relabel must leave a record even though
// the recipient set itself did not change.
func TestRecipientsRelabelIsAudited(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	_, key, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "recipients", "add", key, "--label", "unknown-key")
	runArca(t, "", "recipients", "add", key, "--label", "isma@laptop") // back-fill a friendlier label

	log := runArca(t, "", "log", "--limit", "50")
	if !strings.Contains(log, "recipients-label") {
		t.Fatalf("relabeling a recipient wrote no recipients-label event:\n%s", log)
	}
	// Re-applying the same label is not a change and should not add noise.
	before := strings.Count(log, "recipients-label")
	runArca(t, "", "recipients", "add", key, "--label", "isma@laptop")
	after := strings.Count(runArca(t, "", "log", "--limit", "50"), "recipients-label")
	if after != before {
		t.Fatalf("re-applying an identical label logged again (%d -> %d)", before, after)
	}
}
