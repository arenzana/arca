package main

import (
	"strings"
	"testing"
	"time"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/store"
)

// mutateStore loads the sandbox store, lets fn edit it, and saves — for setting fields (past
// expiry/rotation) that the CLI would refuse or that need a specific clock.
func mutateStore(t *testing.T, fn func(*store.Store)) {
	t.Helper()
	s, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	fn(s)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
}

// --- recipient labels: persistence & guards -------------------------------

func TestLabelSurvivesReencryptAndReload(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")
	r := strings.Fields(runArca(t, "", "recipients"))[0]
	runArca(t, "", "recipients", "add", r, "--label", "isma@mac")

	// A reencrypt (envelope change) must not disturb metadata like labels.
	runArca(t, "", "reencrypt")
	if out := runArca(t, "", "recipients"); !strings.Contains(out, "isma@mac") {
		t.Fatalf("label lost after reencrypt:\n%s", out)
	}
	// And it must round-trip through a fresh load from disk.
	s, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	if s.Label(r) != "isma@mac" {
		t.Fatalf("label did not persist to disk: %q", s.Label(r))
	}
}

func TestLabelRejectedForMultipleRecipients(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	_, k1, _ := crypto.GenerateIdentity()
	_, k2, _ := crypto.GenerateIdentity()
	if err := runArcaErr("", "recipients", "add", k1, k2, "--label", "both"); err == nil {
		t.Fatal("--label with multiple recipients should be rejected")
	}
}

func TestExposureEmptyStore(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	// No secrets: exposure must not error and the table header still prints.
	if out := runArca(t, "", "exposure"); !strings.Contains(out, "SECRET") {
		t.Fatalf("exposure on an empty store should still print a header:\n%s", out)
	}
}

// --- agent defaults: deeper interactions ----------------------------------

func TestAgentRunWithSecretsStrictAndNoPrint(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "printable", "set", "OK_SECRET")
	runArca(t, "noprintable", "set", "NP_SECRET", "--no-print")
	runArca(t, "", "agent", "allow", "OK_SECRET")
	runArca(t, "", "agent", "allow", "NP_SECRET")
	t.Setenv("ARCA_AGENT_STRICT", "1")

	// An allowed secret injects into run_with_secrets and the command can use it.
	res := call(t, mcpRunWithSecrets, map[string]any{"command": "sh", "args": []any{"-c", "test -n \"$OK_SECRET\""}, "secrets": []any{"OK_SECRET"}})
	if res.IsError {
		t.Fatalf("allowed run_with_secrets should succeed: %s", text(t, res))
	}
	// A --no-print secret that is agent-exposed is still usable via run_with_secrets (use-without-
	// reveal) but refused by read_secret.
	if call(t, mcpRunWithSecrets, map[string]any{"command": "true", "secrets": []any{"NP_SECRET"}}).IsError {
		t.Fatal("an exposed --no-print secret should still be injectable via run_with_secrets")
	}
	rd := call(t, mcpReadSecret, map[string]any{"name": "NP_SECRET"})
	if !rd.IsError || !strings.Contains(text(t, rd), "no-print") {
		t.Fatalf("read_secret on a --no-print secret must be refused, got %q", text(t, rd))
	}
}

func TestAgentExposurePersists(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")
	runArca(t, "", "agent", "allow", "API")
	s, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	if !s.Secrets["API"].AgentExposed {
		t.Fatal("agent_exposed did not persist to disk")
	}
}

func TestWarnAgentExposure(t *testing.T) {
	// Non-strict: loud warning naming the risk and the fix.
	t.Setenv("ARCA_AGENT_STRICT", "")
	mcpStrictFlag = false
	out := captureStderr(t, warnAgentExposure)
	if !strings.Contains(out, "NON-STRICT") || !strings.Contains(out, "--strict") {
		t.Fatalf("non-strict warning missing risk/fix:\n%s", out)
	}
	// Strict: confirms the scoped count.
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "API")
	runArca(t, "", "agent", "allow", "API")
	t.Setenv("ARCA_AGENT_STRICT", "1")
	out = captureStderr(t, warnAgentExposure)
	if !strings.Contains(out, "strict mode") || !strings.Contains(out, "1") {
		t.Fatalf("strict notice missing count:\n%s", out)
	}
}

// captureStderr lives in sync_test.go (it also redirects the sync subsystem's syncLog
// sink); the doctor/safety tests below reuse it.

// --- doctor: deeper checks -------------------------------------------------

func TestDoctorRotationExpiryDisabled(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "ROT")
	runArca(t, "v", "set", "EXP")
	runArca(t, "v", "set", "OFF")
	runArca(t, "", "disable", "OFF")
	past := time.Now().Add(-48 * time.Hour)
	mutateStore(t, func(s *store.Store) {
		s.Secrets["ROT"].RotateAfter = &past
		s.Secrets["EXP"].ExpiresAt = &past
	})
	out, _ := execArca("", "doctor")
	for _, want := range []string{"past their rotate-after", "expired secret", "disabled secret"} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor missing %q:\n%s", want, out)
		}
	}
}

func TestDoctorSyncConfigured(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	t.Setenv("ARCA_SYNC_URL", "s3://bucket/prefix?endpoint=example.com")
	out, _ := execArca("", "doctor")
	if !strings.Contains(out, "sync configured") && !strings.Contains(out, "witness configured") {
		// checkSync OK findings are hidden unless there are none higher; assert via --json instead.
		j, _ := execArca("", "doctor", "--json")
		if !strings.Contains(j, "sync configured") {
			t.Fatalf("sync should be reported configured:\n%s", j)
		}
	}
}

func TestDoctorNoStore(t *testing.T) {
	sandbox(t) // sets ARCA_STORE but we never init → no store on disk
	out, _ := execArca("", "doctor")
	if !strings.Contains(out, "no store") {
		t.Fatalf("doctor should report a missing store gracefully:\n%s", out)
	}
}

func TestDoctorMultiRecipientRaisesSensitive(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "B2_MASTER_KEY")
	_, extra, _ := crypto.GenerateIdentity()
	runArca(t, "", "recipients", "add", extra)
	j, _ := execArca("", "doctor", "--json")
	// With >1 recipient a high-privilege secret is elevated to MED (readable on multiple machines).
	if !strings.Contains(j, `"severity": "MED"`) || !strings.Contains(j, "high-privilege") {
		t.Fatalf("multi-recipient sensitive secret should be MED:\n%s", j)
	}
}
