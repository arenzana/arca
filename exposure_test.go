package main

import (
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/store"
)

func TestLooksSensitive(t *testing.T) {
	cases := []struct {
		name string
		tags []string
		desc string
		want bool
	}{
		{"B2_ACCOUNT_KEY", nil, "", true},
		{"GITHUB_ADMIN_TOKEN", nil, "", true},
		{"root_password", nil, "", true},
		{"STRIPE_SECRET_KEY", nil, "", true},
		{"some_key", []string{"master"}, "", true},
		{"innocuous", nil, "the account master key for B2", true},
		{"DB_PASSWORD", nil, "app db password", false},
		{"BSKY_APP_PASSWORD", nil, "", false},
		{"MAILGUN_SMTP_PASSWORD", nil, "outbound email", false},
	}
	for _, c := range cases {
		if got := looksSensitive(c.name, c.tags, c.desc); got != c.want {
			t.Errorf("looksSensitive(%q, %v, %q) = %v, want %v", c.name, c.tags, c.desc, got, c.want)
		}
	}
}

func TestStoreLabel(t *testing.T) {
	s := store.New("", []string{"age1aaa", "age1bbb"})
	if got := s.Label("age1aaa"); got != "" { // nil-map safe, empty by default
		t.Fatalf("unset label = %q, want empty", got)
	}
	s.SetLabel("age1aaa", "alice@laptop")
	if got := s.Label("age1aaa"); got != "alice@laptop" {
		t.Fatalf("label = %q, want alice@laptop", got)
	}
	s.SetLabel("age1aaa", "") // clearing removes it
	if got := s.Label("age1aaa"); got != "" {
		t.Fatalf("cleared label = %q, want empty", got)
	}
}

func TestWhoCanReadAndLabels(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "s3cret", "set", "B2_MASTER_KEY")
	runArca(t, "ok", "set", "DB_PASSWORD")

	r := strings.Fields(runArca(t, "", "recipients"))[0] // the local recipient pubkey

	// Store-wide readership before any label: shows the recipient + (you) + the unlabeled hint.
	out := runArca(t, "", "who-can-read")
	for _, want := range []string{r, "(you)", "unlabeled"} {
		if !strings.Contains(out, want) {
			t.Fatalf("who-can-read missing %q:\n%s", want, out)
		}
	}

	// Back-fill a label onto the already-present recipient, then it must appear.
	runArca(t, "", "recipients", "add", r, "--label", "isma@mac")
	out = runArca(t, "", "who-can-read")
	if !strings.Contains(out, "isma@mac") {
		t.Fatalf("who-can-read did not pick up the label:\n%s", out)
	}

	// Per-secret framing flags a high-privilege name.
	out = runArca(t, "", "who-can-read", "B2_MASTER_KEY")
	if !strings.Contains(out, "B2_MASTER_KEY") || !strings.Contains(out, "high-privilege") {
		t.Fatalf("per-secret who-can-read missing name/flag:\n%s", out)
	}
	// A benign secret is not flagged.
	if out = runArca(t, "", "who-can-read", "DB_PASSWORD"); strings.Contains(out, "high-privilege") {
		t.Fatalf("DB_PASSWORD should not be flagged high-privilege:\n%s", out)
	}
	// Unknown secret errors.
	if err := runArcaErr("", "who-can-read", "NOPE"); err == nil {
		t.Fatal("who-can-read on a missing secret should error")
	}
}

func TestExposure(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "s3cret", "set", "B2_MASTER_KEY")
	runArca(t, "ok", "set", "DB_PASSWORD")

	out := runArca(t, "", "exposure")
	if !strings.Contains(out, "B2_MASTER_KEY") || !strings.Contains(out, "DB_PASSWORD") {
		t.Fatalf("exposure missing secrets:\n%s", out)
	}
	// The sensitive one carries the flag; sort puts it first.
	if !strings.Contains(out, "high-privilege") {
		t.Fatalf("exposure did not flag the sensitive secret:\n%s", out)
	}
	iMaster := strings.Index(out, "B2_MASTER_KEY")
	iDB := strings.Index(out, "DB_PASSWORD")
	if iMaster > iDB {
		t.Fatalf("sensitive secret should sort first:\n%s", out)
	}

	// --sensitive filters to flagged secrets only.
	out = runArca(t, "", "exposure", "--sensitive")
	if !strings.Contains(out, "B2_MASTER_KEY") || strings.Contains(out, "DB_PASSWORD") {
		t.Fatalf("--sensitive should show only flagged secrets:\n%s", out)
	}
}

func TestRecipientRmDropsLabel(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	// add a second labeled recipient, then remove it — its label must be gone.
	_, extra, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	runArca(t, "", "recipients", "add", extra, "--label", "teammate@box")
	if out := runArca(t, "", "recipients"); !strings.Contains(out, "teammate@box") {
		t.Fatalf("label not shown after add:\n%s", out)
	}
	runArca(t, "", "recipients", "rm", extra)
	if out := runArca(t, "", "recipients"); strings.Contains(out, "teammate@box") || strings.Contains(out, extra) {
		t.Fatalf("recipient/label should be gone after rm:\n%s", out)
	}
}
