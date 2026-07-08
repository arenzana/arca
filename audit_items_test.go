package main

import (
	"strings"
	"testing"
)

// TestStrictAuditAgentAware confirms an agent cannot opt out of fail-closed auditing.
func TestStrictAuditAgentAware(t *testing.T) {
	t.Setenv("ARCA_STRICT_AUDIT", "0")
	for _, k := range []string{"CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "CURSOR_TRACE_ID", "AI_AGENT"} {
		t.Setenv(k, "")
	}
	withTTYResponse(t, "")
	if strictAudit() {
		t.Fatal("a non-agent caller at a terminal with ARCA_STRICT_AUDIT=0 should be best-effort")
	}
	t.Setenv("AI_AGENT", "claude-code")
	if !strictAudit() {
		t.Fatal("an agent must stay fail-closed regardless of ARCA_STRICT_AUDIT")
	}
}

// TestReadAllLimited confirms the stdin size guard errors instead of truncating.
func TestReadAllLimited(t *testing.T) {
	if _, err := readAllLimited(strings.NewReader("0123456789"), 5); err == nil {
		t.Fatal("expected an over-limit read to error")
	}
	b, err := readAllLimited(strings.NewReader("hello"), maxInputBytes)
	if err != nil || string(b) != "hello" {
		t.Fatalf("readAllLimited = %q, %v", b, err)
	}
}
