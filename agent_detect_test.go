package main

import "testing"

// TestDetectIdentityAgents covers the agent-detection table: each built-in agent is recognized by
// its runtime marker, an operator can register a custom marker via ARCA_AGENT_MARKERS, any agent can
// self-identify via AI_AGENT, and — critically — an API-key variable is NOT mistaken for an agent.
func TestDetectIdentityAgents(t *testing.T) {
	cases := []struct {
		label       string
		env         map[string]string
		wantAgent   string
		wantSession string
	}{
		{"claude-code", map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": "sess-1"}, "claude-code", "sess-1"},
		{"cursor", map[string]string{"CURSOR_TRACE_ID": "trace-1"}, "cursor", "trace-1"},
		{"gemini-cli", map[string]string{"GEMINI_CLI": "1"}, "gemini-cli", ""},
		{"codex-sandbox", map[string]string{"CODEX_SANDBOX": "seatbelt"}, "codex", ""},
		{"codex-net", map[string]string{"CODEX_SANDBOX_NETWORK_DISABLED": "1"}, "codex", ""},
		{"ai-agent-fallback", map[string]string{"AI_AGENT": "opencode_0-3-1_agent"}, "opencode", ""},
		{"custom-marker", map[string]string{"ARCA_AGENT_MARKERS": "kimi=KIMI_CODE_HOME", "KIMI_CODE_HOME": "/x"}, "kimi", ""},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			sandbox(t) // clears every agent marker first
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			id := detectIdentity()
			if id.Agent != tc.wantAgent {
				t.Fatalf("agent = %q, want %q", id.Agent, tc.wantAgent)
			}
			if tc.wantSession != "" && id.Session != tc.wantSession {
				t.Fatalf("session = %q, want %q", id.Session, tc.wantSession)
			}
		})
	}

	// AI_AGENT carries an optional version (name_version_agent, '-' for '.').
	t.Run("ai-agent-version", func(t *testing.T) {
		sandbox(t)
		t.Setenv("AI_AGENT", "kimi_1-2-3_agent")
		if id := detectIdentity(); id.Agent != "kimi" || id.Version != "1.2.3" {
			t.Fatalf("AI_AGENT parse = %q/%q, want kimi/1.2.3", id.Agent, id.Version)
		}
	})

	// An API-key variable must never be read as an agent marker — countless non-agent scripts set
	// these, and misclassifying them would wrongly apply the advisory agent restrictions.
	t.Run("no-false-positive-on-api-keys", func(t *testing.T) {
		sandbox(t)
		t.Setenv("OPENAI_API_KEY", "sk-x")
		t.Setenv("GEMINI_API_KEY", "x")
		t.Setenv("ANTHROPIC_API_KEY", "x")
		if id := detectIdentity(); id.Agent != "" {
			t.Fatalf("API-key vars must not mark an agent, got %q", id.Agent)
		}
	})

	// A built-in signature wins over a custom marker that also matches.
	t.Run("builtin-precedence", func(t *testing.T) {
		sandbox(t)
		t.Setenv("ARCA_AGENT_MARKERS", "mine=CLAUDECODE")
		t.Setenv("CLAUDECODE", "1")
		if id := detectIdentity(); id.Agent != "claude-code" {
			t.Fatalf("built-in should win, got %q", id.Agent)
		}
	})
}
