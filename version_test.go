package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestVersionCommand covers the `version` subcommand in both human and --json forms. It needs no
// store, so it doubles as a smoke test that the command tree wires up.
func TestVersionCommand(t *testing.T) {
	sandbox(t)

	out := runArca(t, "", "version")
	if !strings.Contains(out, "arca ") || !strings.Contains(out, "platform:") || !strings.Contains(out, "go:") {
		t.Fatalf("version output missing fields: %q", out)
	}

	var v versionView
	if err := json.Unmarshal([]byte(runArca(t, "", "version", "--json")), &v); err != nil {
		t.Fatalf("version --json not valid JSON: %v", err)
	}
	if v.Version == "" || v.Go == "" || v.Platform == "" {
		t.Fatalf("version --json missing required fields: %+v", v)
	}
}

// TestFormatVersion covers the human formatter directly, including the commit-truncation and the
// present/absent commit+date branches that a `go build` in CI may not embed.
func TestFormatVersion(t *testing.T) {
	full := formatVersion(versionView{
		Version: "v1.2.3", Commit: "abcdef0123456789", Date: "2026-07-01T00:00:00Z",
		Go: "go1.26", Platform: "darwin/arm64",
	})
	if !strings.Contains(full, "arca v1.2.3") || !strings.Contains(full, "commit:   abcdef012345") ||
		!strings.Contains(full, "built:    2026-07-01") || strings.Contains(full, "abcdef0123456789") {
		t.Fatalf("full stamp wrong: %q", full)
	}
	bare := formatVersion(versionView{Version: "dev", Go: "go1.26", Platform: "linux/amd64"})
	if strings.Contains(bare, "commit:") || strings.Contains(bare, "built:") {
		t.Fatalf("bare stamp should omit commit/date: %q", bare)
	}
}
