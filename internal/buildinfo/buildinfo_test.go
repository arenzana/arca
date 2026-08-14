package buildinfo

import (
	"strings"
	"testing"
)

func TestVersionPrefersTheInjectedValue(t *testing.T) {
	if got := Version("1.2.3"); got != "1.2.3" {
		t.Fatalf("Version(\"1.2.3\") = %q, want the injected value", got)
	}
}

// "dev" is the sentinel meaning "nothing was injected", which is when the module version from the
// build info is worth consulting. Under `go test` there is no module version, so this falls all
// the way through and the assertion is that it does so without inventing one.
func TestVersionFallsBackWhenNothingWasInjected(t *testing.T) {
	got := Version("dev")
	if got == "" {
		t.Fatal("Version(\"dev\") returned empty; it should always report something")
	}
	if strings.Contains(got, "(devel)") {
		t.Fatalf("Version should not report Go's placeholder module version, got %q", got)
	}
}

func TestCollectAlwaysFillsToolchainAndPlatform(t *testing.T) {
	s := Collect("1.2.3")
	if s.Version != "1.2.3" {
		t.Fatalf("Version = %q", s.Version)
	}
	if s.Go == "" || s.Platform == "" {
		t.Fatalf("Go and Platform come from the runtime and are never empty: %+v", s)
	}
	if !strings.Contains(s.Platform, "/") {
		t.Fatalf("Platform should be GOOS/GOARCH, got %q", s.Platform)
	}
}

func TestFormatShortensTheCommit(t *testing.T) {
	out := Format(Stamp{
		Version: "1.2.3", Commit: "b83cef6d106e013c4970be4e2e4842722b141e68",
		Date: "2026-08-14T13:55:04Z", Go: "go1.26.6", Platform: "linux/amd64",
	})
	if !strings.Contains(out, "b83cef6d106e") {
		t.Fatalf("expected a 12-char commit:\n%s", out)
	}
	if strings.Contains(out, "b83cef6d106e0") {
		t.Fatalf("commit should be truncated to 12 chars:\n%s", out)
	}
}

// A plain `go build` outside a repository embeds no VCS settings. Printing "commit:" with nothing
// after it reads as a broken build rather than an ordinary one, so those rows are dropped.
func TestFormatOmitsRowsWithNoValue(t *testing.T) {
	out := Format(Stamp{Version: "dev", Go: "go1.26.6", Platform: "linux/amd64"})
	for _, absent := range []string{"commit", "built"} {
		if strings.Contains(out, absent) {
			t.Fatalf("%q should be omitted when empty:\n%s", absent, out)
		}
	}
	for _, present := range []string{"version", "go", "platform", "dev"} {
		if !strings.Contains(out, present) {
			t.Fatalf("%q should always be present:\n%s", present, out)
		}
	}
}

// The label column is measured rather than fixed, so values line up whichever rows are present.
func TestFormatAlignsValues(t *testing.T) {
	out := Format(Stamp{Version: "1.2.3", Commit: "abc123def456", Go: "go1.26.6", Platform: "linux/amd64"})
	var cols []int
	for _, line := range strings.Split(strings.TrimSpace(out), "\n")[1:] {
		cols = append(cols, strings.Index(line, strings.TrimSpace(strings.SplitN(line, ":", 2)[1])))
	}
	for i, c := range cols {
		if c != cols[0] {
			t.Fatalf("row %d starts its value at column %d, want %d:\n%s", i, c, cols[0], out)
		}
	}
}
