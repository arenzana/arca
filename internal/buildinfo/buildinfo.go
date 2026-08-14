// Package buildinfo assembles and renders arca's build stamp: the version, the VCS commit and
// date Go embeds, and the toolchain and platform.
//
// The version string itself deliberately does NOT live here. It is injected at release time with
// `-ldflags "-X main.version=..."`, spelled that way in both .goreleaser.yaml and the Makefile,
// and a `-X` naming a symbol that does not exist does not fail the build: the link simply has no
// effect and the variable keeps its default. Moving the variable and missing one of those two
// call sites would produce releases that build, pass, publish, and report their version as "dev".
//
// So `main` owns the variable and passes it in, and this package owns everything that is a
// function of it. That keeps the fragile part in one obvious place and the testable part here.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Stamp is the full build stamp. Emitted by `arca version`, and by `--json` for scripts and
// agents, so the field names are a public interface: see STABILITY.md.
type Stamp struct {
	Version  string `json:"version"`
	Commit   string `json:"commit,omitempty"`
	Date     string `json:"date,omitempty"`
	Go       string `json:"go"`
	Platform string `json:"platform"`
}

// Version resolves the version to report: the ldflags-injected value for a release build, the
// module version from the build info for a `go install module@version` build, or the fallback.
//
// injected is main's variable. It is a parameter rather than a package-level var here for the
// reason in the package comment: the ldflags path must keep pointing at main.
func Version(injected string) string {
	if injected != "dev" {
		return injected
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return injected
}

// Collect builds the stamp, reading the VCS settings Go embeds at build time. Those are absent
// from a plain `go build` outside a repository, in which case Commit and Date stay empty and the
// renderer omits their rows rather than printing blanks.
func Collect(injected string) Stamp {
	s := Stamp{Version: Version(injected), Go: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, kv := range bi.Settings {
			switch kv.Key {
			case "vcs.revision":
				s.Commit = kv.Value
			case "vcs.time":
				s.Date = kv.Value
			}
		}
	}
	return s
}

// Format renders the stamp for humans as an aligned key/value table. The commit is short-hashed
// to 12 characters, and the commit/date rows are omitted when the values were not embedded. The
// label column is measured rather than fixed so the values line up whichever rows are present.
func Format(s Stamp) string {
	commit := s.Commit
	if len(commit) > 12 {
		commit = commit[:12]
	}
	rows := [][2]string{{"version", s.Version}}
	if commit != "" {
		rows = append(rows, [2]string{"commit", commit})
	}
	if s.Date != "" {
		rows = append(rows, [2]string{"built", s.Date})
	}
	rows = append(rows, [2]string{"go", s.Go}, [2]string{"platform", s.Platform})

	w := 0
	for _, r := range rows {
		if len(r[0]) > w {
			w = len(r[0])
		}
	}
	var b strings.Builder
	b.WriteString("arca\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "  %-*s  %s\n", w+1, r[0]+":", r[1])
	}
	return b.String()
}
