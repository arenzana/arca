package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestLdflagsTargetAVariableThatExists guards a failure mode that is silent by construction.
//
// The release version is injected with `-ldflags "-X main.version=..."`. The linker does not
// verify that the named symbol exists: a `-X` pointing at a package or variable that has been
// renamed or moved is not an error, it simply has no effect, and the variable keeps its default.
// A release built that way compiles, tests green, publishes, and reports its version as "dev".
//
// Two files carry the spelling, and both were nearly missed when internal/buildinfo was split out.
// This reads them and fails if either names a symbol this package does not actually declare, so
// moving the variable breaks the build here rather than in a published artifact.
func TestLdflagsTargetAVariableThatExists(t *testing.T) {
	re := regexp.MustCompile(`-X\s+([A-Za-z0-9_./-]+)\.([A-Za-z_][A-Za-z0-9_]*)=`)

	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}

	checked := 0
	for _, f := range []string{".goreleaser.yaml", "Makefile"} {
		b, err := os.ReadFile(f) //#nosec G304 -- fixed repo-local paths
		if err != nil {
			t.Fatalf("cannot read %s, which is one of the files that injects the version: %v", f, err)
		}
		matches := re.FindAllStringSubmatch(string(b), -1)
		if len(matches) == 0 {
			t.Errorf("%s no longer contains a -X version injection; if that moved, this guard must follow it", f)
			continue
		}
		for _, m := range matches {
			pkg, sym := m[1], m[2]
			checked++
			if pkg != "main" {
				t.Errorf("%s injects into %q, but this guard only verifies symbols in package main; "+
					"point it at the new package or the injection can silently stop working", f, pkg)
				continue
			}
			// Package-level declaration of that name, which is what -X can actually write to.
			if !regexp.MustCompile(`(?m)^var\s+` + regexp.QuoteMeta(sym) + `\b`).Match(src) {
				t.Errorf("%s injects -X main.%s, but main.go declares no package-level var %q. "+
					"The linker will not complain: the injection silently does nothing and releases "+
					"report the default version.", f, sym, sym)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no -X injections found in either file; this guard would pass vacuously")
	}
}

// The injected value has to actually reach the reported version, not merely exist. This pins the
// wiring between main's variable and the package that formats it.
func TestInjectedVersionReachesTheStamp(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })

	version = "9.9.9-test"
	if got := appVersion(); got != "9.9.9-test" {
		t.Fatalf("appVersion() = %q, want the injected value", got)
	}
	if out := runArca(t, "", "version"); !strings.Contains(out, "9.9.9-test") {
		t.Fatalf("`arca version` did not report the injected value:\n%s", out)
	}
}
