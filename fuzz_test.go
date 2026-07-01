package main

import (
	"io"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// FuzzShellQuote is the authoritative eval-safety check: a value quoted by shellQuote (used by
// `arca env` for `eval "$(arca env)"`) must, when evaluated by a real shell, round-trip to exactly
// the original — so a value containing quotes, `$()`, backticks, `;`, `|`, etc. can never inject.
func FuzzShellQuote(f *testing.F) {
	if _, err := exec.LookPath("sh"); err != nil {
		f.Skip("needs sh")
	}
	for _, s := range []string{"", "plain", "a'b", "$(id)", "`id`", "a;b|c&d", "; rm -rf /", "a\nb", "\\", `'\''`, "a\"b", "${HOME}"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 || strings.IndexByte(s, 0) >= 0 {
			return // shell arguments cannot carry NUL, and huge inputs aren't the point
		}
		out, err := exec.Command("sh", "-c", "printf %s "+shellQuote(s)).Output() //#nosec G204 -- shellQuote is exactly what's under test
		if err != nil {
			t.Fatalf("sh rejected quoted %q (from %q): %v", shellQuote(s), s, err)
		}
		if string(out) != s {
			t.Fatalf("shellQuote(%q) eval'd to %q — not a faithful round-trip", s, out)
		}
	})
}

// FuzzGlobMatch checks the command-pattern matcher never panics and always agrees with a
// regexp reference (glob where only '*' is special).
func FuzzGlobMatch(f *testing.F) {
	for _, p := range []string{"terraform *", "a*b*c", "*", "exact", "", "kubectl * pods", "*x"} {
		f.Add(p, "terraform apply")
	}
	f.Fuzz(func(t *testing.T, pattern, s string) {
		got := globMatch(pattern, s)
		parts := strings.Split(pattern, "*")
		for i := range parts {
			parts[i] = regexp.QuoteMeta(parts[i])
		}
		re, err := regexp.Compile("^" + strings.Join(parts, ".*") + "$")
		if err != nil {
			return
		}
		if want := re.MatchString(s); got != want {
			t.Fatalf("globMatch(%q, %q) = %v; regexp reference = %v", pattern, s, got, want)
		}
	})
}

// FuzzValidName ensures name validation never panics and that an accepted name really matches the
// safe identifier grammar (defense against shell/env injection via secret names).
func FuzzValidName(f *testing.F) {
	safe := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	for _, n := range []string{"OK", "bad-name", "", "1abc", "A_B_9", "a b", "a;b", "LD_PRELOAD"} {
		f.Add(n)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if validName(name) == nil && !safe.MatchString(name) {
			t.Fatalf("validName accepted %q, which is not a safe identifier", name)
		}
	})
}

// FuzzParseTTL / FuzzParseRate: the duration/rate parsers must never panic on arbitrary input.
func FuzzParseTTL(f *testing.F) {
	for _, s := range []string{"1h", "30m", "7d", "2w", "", "abc", "-5m", "999999999999999h"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = parseTTL(s) })
}

func FuzzParseRate(f *testing.F) {
	for _, s := range []string{"10/1h", "", "0/1h", "abc/1h", "5/x", "-1/1h", "1/1/1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, w, err := parseRate(s)
		if err == nil && (n <= 0 || w == "") {
			t.Fatalf("parseRate(%q) returned ok with n=%d w=%q", s, n, w)
		}
	})
}

// FuzzImportDotenv / FuzzImportJSON: the import parsers must never panic and must never surface a
// name that isn't a safe identifier (which could inject downstream).
func FuzzImportDotenv(f *testing.F) {
	safe := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	f.Add("A=1\nexport B=\"2\"\n# c\nbad-name=x\n")
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 64<<10 { // large-input performance is bounded by the 16 MiB read cap, not here
			return
		}
		pairs, err := parseDotenvSecrets(strings.NewReader(data))
		if err != nil {
			return
		}
		for _, p := range pairs {
			if !safe.MatchString(p.key) {
				t.Fatalf("dotenv import surfaced unsafe name %q", p.key)
			}
		}
	})
}

func FuzzImportJSON(f *testing.F) {
	safe := regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	f.Add(`{"A":"1","B":2,"bad-name":"x"}`)
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 64<<10 { // large-input performance is bounded by the 16 MiB read cap, not here
			return
		}
		pairs, err := parseJSONSecrets(strings.NewReader(data))
		if err != nil {
			return
		}
		for _, p := range pairs {
			if !safe.MatchString(p.key) {
				t.Fatalf("JSON import surfaced unsafe name %q", p.key)
			}
		}
	})
}

// FuzzRedactWriter is the important one: no matter the secret value, the surrounding output, or how
// the stream is chunked, the redactor must never let the raw value survive in its output.
func FuzzRedactWriter(f *testing.F) {
	f.Add("hunter2secret", "connecting with hunter2secret now", 3)
	f.Add("tok", "x", 1)
	f.Add("sk_live_abcABC123", "sk_live_abcABC123 sk_live_abcABC123", 5)
	f.Fuzz(func(t *testing.T, value, output string, chunk int) {
		if chunk <= 0 {
			chunk = 1
		}
		pats := buildRedactPatterns([]redactPattern{{name: "SECRET", value: []byte(value)}}, false, io.Discard)
		if len(pats) == 0 {
			return // value shorter than the scan floor; not redacted by design
		}
		marker := string(redactMarker("SECRET"))
		if strings.Contains(marker, value) {
			return // degenerate: value is part of the marker itself
		}
		var dst strings.Builder
		w := newRedactWriter(&dst, pats)
		for i := 0; i < len(output); i += chunk {
			end := i + chunk
			if end > len(output) {
				end = len(output)
			}
			if _, err := w.Write([]byte(output[i:end])); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(dst.String(), value) {
			t.Fatalf("redacted output still contains the secret value %q:\n%q", value, dst.String())
		}
	})
}
