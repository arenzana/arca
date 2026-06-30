package main

import (
	"strings"
	"testing"
)

func TestRandomSecret(t *testing.T) {
	s, err := randomSecret(32, charsetAlnum)
	if err != nil || len(s) != 32 {
		t.Fatalf("randomSecret = %q, %v", s, err)
	}
	for _, c := range s {
		if !strings.ContainsRune(charsetAlnum, c) {
			t.Fatalf("char %q not in alphabet", c)
		}
	}
	if s2, _ := randomSecret(32, charsetAlnum); s == s2 {
		t.Fatal("two random secrets are identical")
	}
	if _, err := randomSecret(0, charsetAlnum); err == nil {
		t.Fatal("expected an error for length 0")
	}
	if _, err := randomSecret(8, "x"); err == nil {
		t.Fatal("expected an error for a 1-character charset")
	}
}

func TestResolveCharset(t *testing.T) {
	if resolveCharset("hex") != charsetHex || resolveCharset("alnum") != charsetAlnum ||
		resolveCharset("full") != charsetFull || resolveCharset("custom123") != "custom123" {
		t.Fatal("charset resolution mismatch")
	}
}

func TestGenerateCommand(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")

	runArca(t, "", "generate", "API", "--length", "20", "--tag", "demo")
	if out := runArca(t, "", "get", "API"); len(out) != 20 {
		t.Fatalf("generated value length = %d, want 20", len(out))
	}
	if out := runArca(t, "", "show", "API"); !strings.Contains(out, "demo") {
		t.Fatalf("show = %q", out)
	}

	// --show prints the value (hex charset → 10 hex chars)
	if v := strings.TrimSpace(runArca(t, "", "generate", "TOK", "--length", "10", "--charset", "hex", "--show")); len(v) != 10 {
		t.Fatalf("--show value = %q", v)
	}

	// invalid name is rejected; a no-print generated secret can't be revealed with get
	if err := runArcaErr("", "generate", "bad-name"); err == nil {
		t.Fatal("expected an invalid name to be rejected")
	}
	runArca(t, "", "generate", "SECRET", "--no-print")
	if err := runArcaErr("", "get", "SECRET"); err == nil {
		t.Fatal("expected a --no-print generated secret to refuse get")
	}

	// --ttl and --require-approval are applied
	runArca(t, "", "generate", "EPH", "--ttl", "1h", "--require-approval")
	if out := runArca(t, "", "show", "EPH"); !strings.Contains(out, "expires") || !strings.Contains(out, "requires approval") {
		t.Fatalf("show EPH = %q", out)
	}
	// a bad --ttl is rejected
	if err := runArcaErr("", "generate", "BAD", "--ttl", "nope"); err == nil {
		t.Fatal("expected a bad --ttl to fail")
	}
}

func TestAppVersion(t *testing.T) {
	old := version
	defer func() { version = old }()
	version = "1.2.3"
	if appVersion() != "1.2.3" {
		t.Fatalf("ldflags version should win, got %s", appVersion())
	}
	version = "dev"
	if appVersion() == "" {
		t.Fatal("appVersion should never be empty")
	}
}
