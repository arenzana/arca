package main

import (
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/store"
)

// TestSetRefusesEmptyValue is the regression guard for R3, the data-loss bug: `readValue` used to
// return an empty slice with no error, so
//
//	producer-that-failed | arca set PRODKEY
//
// stored an empty value over the real secret and exited 0. The store keeps only the current value,
// so there is no undo and no previous version to roll back to — the secret is simply gone, and the
// success message tells the operator nothing went wrong.
func TestSetRefusesEmptyValue(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "real-token", "set", "PRODKEY")

	err := runArcaErr("", "set", "PRODKEY")
	if err == nil {
		t.Fatal("set with empty stdin must be refused: it would destroy the stored secret")
	}
	// The refusal names the secret and says what it prevented, so a failed pipe is diagnosable
	// from the message alone.
	for _, want := range []string{"PRODKEY", "destroy", "--allow-empty"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not mention %q", err, want)
		}
	}
	if out := runArca(t, "", "get", "PRODKEY"); out != "real-token" {
		t.Fatalf("a refused set damaged the stored value: get = %q, want real-token", out)
	}
}

// TestSetEmptyValueMessageDistinguishesCreateFromReplace pins the two different mistakes apart:
// replacing a stored value with nothing is destructive and unrecoverable, creating an empty secret
// is merely useless. Both are refused, but they do not deserve the same sentence — only one of
// them has already cost the operator something.
func TestSetEmptyValueMessageDistinguishesCreateFromReplace(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "EXISTING")

	replacing := runArcaErr("", "set", "EXISTING")
	creating := runArcaErr("", "set", "BRAND_NEW")
	if replacing == nil || creating == nil {
		t.Fatalf("both empty sets must be refused: replacing=%v creating=%v", replacing, creating)
	}
	if !strings.Contains(replacing.Error(), "destroy") {
		t.Errorf("replacing an existing value should warn about destroying it: %q", replacing)
	}
	if strings.Contains(creating.Error(), "destroy") {
		t.Errorf("creating a new secret destroys nothing; message overstates it: %q", creating)
	}
	// A refused create must not leave a half-made secret behind.
	s, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	if s.Secrets["BRAND_NEW"] != nil {
		t.Fatal("a refused set created the secret anyway")
	}
}

// TestRotateRefusesEmptyValue covers the same failure on the other write path. `rotate` only ever
// replaces — it has already refused a missing secret — so an empty read there is always the
// destructive case.
func TestRotateRefusesEmptyValue(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v1", "set", "TOK")

	err := runArcaErr("", "rotate", "TOK")
	if err == nil {
		t.Fatal("rotate with empty stdin must be refused")
	}
	if !strings.Contains(err.Error(), "destroy") {
		t.Errorf("rotate always replaces, so the refusal should say it would destroy the value: %q", err)
	}
	if out := runArca(t, "", "get", "TOK"); out != "v1" {
		t.Fatalf("a refused rotate damaged the stored value: get = %q, want v1", out)
	}
}

// TestAllowEmptyStoresEmptyValue confirms the escape hatch works on both write paths: an operator
// who means to store nothing says so, and the guard is a speed bump rather than a wall.
func TestAllowEmptyStoresEmptyValue(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "A")
	runArca(t, "v", "set", "B")

	runArca(t, "", "set", "A", "--allow-empty")
	if out := runArca(t, "", "get", "A"); out != "" {
		t.Fatalf("set --allow-empty should store an empty value, got %q", out)
	}
	runArca(t, "", "rotate", "B", "--allow-empty")
	if out := runArca(t, "", "get", "B"); out != "" {
		t.Fatalf("rotate --allow-empty should store an empty value, got %q", out)
	}
}

// TestEmptyValueBoundary pins exactly what counts as empty, because the guard sits behind the
// trailing-newline strip and the boundary is where a data-loss guard is either too loose (a bare
// `echo "" |` still destroys the secret) or too tight (a single space is a legitimate value and
// refusing it would be a new bug).
func TestEmptyValueBoundary(t *testing.T) {
	tests := []struct {
		name        string
		stdin       string
		wantRefused bool
		wantStored  string
	}{
		{"nothing at all", "", true, ""},
		{"bare newline", "\n", true, ""},                           // `echo "" | arca set X`
		{"crlf only", "\r\n", true, ""},                            // the same on Windows
		{"only newlines", "\n\n\n", true, ""},                      // a producer that emitted blank lines
		{"single space", " ", false, " "},                          // whitespace is a value, not an absence
		{"value with trailing newline", "v\n", false, "v"},         // the ordinary `echo v |` case
		{"leading newline kept", "\nv", false, "\nv"},              // only trailing newlines are stripped
		{"multi-line secret", "-----\nkey\n", false, "-----\nkey"}, // PEM shape round-trips
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sandbox(t)
			runArca(t, "", "init")
			runArca(t, "original", "set", "K")

			err := runArcaErr(tc.stdin, "set", "K")
			if tc.wantRefused {
				if err == nil {
					t.Fatalf("stdin %q should have been refused as empty", tc.stdin)
				}
				if out := runArca(t, "", "get", "K"); out != "original" {
					t.Fatalf("a refused set damaged the stored value: get = %q", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("stdin %q is a real value and must be stored: %v", tc.stdin, err)
			}
			if out := runArca(t, "", "get", "K"); out != tc.wantStored {
				t.Fatalf("get = %q, want %q", out, tc.wantStored)
			}
		})
	}
}

// TestImportSkipsEmptyOverwrite covers the third way an empty value reaches the store. `import
// --overwrite` reads its values from a file rather than stdin, so it does not go through
// readValue, but `KEY=` over an existing secret destroys it exactly the same way.
//
// The asymmetry is deliberate and is what this test pins: a bare `KEY=` is an ordinary line in a
// real .env file, so creating an empty secret from one stays allowed. Only the overwriting case —
// the one that loses something — is skipped.
func TestImportSkipsEmptyOverwrite(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "real-token", "set", "KEEP")

	runArca(t, "KEEP=\nFRESH=\n", "import", "--overwrite")
	if out := runArca(t, "", "get", "KEEP"); out != "real-token" {
		t.Fatalf("import overwrote a stored secret with an empty value: get = %q, want real-token", out)
	}
	// The new-secret half of the same import is unaffected: nothing was lost, so nothing is refused.
	s, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	if s.Secrets["FRESH"] == nil {
		t.Fatal("import skipped a new empty secret; only the destructive overwrite should be skipped")
	}

	// ...and the operator who means it can still say so.
	runArca(t, "KEEP=\n", "import", "--overwrite", "--allow-empty")
	if out := runArca(t, "", "get", "KEEP"); out != "" {
		t.Fatalf("import --allow-empty should have replaced the value, got %q", out)
	}
}
