package main

import (
	"strings"
	"testing"

	"github.com/arenzana/arca/internal/store"
)

// TestAnnotate covers editing tags/description/meta without touching the value: the value and its
// ciphertext are unchanged, UpdatedAt (which tracks value changes) is preserved, and the metadata
// edits land. It also works on a --no-print secret, which `set` can't re-annotate without the value.
func TestAnnotate(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "topsecret", "set", "API", "--tag", "old", "--desc", "d1", "--no-print")

	before, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	origCipher := before.Secrets["API"].Value
	origUpdated := before.Secrets["API"].UpdatedAt

	runArca(t, "", "annotate", "API",
		"--add-tag", "prod,db", "--rm-tag", "old", "--desc", "d2", "--meta", "owner=team")

	after, err := store.Load(storePath())
	if err != nil {
		t.Fatal(err)
	}
	sec := after.Secrets["API"]
	if sec.Value != origCipher {
		t.Fatal("annotate changed the encrypted value")
	}
	if !sec.UpdatedAt.Equal(origUpdated) {
		t.Fatal("annotate bumped UpdatedAt (which tracks value changes)")
	}
	if sec.Description != "d2" {
		t.Fatalf("description = %q, want d2", sec.Description)
	}
	if contains(sec.Tags, "old") || !contains(sec.Tags, "prod") || !contains(sec.Tags, "db") {
		t.Fatalf("tags = %v, want prod+db, no old", sec.Tags)
	}
	if sec.Meta["owner"] != "team" {
		t.Fatalf("meta = %v, want owner=team", sec.Meta)
	}
	if !sec.NoPrint {
		t.Fatal("annotate dropped the --no-print policy")
	}

	// --tag replaces the whole set; --rm-meta drops a key; --desc "" clears.
	runArca(t, "", "annotate", "API", "--tag", "only", "--rm-meta", "owner", "--desc", "")
	final, _ := store.Load(storePath())
	fsec := final.Secrets["API"]
	if len(fsec.Tags) != 1 || fsec.Tags[0] != "only" {
		t.Fatalf("tags after replace = %v, want [only]", fsec.Tags)
	}
	if _, ok := fsec.Meta["owner"]; ok {
		t.Fatal("rm-meta did not remove the key")
	}
	if fsec.Description != "" {
		t.Fatalf("desc not cleared: %q", fsec.Description)
	}

	// The audit log records an annotate.
	if out := runArca(t, "", "log", "API"); !strings.Contains(out, "annotate") {
		t.Fatalf("annotate not audited: %q", out)
	}
}

// TestAnnotateErrors covers the no-op and missing-secret guards.
func TestAnnotateErrors(t *testing.T) {
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v", "set", "X")

	if err := runArcaErr("", "annotate", "X"); err == nil {
		t.Fatal("annotate with no changes should error")
	}
	if err := runArcaErr("", "annotate", "GHOST", "--desc", "y"); err == nil {
		t.Fatal("annotate of a missing secret should error")
	}
}
