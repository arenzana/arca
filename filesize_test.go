package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// maxFileLines is a ratchet, not a target.
//
// main.go reached 2374 lines holding ten unrelated jobs — version stamping, root wiring, XDG
// paths, rollback detection, audit plumbing, identity detection, input helpers, name validation,
// the access-control gate and every command constructor — and nothing failed while it happened.
// That is the point: unbounded growth has no symptom until someone goes looking.
//
// 1000 clears today's largest file with room to spare, so this does not fire on ordinary work. It
// fires when a file is on its way to becoming the next main.go. The remedy is never to raise the
// number: it is to split the file, which is what the number exists to prompt.
const maxFileLines = 1000

// TestNoFileGrowsUnbounded walks the module and fails on any Go source file past the limit.
//
// Tests are included. A test file that long is usually several unrelated suites sharing a name,
// which is the same failure this guards against and is no less worth splitting.
func TestNoFileGrowsUnbounded(t *testing.T) {
	var oversized []string
	checked := 0

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Vendored or generated trees are not ours to split.
			if name := d.Name(); name == ".git" || name == "vendor" || name == "dist" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path) //#nosec G304 -- walking the module's own sources
		if err != nil {
			return err
		}
		checked++
		if n := bytes.Count(b, []byte{'\n'}); n > maxFileLines {
			oversized = append(oversized, path+": "+itoa(n)+" lines")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("walked the module and found no Go files; this test would pass vacuously")
	}
	if len(oversized) > 0 {
		t.Fatalf("these files are past the %d-line limit:\n  %s\n\n"+
			"Split them rather than raising maxFileLines. The limit exists because main.go grew to "+
			"2374 lines without anything failing, and raising it is how that happens again.",
			maxFileLines, strings.Join(oversized, "\n  "))
	}
}

// itoa avoids pulling strconv in for one call site in a guard test.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
