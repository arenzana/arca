package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// errWriter fails every write, to check the redactWriter propagates a downstream error.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("downstream boom") }

func TestRedactWriteError(t *testing.T) {
	w := newRedactWriter(errWriter{}, []redactPattern{pat("S", "secret")})
	// More than maxLen bytes, so the writer flushes (and hits the failing dst) rather than only
	// buffering the held-back tail.
	if _, err := w.Write([]byte("plenty of output here to force a flush")); err == nil {
		t.Fatal("a downstream write error should propagate")
	}
	// Flush should also surface the error.
	w2 := newRedactWriter(errWriter{}, []redactPattern{pat("S", "secret")})
	_, _ = w2.Write([]byte("tiny"))
	if err := w2.Flush(); err == nil {
		t.Fatal("Flush should surface a downstream write error")
	}
}

// feed writes the input through a redactWriter in the given chunk sizes and returns the full
// redacted output. Chunking exercises the held-back-tail logic that catches a value split across
// writes.
func feed(t *testing.T, pats []redactPattern, chunk int, input string) (string, *redactWriter) {
	t.Helper()
	var dst bytes.Buffer
	w := newRedactWriter(&dst, pats)
	for i := 0; i < len(input); i += chunk {
		end := i + chunk
		if end > len(input) {
			end = len(input)
		}
		if _, err := w.Write([]byte(input[i:end])); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return dst.String(), w
}

func pat(name, value string) redactPattern {
	return redactPattern{name: name, value: []byte(value), repl: redactMarker(name)}
}

func TestRedactBasic(t *testing.T) {
	pats := []redactPattern{pat("SECRET", "hunter2")}
	want := "user=«arca:SECRET» done"
	// Feed at every chunk size from 1 (byte-by-byte, worst case for boundaries) up to the whole
	// string at once — the output must be identical and the value must never appear.
	for chunk := 1; chunk <= len("user=hunter2 done"); chunk++ {
		got, w := feed(t, []redactPattern{pats[0]}, chunk, "user=hunter2 done")
		if got != want {
			t.Fatalf("chunk=%d: got %q, want %q", chunk, got, want)
		}
		if strings.Contains(got, "hunter2") {
			t.Fatalf("chunk=%d: value leaked: %q", chunk, got)
		}
		if w.hits["SECRET"] != 1 {
			t.Fatalf("chunk=%d: hits=%d, want 1", chunk, w.hits["SECRET"])
		}
	}
}

func TestRedactMultipleOccurrences(t *testing.T) {
	got, w := feed(t, []redactPattern{pat("K", "abcd")}, 3, "abcd-abcd-abcd")
	if got != "«arca:K»-«arca:K»-«arca:K»" {
		t.Fatalf("got %q", got)
	}
	if w.hits["K"] != 3 {
		t.Fatalf("hits=%d, want 3", w.hits["K"])
	}
}

// TestRedactLongestWins checks that when one secret's value contains another, the longer match
// is taken (so "abcdef" isn't redacted as "«A»def").
func TestRedactLongestWins(t *testing.T) {
	pats := []redactPattern{pat("SHORT", "abc"), pat("LONG", "abcdef")}
	got, _ := feed(t, pats, 2, "x abcdef y")
	if got != "x «arca:LONG» y" {
		t.Fatalf("got %q", got)
	}
}

// TestRedactNoMatchPassthrough makes sure ordinary output (including a dangling prefix of a
// secret at the very end) is emitted byte-for-byte.
func TestRedactNoMatchPassthrough(t *testing.T) {
	pats := []redactPattern{pat("SECRET", "hunter2")}
	in := "nothing secret here, just hun" // ends with a prefix of the value that never completes
	got, w := feed(t, pats, 4, in)
	if got != in {
		t.Fatalf("got %q, want unchanged %q", got, in)
	}
	if w.hits["SECRET"] != 0 {
		t.Fatalf("unexpected hit")
	}
}

func TestPartialMarker(t *testing.T) {
	// Long enough to reveal a small fraction: head 2 + stars + tail 3.
	got := string(partialMarker("TOK", []byte("hunter2secret"))) // 13 chars
	if got != "hu********ret" {
		t.Fatalf("partial = %q", got)
	}
	// Too short to reveal safely → falls back to the full marker.
	if got := string(partialMarker("TOK", []byte("short"))); got != "«arca:TOK»" {
		t.Fatalf("short partial = %q, want full marker", got)
	}
}

func TestBuildRedactPatternsSkipsShort(t *testing.T) {
	var warn bytes.Buffer
	in := []redactPattern{{name: "OK", value: []byte("longenough")}, {name: "TINY", value: []byte("ab")}}
	pats := buildRedactPatterns(in, false, &warn)
	if len(pats) != 1 || pats[0].name != "OK" {
		t.Fatalf("expected only OK to be scanned, got %+v", pats)
	}
	if !strings.Contains(warn.String(), "TINY") {
		t.Fatalf("expected a warning naming the skipped short secret, got %q", warn.String())
	}
}
