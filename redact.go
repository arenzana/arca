package main

import (
	"bytes"
	"fmt"
	"io"
	"sort"
)

// Output redaction: when `arca exec` runs a command with secrets injected into its environment,
// the command can still print a secret to its own stdout/stderr — and when an AI agent is the one
// reading that output, the value lands straight in the model's context. The redactWriter sits
// between the child and the real output and replaces any occurrence of an injected secret value
// with a marker, so a leak is caught at the boundary rather than trusted not to happen.

// minRedactLen is the shortest value arca will scan for. A very short value occurs incidentally
// in ordinary output (a 2-char value would redact a large fraction of it), so values shorter than
// this are left alone; exec warns when it skips one.
const minRedactLen = 4

// redactMarker is the default replacement: identifiable (you know which secret leaked) without
// revealing any of the value to whoever reads the output.
func redactMarker(name string) []byte { return []byte("«arca:" + name + "»") }

// partialMarker reveals a few real characters of a long value — the familiar "ab…xyz" dashboard
// convention. It is weaker (it hands those characters to the reader), so it is opt-in and falls
// back to the full marker for values too short to reveal a small fraction of.
func partialMarker(name string, value []byte) []byte {
	const head, tail = 2, 3
	if len(value) < 12 {
		return redactMarker(name)
	}
	out := append([]byte{}, value[:head]...)
	out = append(out, bytes.Repeat([]byte("*"), len(value)-head-tail)...)
	return append(out, value[len(value)-tail:]...)
}

// redactPattern is one secret to look for and what to write in its place.
type redactPattern struct {
	name  string
	value []byte
	repl  []byte
}

// redactWriter replaces secret values in a byte stream before passing it to dst. It holds back a
// tail of up to (maxLen-1) bytes between writes so a value split across two writes is still
// matched; Flush emits whatever remains once the stream ends.
//
// A redactWriter is written by a single goroutine (os/exec drives one per stream), so it needs no
// locking; the pattern set it reads is immutable after construction.
type redactWriter struct {
	dst    io.Writer
	pats   []redactPattern // sorted longest value first, so a longer secret wins over a shorter one it contains
	maxLen int
	buf    []byte
	hits   map[string]int // name → occurrences caught, read after the stream closes
}

func newRedactWriter(dst io.Writer, pats []redactPattern) *redactWriter {
	sort.SliceStable(pats, func(i, j int) bool { return len(pats[i].value) > len(pats[j].value) })
	maxLen := 0
	for _, p := range pats {
		if len(p.value) > maxLen {
			maxLen = len(p.value)
		}
	}
	return &redactWriter{dst: dst, pats: pats, maxLen: maxLen, hits: map[string]int{}}
}

func (w *redactWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	out, keep := w.scan(w.buf, false)
	w.buf = keep
	if len(out) > 0 {
		if _, err := w.dst.Write(out); err != nil {
			return len(p), err
		}
	}
	return len(p), nil
}

// Flush writes any held-back tail, scanning it one final time. Call it once the child has exited.
func (w *redactWriter) Flush() error {
	out, _ := w.scan(w.buf, true)
	w.buf = nil
	if len(out) == 0 {
		return nil
	}
	_, err := w.dst.Write(out)
	return err
}

// scan replaces secret values in buf. With flushAll false it will not *begin* a match within the
// last maxLen-1 bytes — those could be the prefix of a value that completes in a later write — and
// returns them as keep. With flushAll true it processes everything and keep is nil.
func (w *redactWriter) scan(buf []byte, flushAll bool) (out, keep []byte) {
	if w.maxLen == 0 {
		return buf, nil
	}
	limit := len(buf)
	if !flushAll {
		if limit -= w.maxLen - 1; limit < 0 {
			limit = 0
		}
	}
	var sb []byte
	i := 0
	for i < len(buf) {
		if i >= limit {
			break // remaining bytes are a possible partial match; keep them
		}
		if p := w.matchAt(buf, i); p != nil {
			sb = append(sb, p.repl...)
			w.hits[p.name]++
			i += len(p.value)
			continue
		}
		sb = append(sb, buf[i])
		i++
	}
	if flushAll {
		return sb, nil
	}
	return sb, buf[i:]
}

// matchAt returns the pattern whose value starts at buf[i], preferring the longest (pats are
// sorted longest-first), or nil.
func (w *redactWriter) matchAt(buf []byte, i int) *redactPattern {
	for j := range w.pats {
		v := w.pats[j].value
		if i+len(v) <= len(buf) && bytes.Equal(buf[i:i+len(v)], v) {
			return &w.pats[j]
		}
	}
	return nil
}

// buildRedactPatterns turns injected name→value pairs into patterns, skipping values too short to
// scan for safely (reported via warn) and applying the chosen marker style.
func buildRedactPatterns(injected []redactPattern, reveal bool, warn io.Writer) []redactPattern {
	pats := make([]redactPattern, 0, len(injected))
	for _, p := range injected {
		if len(p.value) < minRedactLen {
			fmt.Fprintf(warn, "redact: %q is too short to scan for; its value will not be redacted from output\n", p.name)
			continue
		}
		repl := redactMarker(p.name)
		if reveal {
			repl = partialMarker(p.name, p.value)
		}
		pats = append(pats, redactPattern{name: p.name, value: p.value, repl: repl})
	}
	return pats
}
