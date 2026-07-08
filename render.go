package main

import (
	"os"
	"regexp"
	"strings"

	"golang.org/x/term"
)

// ANSI styling for arca's palette — no dependencies. Column widths are computed from the *visible*
// text (ANSI escapes stripped) so colored cells still align.
const (
	ansiReset = "\x1b[0m"
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
	fgTeal    = "\x1b[38;2;63;163;155m"
	fgCoral   = "\x1b[38;2;236;139;119m"
	fgGreen   = "\x1b[38;2;95;180;156m"
	fgAmber   = "\x1b[38;2;233;194;107m"
)

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stdoutIsTTY() bool { return term.IsTerminal(int(os.Stdout.Fd())) }

// isCtrl reports whether r is a terminal control character: a C0 control (incl. ESC, CR, BS, TAB,
// newline), DEL, or a C1 control. These are what an attacker uses to move the cursor, overwrite a
// line, set the window title (OSC), clear the screen, or smuggle further escapes.
func isCtrl(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) }

// sanitize strips terminal control characters from untrusted text before it is rendered — secret
// metadata (descriptions, tags, meta), and the audit log's agent/actor/caller/session columns,
// which for a detected agent come from the environment it controls. Without this, running
// `arca ls` / `log` / `show` on a poisoned store (or after an agent set a crafted $ARCA_ACTOR)
// could inject escapes into the operator's terminal — spoofing or hiding audit rows, rewriting the
// display, or setting the title. arca's own colors are applied by paint()/colorOp() to trusted
// strings after this, so intended styling is unaffected.
func sanitize(s string) string {
	if !strings.ContainsFunc(s, isCtrl) {
		return s // common case: nothing to strip, no allocation
	}
	return strings.Map(func(r rune) rune {
		if isCtrl(r) {
			return -1 // drop it
		}
		return r
	}, s)
}

// sanitizeAll sanitizes each string in place and returns the slice, for convenience at call sites
// that build a row of untrusted cells.
func sanitizeAll(cells []string) []string {
	for i, c := range cells {
		cells[i] = sanitize(c)
	}
	return cells
}

// sanitizeJSONBytes strips raw DEL (0x7f) and C1 (U+0080–U+009F) runes from marshaled JSON before
// it is emitted (FU-6). Go's encoder escapes C0 as \u00XX — safe in the byte stream — but DEL and
// C1 pass through raw, so a consumer that prints a decoded field (or pipes through `jq -r`) would
// feed live control sequences to the terminal, the exact injection SEC-07 strips from the table
// views. Dropping the runes from the encoded bytes is safe: they can only occur inside string
// values, never in JSON structure.
func sanitizeJSONBytes(b []byte) []byte {
	s := string(b)
	if !strings.ContainsFunc(s, isJSONCtrl) {
		return b // common case: nothing to strip, no extra allocation
	}
	return []byte(strings.Map(func(r rune) rune {
		if isJSONCtrl(r) {
			return -1
		}
		return r
	}, s))
}

// isJSONCtrl matches the control runes that survive Go's JSON encoding unescaped.
func isJSONCtrl(r rune) bool { return r == 0x7f || (r >= 0x80 && r <= 0x9f) }

// paint wraps text in an ANSI color.
func paint(code, s string) string { return code + s + ansiReset }

// visibleLen is the display width of s with ANSI escapes removed.
func visibleLen(s string) int { return len([]rune(ansiRe.ReplaceAllString(s, ""))) }

// renderTable prints a styled, aligned table on a terminal, or plain tab-separated columns when the
// output is piped — so scripts and grep still get clean, parseable rows.
func renderTable(headers []string, rows [][]string) {
	if !stdoutIsTTY() {
		plainTable(headers, rows)
		return
	}
	os.Stdout.WriteString(styledTable(headers, rows))
}

// styledTable renders aligned columns with a bold teal header and a dimmed first column (the
// timestamp), no borders — lightweight and dependency-free. Padding is computed from visible width,
// so per-cell ANSI colors don't break alignment.
func styledTable(headers []string, rows [][]string) string {
	n := len(headers)
	widths := make([]int, n)
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i := 0; i < n && i < len(r); i++ {
			if w := visibleLen(r[i]); w > widths[i] {
				widths[i] = w
			}
		}
	}
	const gap = 2
	var b strings.Builder
	// header
	for i, h := range headers {
		b.WriteString(paint(ansiBold+fgTeal, h))
		if i < n-1 {
			b.WriteString(strings.Repeat(" ", widths[i]-len(h)+gap))
		}
	}
	b.WriteByte('\n')
	// rows
	for _, r := range rows {
		for i := 0; i < n; i++ {
			cell := ""
			if i < len(r) {
				cell = r[i]
			}
			vis := visibleLen(cell)
			if i == 0 {
				cell = paint(ansiDim, cell) // dim the timestamp / first column
			}
			b.WriteString(cell)
			if i < n-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-vis+gap))
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func plainTable(headers []string, rows [][]string) {
	// Kept simple and dependency-free: compute widths, pad to align.
	n := len(headers)
	widths := make([]int, n)
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, r := range rows {
		for i := 0; i < n && i < len(r); i++ {
			if len(r[i]) > widths[i] {
				widths[i] = len(r[i])
			}
		}
	}
	const gap = 2
	print := func(cells []string) {
		for i := 0; i < n; i++ {
			c := ""
			if i < len(cells) {
				c = cells[i]
			}
			os.Stdout.WriteString(c)
			if i < n-1 {
				os.Stdout.WriteString(strings.Repeat(" ", widths[i]-len(c)+gap))
			}
		}
		os.Stdout.WriteString("\n")
	}
	print(headers)
	for _, r := range rows {
		print(r)
	}
}

// colorOp tints an audit op for the styled table — green for a use, amber for a write, coral for
// an alert or removal. It returns the plain op when stdout isn't a terminal, so piped output stays
// unstyled.
func colorOp(op string) string {
	if !stdoutIsTTY() {
		return op
	}
	return styledOp(op)
}

func styledOp(op string) string {
	code := fgTeal
	switch op {
	case "read", "exec", "env", "inject":
		code = fgGreen
	case "set", "rotate", "generate", "import", "grant", "handle-create", "annotate":
		code = fgAmber
	case "canary", "ratelimit", "redact", "rm", "revoke", "handle-revoke":
		code = fgCoral
	}
	return paint(code, op)
}
