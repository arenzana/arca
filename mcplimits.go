package main

// Resource bounds for the MCP exec path.
//
// `run_with_secrets` / `run_with_handle` let the AI agent choose the command arca runs. Unlike
// `arca exec` — which streams the child's output straight to the operator's stdout and is
// therefore bounded by the terminal — the MCP tools must *capture* the output to return it in
// the tool result. Capturing an agent-chosen command with no ceiling means the agent controls
// arca's memory and arca's lifetime: `yes` or a hung command is a denial of service against
// the very process that is supposed to contain it.
//
// Two bounds close that: a byte cap on what is captured, and a wall-clock deadline on the child.
//
// Both are overridable, and both are CLAMPED to a range rather than honoured verbatim. The
// reasoning matches ARCA_AGENT_STRICT: when the *agent* is the one launching `arca mcp`, the
// agent owns the environment, so a knob that can be set to "unlimited" is not a bound at all —
// it is a documented way to remove one.

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"
)

// Capture cap: how many bytes of a child's (already-redacted) output are kept per stream.
const (
	defaultMCPMaxOutput = 1 << 20  // 1 MiB — generous for a tool result, cheap to hold
	minMCPMaxOutput     = 4 << 10  // 4 KiB — below this even an error message gets cut
	maxMCPMaxOutput     = 16 << 20 // 16 MiB — the ceiling an override cannot pass
)

// Child deadline: how long an agent-invoked command may run before it is killed.
const (
	defaultMCPTimeout = 120 * time.Second
	minMCPTimeout     = 1 * time.Second
	maxMCPTimeout     = 600 * time.Second // generous, but finite: an unbounded knob is not a bound
)

// mcpWaitDelay bounds the window between killing the child and giving up on its output pipes.
// A killed child's own children can inherit and hold those pipes open, which would block Wait
// indefinitely and defeat the deadline we just enforced.
const mcpWaitDelay = 5 * time.Second

// Environment overrides. Both are read per call so a long-lived server picks up nothing
// surprising at start; the clamp is what makes that safe.
const (
	envMCPMaxOutput = "ARCA_MCP_MAX_OUTPUT" // bytes
	envMCPTimeout   = "ARCA_MCP_TIMEOUT"    // Go duration ("90s") or bare seconds ("90")
)

// clampWarnOnce keeps a misconfigured override from printing on every single tool call; the
// operator needs to see it once, not once per invocation.
var clampWarnOnce sync.Map // env var name → struct{}

// warnClamped reports, at most once per env var per process, that an override was clamped.
// stderr is safe here: the MCP JSON-RPC channel is stdout, never stderr.
func warnClamped(env, raw string, applied any) {
	if _, loaded := clampWarnOnce.LoadOrStore(env, struct{}{}); loaded {
		return
	}
	fmt.Fprintf(os.Stderr, "arca mcp: %s=%q is outside the permitted range; using %v instead\n", env, raw, applied)
}

// mcpMaxOutput is the per-stream capture cap in bytes, clamped to [minMCPMaxOutput, maxMCPMaxOutput].
// An unset, empty, or unparseable value yields the default.
func mcpMaxOutput() int {
	raw := os.Getenv(envMCPMaxOutput)
	if raw == "" {
		return defaultMCPMaxOutput
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		warnClamped(envMCPMaxOutput, raw, defaultMCPMaxOutput)
		return defaultMCPMaxOutput
	}
	switch {
	case n < minMCPMaxOutput:
		warnClamped(envMCPMaxOutput, raw, minMCPMaxOutput)
		return minMCPMaxOutput
	case n > maxMCPMaxOutput:
		warnClamped(envMCPMaxOutput, raw, maxMCPMaxOutput)
		return maxMCPMaxOutput
	}
	return n
}

// mcpExecTimeout is the child's wall-clock deadline, clamped to [minMCPTimeout, maxMCPTimeout].
// It accepts a Go duration ("90s", "2m") or a bare number of seconds ("90").
func mcpExecTimeout() time.Duration {
	raw := os.Getenv(envMCPTimeout)
	if raw == "" {
		return defaultMCPTimeout
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		secs, serr := strconv.Atoi(raw)
		if serr != nil {
			warnClamped(envMCPTimeout, raw, defaultMCPTimeout)
			return defaultMCPTimeout
		}
		d = time.Duration(secs) * time.Second
	}
	switch {
	case d < minMCPTimeout:
		warnClamped(envMCPTimeout, raw, minMCPTimeout)
		return minMCPTimeout
	case d > maxMCPTimeout:
		warnClamped(envMCPTimeout, raw, maxMCPTimeout)
		return maxMCPTimeout
	}
	return d
}

// maxMCPMessageBytes caps one inbound JSON-RPC line (audit Info: mcp-go's
// ReadString is uncapped). A real request is a few KiB of names and args;
// 16 MiB matches maxMCPMaxOutput and is far past any legitimate call.
const maxMCPMessageBytes = 16 << 20

// cappedLineReader wraps stdin so a single over-long line (no newline within
// the cap) fails the read instead of growing the server's heap unboundedly.
type cappedLineReader struct {
	r   io.Reader
	cur int // bytes seen since the last newline
}

func (c *cappedLineReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	for _, b := range p[:n] {
		if b == '\n' {
			c.cur = 0
			continue
		}
		c.cur++
		if c.cur > maxMCPMessageBytes {
			return 0, fmt.Errorf("mcp: inbound message exceeds the %d-byte limit", maxMCPMessageBytes)
		}
	}
	return n, err
}

// It must sit DOWNSTREAM of the redactWriter, never upstream. redactWriter deliberately holds
// back a tail of up to maxLen-1 bytes so a secret split across two Writes is still matched
// (see redact.go); truncating its *input* would defeat that hold-back and could emit a partial
// secret at the cut. Wrapping its *output* means the cap can only ever discard bytes that have
// already been through redaction.
//
// Write always reports the full length as written and never returns an error for the discarded
// remainder: dropping output past the cap is the intended behaviour, not a failure, and a short
// write would read as a broken stream to the redactWriter upstream.
type capWriter struct {
	dst     io.Writer
	limit   int
	written int
	dropped int
}

func (w *capWriter) Write(p []byte) (int, error) {
	n := len(p)
	room := w.limit - w.written
	if room <= 0 {
		w.dropped += n
		return n, nil
	}
	if len(p) > room {
		w.dropped += len(p) - room
		p = p[:room]
	}
	m, err := w.dst.Write(p)
	w.written += m
	if err != nil {
		return m, err
	}
	return n, nil
}

// truncationNotice describes what a pair of capped streams discarded, or "" if nothing was cut.
// It is appended AFTER redaction and after the cap, so the notice itself is never truncated and
// never scanned as if it were child output.
func truncationNotice(limit int, caps ...*capWriter) string {
	dropped := 0
	for _, c := range caps {
		dropped += c.dropped
	}
	if dropped == 0 {
		return ""
	}
	return fmt.Sprintf("\n[arca: output truncated — %d byte(s) past the %d-byte per-stream limit were discarded (raise with %s, ceiling %d)]",
		dropped, limit, envMCPMaxOutput, maxMCPMaxOutput)
}
