package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestHelperProcess is not a real test: it is the child process the runRedacted tests spawn.
// Driving the test binary itself keeps these tests free of any shell or coreutils dependency,
// so they run identically on Linux, macOS, and Windows.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("ARCA_TEST_HELPER") != "1" {
		return
	}
	switch os.Getenv("ARCA_TEST_HELPER_MODE") {
	case "spew": // emit ARCA_TEST_HELPER_N copies of a 1 KiB block
		n := 0
		fmt.Sscanf(os.Getenv("ARCA_TEST_HELPER_N"), "%d", &n)
		block := bytes.Repeat([]byte("x"), 1024)
		for i := 0; i < n; i++ {
			os.Stdout.Write(block)
		}
	case "sleep": // outlive the deadline
		time.Sleep(60 * time.Second)
	case "leak": // print the injected secret, to prove redaction still runs
		os.Stdout.WriteString("before " + os.Getenv("LEAKY") + " after\n")
	case "exit7":
		os.Exit(7)
	}
	os.Exit(0)
}

// helperCmd returns the command/args/env that re-invoke this test binary as TestHelperProcess.
func helperCmd(mode string, extra ...string) (string, []string, []string) {
	env := append(os.Environ(), "ARCA_TEST_HELPER=1", "ARCA_TEST_HELPER_MODE="+mode)
	env = append(env, extra...)
	return os.Args[0], []string{"-test.run=TestHelperProcess"}, env
}

func TestCapWriter(t *testing.T) {
	tests := []struct {
		name        string
		limit       int
		writes      []string
		wantOut     string
		wantDropped int
	}{
		{"under the limit", 10, []string{"abc"}, "abc", 0},
		{"exactly the limit", 3, []string{"abc"}, "abc", 0},
		{"single write over", 3, []string{"abcdef"}, "abc", 3},
		{"across writes, cut mid-write", 4, []string{"ab", "cdef"}, "abcd", 2},
		{"writes entirely past the cap", 2, []string{"ab", "cd", "ef"}, "ab", 4},
		{"zero limit drops everything", 0, []string{"abc"}, "", 3},
		{"empty write", 5, []string{""}, "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := &capWriter{dst: &buf, limit: tt.limit}
			for _, s := range tt.writes {
				n, err := w.Write([]byte(s))
				if err != nil {
					t.Fatalf("Write(%q) returned error: %v", s, err)
				}
				// The io.Writer contract forbids a short write without an error, and a short
				// write would read as a broken stream to the redactWriter upstream.
				if n != len(s) {
					t.Errorf("Write(%q) = %d, want %d (must always report a full write)", s, n, len(s))
				}
			}
			if got := buf.String(); got != tt.wantOut {
				t.Errorf("captured %q, want %q", got, tt.wantOut)
			}
			if w.dropped != tt.wantDropped {
				t.Errorf("dropped = %d, want %d", w.dropped, tt.wantDropped)
			}
		})
	}
}

// TestCapWriterNeverEmitsPartialSecret is the property Steve required: the cap sits downstream of
// redaction, so truncation can only ever cut bytes that have already been through the redactWriter.
// The adversarial case is a secret split across two Writes (which the redactWriter handles with a
// held-back tail) landing exactly on the cap boundary.
func TestCapWriterNeverEmitsPartialSecret(t *testing.T) {
	const secret = "SUPERSECRETVALUE1234"

	// truncated counts subtests where the cap actually cut something. Without it this test could
	// pass vacuously if redaction or the cap stopped engaging — a green assertion that can no
	// longer fail is worse than no assertion.
	truncated := 0

	// Sweep the split point through the secret and the cap through the region where the secret
	// lands, so every combination of "torn across Writes" and "torn by the cap" is covered.
	for split := 1; split < len(secret); split++ {
		for _, limit := range []int{4, 8, 12, 16, 20, 24, 32} {
			name := fmt.Sprintf("split=%d/limit=%d", split, limit)
			t.Run(name, func(t *testing.T) {
				var buf bytes.Buffer
				cw := &capWriter{dst: &buf, limit: limit}
				rw := newRedactWriter(cw, []redactPattern{
					{name: "S", value: []byte(secret), repl: redactMarker("S")},
				})

				// "AAAA" + secret, with the secret torn across two Writes at `split`.
				if _, err := rw.Write([]byte("AAAA" + secret[:split])); err != nil {
					t.Fatal(err)
				}
				if _, err := rw.Write([]byte(secret[split:] + "ZZZZ")); err != nil {
					t.Fatal(err)
				}
				if err := rw.Flush(); err != nil {
					t.Fatal(err)
				}

				got := buf.String()
				if cw.dropped > 0 {
					truncated++
				}
				if strings.Contains(got, secret) {
					t.Fatalf("full secret leaked into captured output: %q", got)
				}
				// No run of secret bytes long enough to be worth anything may survive. minRedactLen
				// is arca's own threshold for "long enough to be identifiable".
				for i := 0; i+minRedactLen <= len(secret); i++ {
					if frag := secret[i : i+minRedactLen]; strings.Contains(got, frag) {
						t.Fatalf("partial secret %q leaked at the cap boundary: %q", frag, got)
					}
				}
			})
		}
	}

	if truncated == 0 {
		t.Fatal("no subtest actually hit the cap — this test would pass vacuously; widen the sweep")
	}
	t.Logf("%d subtest(s) truncated at the cap with no partial secret emitted", truncated)
}

func TestMCPMaxOutputClamp(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want int
	}{
		{"unset uses the default", "", defaultMCPMaxOutput},
		{"in range is honoured", "65536", 65536},
		{"below the floor clamps up", "1", minMCPMaxOutput},
		{"negative clamps up", "-5", minMCPMaxOutput},
		{"above the ceiling clamps down", "999999999", maxMCPMaxOutput},
		{"unparseable falls back", "lots", defaultMCPMaxOutput},
		{"empty falls back", "", defaultMCPMaxOutput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envMCPMaxOutput, tt.env)
			if got := mcpMaxOutput(); got != tt.want {
				t.Errorf("mcpMaxOutput() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestMCPExecTimeoutClamp(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want time.Duration
	}{
		{"unset uses the default", "", defaultMCPTimeout},
		{"duration in range", "90s", 90 * time.Second},
		{"bare seconds in range", "90", 90 * time.Second},
		{"minutes in range", "2m", 2 * time.Minute},
		{"below the floor clamps up", "10ms", minMCPTimeout},
		{"zero clamps up", "0", minMCPTimeout},
		{"negative clamps up", "-30s", minMCPTimeout},
		{"above the ceiling clamps down", "24h", maxMCPTimeout},
		// The point of clamping rather than honouring: an agent that owns the environment must
		// not be able to spell "no limit".
		{"unbounded spelling clamps down", "999999h", maxMCPTimeout},
		{"unparseable falls back", "forever", defaultMCPTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envMCPTimeout, tt.env)
			if got := mcpExecTimeout(); got != tt.want {
				t.Errorf("mcpExecTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunRedactedCapsOutput(t *testing.T) {
	t.Setenv(envMCPMaxOutput, "8192") // 8 KiB, above the floor so it is honoured verbatim
	cmd, args, env := helperCmd("spew", "ARCA_TEST_HELPER_N=64")

	out, code, err := runRedacted(context.Background(), cmd, args, env, nil)
	if err != nil {
		t.Fatalf("runRedacted: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	// The child wrote 64 KiB; capture must be bounded by the cap plus the truncation notice.
	const notice = "output truncated"
	if !strings.Contains(out, notice) {
		t.Errorf("expected a truncation notice in the output, got %d bytes ending %q", len(out), tail(out, 120))
	}
	if len(out) > 8192+512 {
		t.Errorf("captured %d bytes, want ~8192 plus a short notice — the cap did not hold", len(out))
	}
	if got := strings.Count(out, "x"); got > 8192 {
		t.Errorf("captured %d payload bytes, want <= 8192", got)
	}
}

func TestRunRedactedNoNoticeWhenUnderCap(t *testing.T) {
	t.Setenv(envMCPMaxOutput, "8192")
	cmd, args, env := helperCmd("spew", "ARCA_TEST_HELPER_N=1") // 1 KiB, well under

	out, _, err := runRedacted(context.Background(), cmd, args, env, nil)
	if err != nil {
		t.Fatalf("runRedacted: %v", err)
	}
	if strings.Contains(out, "output truncated") {
		t.Errorf("unexpected truncation notice for output under the cap: %q", tail(out, 120))
	}
	if n := strings.Count(out, "x"); n != 1024 {
		t.Errorf("captured %d payload bytes, want the full 1024", n)
	}
}

func TestRunRedactedTimesOut(t *testing.T) {
	t.Setenv(envMCPTimeout, "1") // clamps to the 1s floor
	cmd, args, env := helperCmd("sleep")

	start := time.Now()
	_, _, err := runRedacted(context.Background(), cmd, args, env, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error, got nil — the child outlived its deadline")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("error = %q, want it to name the deadline", err)
	}
	// The helper sleeps 60s. Allow the 1s deadline plus WaitDelay plus scheduling slack.
	if elapsed > 20*time.Second {
		t.Errorf("runRedacted took %v — the deadline did not actually kill the child", elapsed)
	}
}

// Redaction must still work on the capped path: the cap is an addition, not a replacement.
func TestRunRedactedStillRedactsUnderCap(t *testing.T) {
	const secret = "hunter2-hunter2-hunter2"
	cmd, args, env := helperCmd("leak", "LEAKY="+secret)

	out, _, err := runRedacted(context.Background(), cmd, args, env,
		[]redactPattern{{name: "LEAKY", value: []byte(secret), repl: redactMarker("LEAKY")}})
	if err != nil {
		t.Fatalf("runRedacted: %v", err)
	}
	if strings.Contains(out, secret) {
		t.Fatalf("secret survived redaction: %q", out)
	}
	if !strings.Contains(out, string(redactMarker("LEAKY"))) {
		t.Errorf("expected the redaction marker in %q", out)
	}
}

// A non-zero exit must still be reported, not swallowed by the new error paths.
func TestRunRedactedPreservesExitCode(t *testing.T) {
	cmd, args, env := helperCmd("exit7")
	_, code, err := runRedacted(context.Background(), cmd, args, env, nil)
	if err != nil {
		t.Fatalf("runRedacted: %v", err)
	}
	if code != 7 {
		t.Errorf("exit code = %d, want 7", code)
	}
}

func TestTruncationNotice(t *testing.T) {
	tests := []struct {
		name    string
		dropped []int
		want    bool
	}{
		{"nothing dropped", []int{0, 0}, false},
		{"stdout dropped", []int{10, 0}, true},
		{"stderr dropped", []int{0, 10}, true},
		{"both dropped", []int{3, 4}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			caps := make([]*capWriter, 0, len(tt.dropped))
			for _, d := range tt.dropped {
				caps = append(caps, &capWriter{dropped: d})
			}
			got := truncationNotice(1024, caps...)
			if (got != "") != tt.want {
				t.Errorf("truncationNotice() = %q, want non-empty = %v", got, tt.want)
			}
		})
	}
}

func TestDisableCoreDumps(t *testing.T) {
	if err := disableCoreDumps(); err != nil {
		t.Fatalf("disableCoreDumps: %v", err)
	}
	if runtime.GOOS == "windows" {
		return // no RLIMIT_CORE; the call is a documented no-op
	}
	if cur := coreLimit(t); cur != 0 {
		t.Errorf("RLIMIT_CORE soft limit = %d after disableCoreDumps, want 0", cur)
	}
	// Idempotent: the early return for an already-zero limit must not error.
	if err := disableCoreDumps(); err != nil {
		t.Fatalf("second disableCoreDumps: %v", err)
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
