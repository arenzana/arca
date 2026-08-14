// Package policy parses the values arca's per-secret controls are expressed in: relative
// lifetimes (--ttl) and use caps (--rate).
//
// These are split out because the same string has to mean the same thing in two different places
// that are easy to let drift apart: the path that *enforces* a control, and the path that decides
// whether a change to it needs an operator terminal. A second copy of the rate-window defaulting,
// for instance, would let the anchor guard a policy the access path does not actually apply.
package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseTTL parses a relative duration for --ttl. It extends Go's time.ParseDuration (ns…h) with
// 'd' (days) and 'w' (weeks) suffixes, the units people actually reach for with secrets.
func ParseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if n := len(s); n >= 2 {
		switch s[n-1] {
		case 'd', 'w':
			num, err := strconv.ParseFloat(s[:n-1], 64)
			if err != nil {
				return 0, fmt.Errorf("invalid duration %q", s)
			}
			hours := 24.0
			if s[n-1] == 'w' {
				hours = 24 * 7
			}
			return time.Duration(num * hours * float64(time.Hour)), nil
		}
	}
	return time.ParseDuration(s)
}

// RateWindow resolves a stored rate window to the window actually enforced, returning both the
// duration and the string form used in messages. An empty window means the documented 1h default;
// an unparseable one can only come from a hand-edited store, and falling back to 1h keeps a
// malformed field from disabling the cap entirely.
//
// Callers that compare rate limits (the policy-downgrade anchor) must use this rather than
// re-deriving the default, or the anchor would guard a policy the access path does not apply.
func RateWindow(stored string) (time.Duration, string) {
	winStr := stored
	if winStr == "" {
		winStr = "1h"
	}
	win, err := ParseTTL(winStr)
	if err != nil {
		return time.Hour, "1h"
	}
	return win, winStr
}

// ParseRate parses a "--rate N/DURATION" value (e.g. "10/1h") into a use cap and a window string.
func ParseRate(s string) (int, string, error) {
	n, dur, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return 0, "", fmt.Errorf("rate must look like N/DURATION, e.g. 10/1h")
	}
	count, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil || count <= 0 {
		return 0, "", fmt.Errorf("rate count must be a positive integer (got %q)", strings.TrimSpace(n))
	}
	dur = strings.TrimSpace(dur)
	if _, err := ParseTTL(dur); err != nil {
		return 0, "", fmt.Errorf("rate window %q: %w", dur, err)
	}
	return count, dur, nil
}
