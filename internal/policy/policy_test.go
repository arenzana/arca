package policy

import (
	"testing"
	"time"
)

func TestParseTTLStandardUnits(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"30s":    30 * time.Second,
		"5m":     5 * time.Minute,
		"2h":     2 * time.Hour,
		"1h30m":  90 * time.Minute,
		"500ms":  500 * time.Millisecond,
		"  1h  ": time.Hour, // surrounding whitespace is trimmed
	} {
		got, err := ParseTTL(in)
		if err != nil || got != want {
			t.Errorf("ParseTTL(%q) = %v, %v; want %v, nil", in, got, err, want)
		}
	}
}

// The reason this wraps time.ParseDuration at all: 'd' and 'w' are the units people reach for
// with secrets, and the standard library stops at hours.
func TestParseTTLDayAndWeekSuffixes(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"1d":   24 * time.Hour,
		"7d":   7 * 24 * time.Hour,
		"1w":   7 * 24 * time.Hour,
		"2w":   14 * 24 * time.Hour,
		"0.5d": 12 * time.Hour,
		"0d":   0,
	} {
		got, err := ParseTTL(in)
		if err != nil || got != want {
			t.Errorf("ParseTTL(%q) = %v, %v; want %v, nil", in, got, err, want)
		}
	}
}

func TestParseTTLRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "d", "w", "abc", "1y", "xd", "-", "1.2.3d", "10 d"} {
		if _, err := ParseTTL(in); err == nil {
			t.Errorf("ParseTTL(%q) = nil error, want an error", in)
		}
	}
}

// An empty window means the documented 1h default. This defaulting has to live in exactly one
// place: the path that enforces a rate limit and the path that decides whether changing it needs
// an operator terminal must agree, or the anchor guards a policy the access path never applies.
func TestRateWindowDefaultsToAnHour(t *testing.T) {
	d, s := RateWindow("")
	if d != time.Hour || s != "1h" {
		t.Fatalf("RateWindow(\"\") = %v, %q; want 1h, \"1h\"", d, s)
	}
}

func TestRateWindowPassesThroughValidWindows(t *testing.T) {
	if d, s := RateWindow("2d"); d != 48*time.Hour || s != "2d" {
		t.Fatalf("RateWindow(\"2d\") = %v, %q; want 48h, \"2d\"", d, s)
	}
	if d, s := RateWindow("15m"); d != 15*time.Minute || s != "15m" {
		t.Fatalf("RateWindow(\"15m\") = %v, %q; want 15m, \"15m\"", d, s)
	}
}

// A malformed window can only come from a hand-edited store. Falling back to 1h keeps a bad
// field from disabling the cap entirely, which would turn a corrupted value into no rate limit.
func TestRateWindowFallsBackOnGarbage(t *testing.T) {
	for _, in := range []string{"garbage", "1y", "-"} {
		if d, s := RateWindow(in); d != time.Hour || s != "1h" {
			t.Errorf("RateWindow(%q) = %v, %q; want the 1h fallback", in, d, s)
		}
	}
}

func TestParseRateValid(t *testing.T) {
	for in, want := range map[string]struct {
		n   int
		win string
	}{
		"10/1h":      {10, "1h"},
		"1/30s":      {1, "30s"},
		"100/7d":     {100, "7d"},
		" 5 / 1h ":   {5, "1h"},
		"2/1h30m":    {2, "1h30m"},
		"1000000/1w": {1000000, "1w"},
	} {
		n, win, err := ParseRate(in)
		if err != nil || n != want.n || win != want.win {
			t.Errorf("ParseRate(%q) = %d, %q, %v; want %d, %q, nil", in, n, win, err, want.n, want.win)
		}
	}
}

func TestParseRateRejectsMalformed(t *testing.T) {
	for _, in := range []string{
		"10",     // no window at all
		"",       // empty
		"abc/1h", // non-numeric count
		"0/1h",   // a zero cap would mean "never", which --rate is not for
		"-1/1h",  // negative
		"1.5/1h", // fractional count
		"10/",    // empty window
		"10/1y",  // unparseable window
		"10/abc", // ditto
		"/1h",    // missing count
	} {
		if _, _, err := ParseRate(in); err == nil {
			t.Errorf("ParseRate(%q) = nil error, want an error", in)
		}
	}
}
