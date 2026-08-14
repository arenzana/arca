package main

import (
	"strings"
	"testing"
	"time"

	"github.com/arenzana/arca/internal/store"
)

// expiryFixture gives secrets that expire in a week, plus some with no expiry at all. The
// distinction matters: "no expiry" is the least protected state, not a missing value.
//
// The numbered duplicates exist because every case that is *expected to succeed* mutates its
// target, so no two such cases may share one. Writing this table against a single FOREVER first
// produced a failure that looked like a predicate bug and was not: the preceding row gave FOREVER
// an expiry, after which the next row's clear was a real downgrade and correctly refused. The
// refusal tables can share targets, since a refused case changes nothing.
func expiryFixture(t *testing.T) {
	t.Helper()
	sandbox(t)
	runArca(t, "", "init")
	runArca(t, "v-exp", "set", "EXPIRING", "--ttl", "7d")
	runArca(t, "v-exp2", "set", "EXPIRING2", "--ttl", "7d")
	runArca(t, "v-exp3", "set", "EXPIRING3", "--ttl", "7d")
	runArca(t, "v-exp4", "set", "EXPIRING4", "--ttl", "7d")
	runArca(t, "v-noexp", "set", "FOREVER")
	runArca(t, "v-noexp2", "set", "FOREVER2")
}

func ptr(t time.Time) *time.Time { return &t }

// The unit-level rule, tested directly so the boundary cases do not depend on a terminal.
func TestExpiryDowngradeRule(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	week := now.Add(7 * 24 * time.Hour)

	for _, tc := range []struct {
		name       string
		cur        *store.Secret
		ttl, exact string
		want       bool // is this a downgrade needing an operator?
	}{
		{"extend by ttl", &store.Secret{ExpiresAt: ptr(week)}, "30d", "", true},
		{"extend by absolute date", &store.Secret{ExpiresAt: ptr(week)}, "", "2030-01-01", true},
		{"clear an expiry", &store.Secret{ExpiresAt: ptr(week)}, "", "", true},
		{"shorten by ttl", &store.Secret{ExpiresAt: ptr(week)}, "1d", "", false},
		{"shorten by absolute date", &store.Secret{ExpiresAt: ptr(week)}, "", "2026-06-02", false},
		// A secret that never expires has nothing to relax; setting any expiry only tightens.
		{"set one where there was none", &store.Secret{}, "365d", "", false},
		{"clear when there was none", &store.Secret{}, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := expiryDowngrade(tc.cur, tc.ttl, tc.exact, now)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := d != nil; got != tc.want {
				t.Fatalf("expiryDowngrade = %v, want downgrade=%v", d, tc.want)
			}
		})
	}
}

// Exactly equal is not an extension. Without this the anchor would fire on a no-op rewrite, and a
// prompt on ordinary traffic is what teaches an operator to answer y without reading.
func TestExpiryDowngradeIgnoresAnUnchangedInstant(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	at := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	d, err := expiryDowngrade(&store.Secret{ExpiresAt: ptr(at)}, "", "2027-01-01", now)
	if err != nil {
		t.Fatal(err)
	}
	if d != nil {
		t.Fatalf("rewriting the same expiry is not a downgrade, got %v", d)
	}
}

func TestExpiryDowngradeSurfacesBadFlags(t *testing.T) {
	now := time.Now()
	cur := &store.Secret{ExpiresAt: ptr(now.Add(time.Hour))}
	if _, err := expiryDowngrade(cur, "7d", "2030-01-01", now); err == nil {
		t.Fatal("--ttl and --expires-at together should error before prompting")
	}
	if _, err := expiryDowngrade(cur, "nonsense", "", now); err == nil {
		t.Fatal("an unparseable ttl should error before prompting")
	}
}

// End to end: the load-bearing half. An agent cannot open a terminal that does not exist.
func TestExtendingAnExpiryIsRefusedWithoutTerminal(t *testing.T) {
	expiryFixture(t)
	withNoTTY(t)

	for _, args := range [][]string{
		{"set", "EXPIRING", "--ttl", "365d"},
		{"set", "EXPIRING", "--expires-at", "2030-01-01"},
		{"set", "EXPIRING", "--ttl", ""}, // clearing it entirely
		{"generate", "EXPIRING", "--ttl", "365d"},
		{"rotate", "EXPIRING", "--ttl", "365d"}, // the third command, unanchored until now
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			err := runArcaErr("v-replacement", args...)
			if err == nil {
				t.Fatalf("arca %s extended an expiry with no terminal", strings.Join(args, " "))
			}
			if !strings.Contains(err.Error(), "terminal") {
				t.Fatalf("refusal does not explain the terminal requirement: %v", err)
			}
		})
	}
}

// The no-overshoot half. Tightening, and touching a secret that never expires, must stay headless.
func TestExpiryAnchorDoesNotOverfire(t *testing.T) {
	expiryFixture(t)
	withNoTTY(t)

	for _, tc := range []struct {
		why  string
		args []string
	}{
		{"shortening is tightening", []string{"set", "EXPIRING2", "--ttl", "1h"}},
		{"a secret with no expiry has nothing to relax", []string{"set", "FOREVER", "--ttl", "365d"}},
		{"clearing an expiry that does not exist changes nothing", []string{"set", "FOREVER2", "--ttl", ""}},
		{"a write with no expiry flag at all", []string{"set", "EXPIRING3", "--desc", "note"}},
		{"rotate without touching the expiry", []string{"rotate", "EXPIRING4"}},
	} {
		t.Run(tc.why, func(t *testing.T) {
			if err := runArcaErr("v-replacement", tc.args...); err != nil {
				t.Fatalf("arca %s was refused headless (%s): %v", strings.Join(tc.args, " "), tc.why, err)
			}
		})
	}
}

// The clearing path did not exist before: applyExpiry had no way to remove an expiry, which is
// half of why the residual stayed open. An empty flag now clears, matching `--rate ""`.
func TestEmptyExpiryFlagClearsTheExpiry(t *testing.T) {
	expiryFixture(t)
	withTTYResponse(t, "y")

	if err := runArcaErr("v-replacement", "set", "EXPIRING", "--ttl", ""); err != nil {
		t.Fatalf("an operator should be able to clear an expiry: %v", err)
	}
	if out := runArca(t, "", "show", "EXPIRING"); strings.Contains(out, "EXPIRES") &&
		!strings.Contains(out, "never") && strings.Contains(out, "20") {
		t.Fatalf("the expiry should be gone:\n%s", out)
	}
}

// A flag that is absent must not be read as an empty one, or every re-set would silently drop the
// expiry it was not asked to touch.
func TestOmittingTheFlagPreservesTheExpiry(t *testing.T) {
	expiryFixture(t)
	withNoTTY(t)

	runArca(t, "v-replacement", "set", "EXPIRING", "--desc", "untouched")
	out := runArca(t, "", "show", "--json", "EXPIRING")
	if !strings.Contains(out, "expires_at") {
		t.Fatalf("re-setting without an expiry flag dropped the expiry:\n%s", out)
	}
}
