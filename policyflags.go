// The per-secret policy vocabulary, defined once for every command that writes a value.
//
// `set` and `generate` previously each declared these flags and each applied them, in about forty
// lines that were byte-identical apart from the audit verb. Two copies of a policy surface is not
// a tidiness problem: the copies drift, and here they already had. `--rate`'s help said "empty
// clears it" on `set` and not on `generate` though both clear on empty, and `--meta` and
// `--rotate-after` existed on `set` only, so a generated secret could not carry metadata or a
// rotation date at all. Neither difference was a decision.
//
// It also matters for the anchor. requirePolicyOperator decides whether a change needs an operator
// terminal by comparing the flags against the stored secret; if the set of flags it is told about
// ever diverges from the set a command actually applies, the anchor guards a policy the write path
// does not enforce. Routing both through one struct makes that divergence impossible to express.

package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/policy"
	"github.com/arenzana/arca/internal/store"
)

// policyFlags holds the per-secret controls a write command can set. Zero value is unset
// throughout: every field is applied only when its flag was actually given, so re-running a write
// command without a flag never silently clears the bit it controls.
type policyFlags struct {
	tags        []string
	desc        string
	rotateAfter string
	ttl         string
	expiresAt   string
	meta        map[string]string

	noPrint         bool
	requireApproval bool
	requireGrant    bool
	canary          bool
	rate            string
}

// register declares the vocabulary on a command. Help text lives here so the same flag cannot
// describe itself differently depending on which command you asked.
func (p *policyFlags) register(c *cobra.Command) {
	f := c.Flags()
	f.StringSliceVar(&p.tags, "tag", nil, "tags (repeatable or comma-separated)")
	f.StringVar(&p.desc, "desc", "", "description")
	f.StringVar(&p.rotateAfter, "rotate-after", "", "rotation date (YYYY-MM-DD)")
	f.StringVar(&p.ttl, "ttl", "", "expire after a relative duration (e.g. 30m, 12h, 7d, 2w)")
	f.StringVar(&p.expiresAt, "expires-at", "", "expire at an absolute time (RFC3339 or YYYY-MM-DD)")
	f.StringToStringVar(&p.meta, "meta", nil, "extra metadata key=value (repeatable)")
	f.BoolVar(&p.noPrint, "no-print", false, "exec-only: get/env/inject refuse to reveal it")
	f.BoolVar(&p.requireApproval, "require-approval", false, "require human approval (TTY) before each release")
	f.BoolVar(&p.canary, "canary", false, "mark as a decoy: any use trips an alert and a signed audit event")
	f.BoolVar(&p.requireGrant, "require-grant", false, "usable only via exec/MCP with a matching active grant")
	f.StringVar(&p.rate, "rate", "", "rate limit as N/DURATION (e.g. 10/1h); empty clears it")
}

// anchor runs the T13/R28 control-plane check for a write command. Called before the value is
// read, so a refusal costs nothing: the write is unconditional and would otherwise destroy the
// value on its way to a policy change the caller is not allowed to make.
//
// It exists as a method so the flags handed to the anchor are structurally the same ones apply
// writes. Passing them positionally at each call site is what would let the two drift.
func (p *policyFlags) anchor(cmd *cobra.Command, verb, name string, existing *store.Secret) error {
	return requirePolicyOperator(verb, name, cmd.Flags().Changed, existing,
		p.noPrint, p.requireApproval, p.requireGrant, p.canary, p.rate)
}

// apply writes the flags onto sec, reporting whether the canary designation changed so the caller
// can update the local registry after the store is saved. Ordering and the "only when Changed"
// rule are preserved exactly from the two implementations this replaces.
func (p *policyFlags) apply(cmd *cobra.Command, sec *store.Secret) (canaryChanged bool, err error) {
	if len(p.tags) > 0 {
		sec.Tags = p.tags
	}
	if p.desc != "" {
		sec.Description = p.desc
	}
	if p.rotateAfter != "" {
		t, err := time.Parse("2006-01-02", p.rotateAfter)
		if err != nil {
			return false, fmt.Errorf("rotate-after: %w", err)
		}
		sec.RotateAfter = &t
	}
	if err := applyExpiry(sec, p.ttl, p.expiresAt); err != nil {
		return false, err
	}
	if len(p.meta) > 0 {
		if sec.Meta == nil {
			sec.Meta = map[string]string{}
		}
		for k, v := range p.meta {
			sec.Meta[k] = v
		}
	}
	// Only change a policy bit when its flag was actually given, so re-setting a secret doesn't
	// silently clear the protection it already carries.
	if cmd.Flags().Changed("no-print") {
		sec.NoPrint = p.noPrint
	}
	if cmd.Flags().Changed("require-approval") {
		sec.RequireApproval = p.requireApproval
	}
	canaryChanged = cmd.Flags().Changed("canary")
	if canaryChanged {
		sec.Canary = false // never persist the designation to the (synced) store — SEC-04
	}
	if cmd.Flags().Changed("require-grant") {
		sec.RequireGrant = p.requireGrant
	}
	if cmd.Flags().Changed("rate") {
		if p.rate == "" {
			sec.RateLimit, sec.RateWindow = 0, ""
		} else {
			n, w, err := policy.ParseRate(p.rate)
			if err != nil {
				return false, err
			}
			sec.RateLimit, sec.RateWindow = n, w
		}
	}
	return canaryChanged, nil
}

// syncCanary reconciles the local canary registry with a designation change, after the store has
// been saved. verb only shapes the error message.
func (p *policyFlags) syncCanary(name, verb string) error {
	update := unmarkCanary
	if p.canary {
		update = markCanary
	}
	if err := update(name); err != nil {
		return fmt.Errorf("%s %s but failed to update its canary state: %w", verb, name, err)
	}
	return nil
}
