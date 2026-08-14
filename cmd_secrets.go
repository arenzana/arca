// The per-secret commands: set, get, ls, show, rm, disable and enable.
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/policy"
	"github.com/arenzana/arca/internal/secretname"
	"github.com/arenzana/arca/internal/store"
	"github.com/spf13/cobra"
)

// newSet adds or updates a secret. The value comes from a TTY/stdin (never an arg). On an
// existing secret it preserves CreatedAt and only touches the fields the user supplied.
func newSet() *cobra.Command {
	var tags []string
	var desc, rotate, ttl, expiresAt string
	var meta map[string]string
	var noPrint, requireApproval, canary, requireGrant, allowEmpty bool
	var rate string
	c := &cobra.Command{
		Use:   "set NAME",
		Short: "Add or update a secret (value from TTY or stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := secretname.Validate(name); err != nil {
				return err
			}
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			recips, err := crypto.ParseRecipients(s.Recipients)
			if err != nil {
				return err
			}
			// T13/R28: relaxing the policy on a secret that already exists is a control-plane
			// change wearing a write command's clothes. Anchor it before the value is read, so a
			// refusal costs nothing (the write below is unconditional and would destroy the value
			// on its way to a policy change the caller is not allowed to make).
			if err := requirePolicyOperator("set", name, cmd.Flags().Changed, s.Secrets[name],
				noPrint, requireApproval, requireGrant, canary, rate); err != nil {
				return err
			}
			// Whether this set replaces an existing value decides how bad an empty read is, so
			// look it up before reading rather than after.
			replacing := s.Secrets[name] != nil
			val, err := readValue("Value: ", allowEmpty)
			if err != nil {
				if errors.Is(err, errEmptyValue) {
					return emptyValueError(name, replacing)
				}
				return err
			}
			armored, err := crypto.Encrypt(val, recips)
			if err != nil {
				return err
			}

			now := time.Now().UTC()
			sec := s.Secrets[name]
			if sec == nil { // new secret
				sec = &store.Secret{CreatedAt: now}
				s.Secrets[name] = sec
			}
			sec.Value = armored
			sec.UpdatedAt = now
			if len(tags) > 0 {
				sec.Tags = tags
			}
			if desc != "" {
				sec.Description = desc
			}
			if rotate != "" {
				t, err := time.Parse("2006-01-02", rotate)
				if err != nil {
					return fmt.Errorf("rotate-after: %w", err)
				}
				sec.RotateAfter = &t
			}
			if err := applyExpiry(sec, ttl, expiresAt); err != nil {
				return err
			}
			if len(meta) > 0 {
				if sec.Meta == nil {
					sec.Meta = map[string]string{}
				}
				for k, v := range meta {
					sec.Meta[k] = v
				}
			}
			// Only change the policy when the flag was actually given, so re-setting a secret
			// doesn't silently clear its no-print bit.
			if cmd.Flags().Changed("no-print") {
				sec.NoPrint = noPrint
			}
			if cmd.Flags().Changed("require-approval") {
				sec.RequireApproval = requireApproval
			}
			canaryChanged := cmd.Flags().Changed("canary")
			if canaryChanged {
				sec.Canary = false // never persist the designation to the (synced) store — SEC-04
			}
			if cmd.Flags().Changed("require-grant") {
				sec.RequireGrant = requireGrant
			}
			if cmd.Flags().Changed("rate") {
				if rate == "" {
					sec.RateLimit, sec.RateWindow = 0, ""
				} else {
					n, w, err := policy.ParseRate(rate)
					if err != nil {
						return err
					}
					sec.RateLimit, sec.RateWindow = n, w
				}
			}
			if err := s.Save(); err != nil {
				return err
			}
			if canaryChanged {
				update := unmarkCanary
				if canary {
					update = markCanary
				}
				if err := update(name); err != nil {
					return fmt.Errorf("saved %s but failed to update its canary state: %w", name, err)
				}
			}
			if err := logAudit("set", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "stored %s\n", name)
			return nil
		},
	}
	c.Flags().StringSliceVar(&tags, "tag", nil, "tags (repeatable or comma-separated)")
	c.Flags().StringVar(&desc, "desc", "", "description")
	c.Flags().StringVar(&rotate, "rotate-after", "", "rotation date (YYYY-MM-DD)")
	c.Flags().StringVar(&ttl, "ttl", "", "expire after a relative duration (e.g. 30m, 12h, 7d, 2w)")
	c.Flags().StringVar(&expiresAt, "expires-at", "", "expire at an absolute time (RFC3339 or YYYY-MM-DD)")
	c.Flags().StringToStringVar(&meta, "meta", nil, "extra metadata key=value (repeatable)")
	c.Flags().BoolVar(&noPrint, "no-print", false, "exec-only: get/env/inject refuse to reveal it")
	c.Flags().BoolVar(&requireApproval, "require-approval", false, "require human approval (TTY) before each release")
	c.Flags().BoolVar(&canary, "canary", false, "mark as a decoy: any use trips an alert and a signed audit event")
	c.Flags().BoolVar(&requireGrant, "require-grant", false, "usable only via exec/MCP with a matching active grant")
	c.Flags().StringVar(&rate, "rate", "", "rate limit as N/DURATION (e.g. 10/1h); empty clears it")
	c.Flags().BoolVar(&allowEmpty, "allow-empty", false, "permit storing an empty value (refused by default: an empty read would destroy an existing secret)")
	return c
}

// newGet decrypts and prints one secret. It refuses --no-print secrets (the whole point of
// that flag is that the value must not reach stdout) and records a "read" in the audit log.
func newGet() *cobra.Command {
	var nl, noLog bool
	c := &cobra.Command{
		Use:   "get NAME",
		Short: "Decrypt and print one secret (records a read)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			s, err := openStore()
			if err != nil {
				return err
			}
			sec := s.Secrets[name]
			if sec == nil {
				return fmt.Errorf("no such secret: %s", name)
			}
			if sec.NoPrint {
				return fmt.Errorf("%s is marked --no-print; use `exec` instead", name)
			}
			if err := gate(sec, name, ""); err != nil {
				return err
			}
			ids, err := loadIDs()
			if err != nil {
				return err
			}
			plain, err := crypto.Decrypt(sec.Value, ids)
			if err != nil {
				return fmt.Errorf("decrypt %s: %w", name, err)
			}
			// Log before revealing: under fail-closed auditing, a read that cannot be recorded must
			// not disclose the value. --no-log may suppress the record for a human, but never for an
			// AI agent (which can't suppress its own trail) and never for a rate-limited secret — the
			// audit log IS the rate counter, so honoring --no-log there would let a human bypass the
			// limit by reading in a loop (SEC-12). "Human" is anchored to a controlling terminal,
			// not env-based agent detection, which an agent can scrub (SEC-06).
			human := detectIdentity().Agent == "" && hasControllingTTY()
			if !noLog || !human || sec.RateLimit > 0 {
				if noLog && human && sec.RateLimit > 0 {
					fmt.Fprintf(os.Stderr, "note: --no-log ignored for %s (it is rate-limited)\n", name)
				} else if noLog && !human {
					fmt.Fprintf(os.Stderr, "note: --no-log ignored for %s (no interactive terminal)\n", name)
				}
				if err := logAudit("read", name, ""); err != nil {
					return err
				}
			}
			os.Stdout.Write(plain) // raw, no trailing newline unless -n
			if nl {
				fmt.Println()
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&nl, "newline", "n", false, "append a trailing newline")
	c.Flags().BoolVar(&noLog, "no-log", false, "do not record this read")
	return c
}

// newLs lists secrets and their metadata. It never decrypts; with --reads it joins the audit
// DB for last-read/count, which is why that data lives outside the store.
func newLs() *cobra.Command {
	var tag string
	var reads, jsonOut bool
	c := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List secrets and metadata (no decryption)",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			var a *audit.Log
			if reads || jsonOut { // --json always enriches with last-read when available
				if a, err = audit.Open(auditPath()); err == nil {
					defer a.Close()
				}
			}
			if jsonOut {
				views := []secretView{}
				for _, name := range s.Names() {
					sec := s.Secrets[name]
					if tag != "" && !contains(sec.Tags, tag) {
						continue
					}
					var lr time.Time
					var cnt int
					if a != nil {
						lr, cnt, _ = a.LastRead(name)
					}
					views = append(views, viewOf(name, sec, lr, cnt))
				}
				return emitJSON(views)
			}
			showReads := reads && a != nil
			headers := []string{"NAME", "TAGS", "UPDATED", "DESCRIPTION"}
			if showReads {
				headers = []string{"NAME", "TAGS", "UPDATED", "LAST READ", "READS", "DESCRIPTION"}
			}
			rows := [][]string{}
			for _, name := range s.Names() {
				sec := s.Secrets[name]
				if tag != "" && !contains(sec.Tags, tag) {
					continue
				}
				updated := sec.UpdatedAt.Local().Format("2006-01-02")
				// Flag disabled/expired secrets so they're visible at a glance (e.g. during a leak).
				desc := sec.Description
				if sec.Disabled {
					desc = strings.TrimSpace("[disabled] " + desc)
				} else if sec.Expired(time.Now()) {
					desc = strings.TrimSpace("[expired] " + desc)
				}
				if showReads {
					lr, cnt, _ := a.LastRead(name)
					lrs := "never"
					if !lr.IsZero() {
						lrs = lr.Local().Format("2006-01-02 15:04")
					}
					rows = append(rows, sanitizeAll([]string{name, strings.Join(sec.Tags, ","), updated, lrs, strconv.Itoa(cnt), desc}))
				} else {
					rows = append(rows, sanitizeAll([]string{name, strings.Join(sec.Tags, ","), updated, desc}))
				}
			}
			renderTable(headers, rows)
			return nil
		},
	}
	c.Flags().StringVar(&tag, "tag", "", "filter by tag")
	c.Flags().BoolVar(&reads, "reads", false, "include last-read / read-count from the audit log")
	c.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return c
}

// newShow prints one secret's metadata (never the value), enriched with last-read info from
// the audit DB.
func newShow() *cobra.Command {
	var jsonOut bool
	c := &cobra.Command{
		Use:   "show NAME",
		Short: "Show metadata for a secret (no decryption)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			s, err := openStore()
			if err != nil {
				return err
			}
			sec := s.Secrets[name]
			if sec == nil {
				return fmt.Errorf("no such secret: %s", name)
			}
			var lr time.Time
			var cnt int
			if a, err := audit.Open(auditPath()); err == nil {
				lr, cnt, _ = a.LastRead(name)
				a.Close()
			}
			if jsonOut {
				return emitJSON(viewOf(name, sec, lr, cnt))
			}
			fmt.Printf("name:         %s\n", sanitize(name))
			fmt.Printf("created:      %s\n", sec.CreatedAt.Local().Format(time.RFC3339))
			fmt.Printf("updated:      %s\n", sec.UpdatedAt.Local().Format(time.RFC3339))
			if lr.IsZero() {
				fmt.Printf("last read:    never\n")
			} else {
				fmt.Printf("last read:    %s (%d total)\n", lr.Local().Format(time.RFC3339), cnt)
			}
			if sec.NoPrint {
				fmt.Printf("policy:       no-print (exec-only)\n")
			}
			if sec.RequireApproval {
				fmt.Printf("policy:       requires approval\n")
			}
			if sec.RateLimit > 0 {
				win := sec.RateWindow
				if win == "" {
					win = "1h"
				}
				fmt.Printf("policy:       rate-limited (%d per %s)\n", sec.RateLimit, win)
			}
			if len(sec.Tags) > 0 {
				fmt.Printf("tags:         %s\n", sanitize(strings.Join(sec.Tags, ", ")))
			}
			if sec.Description != "" {
				fmt.Printf("description:  %s\n", sanitize(sec.Description))
			}
			if sec.RotateAfter != nil {
				fmt.Printf("rotate after: %s\n", sec.RotateAfter.Format("2006-01-02"))
			}
			if sec.Disabled {
				fmt.Printf("status:       DISABLED (refused on every access path; `arca enable %s` to restore)\n", name)
			}
			if sec.ExpiresAt != nil {
				state := "valid"
				if sec.Expired(time.Now()) {
					state = "EXPIRED — refused on every access path"
				}
				fmt.Printf("expires:      %s (%s)\n", sec.ExpiresAt.Local().Format(time.RFC3339), state)
			}
			for k, v := range sec.Meta {
				fmt.Printf("meta.%s: %s\n", sanitize(k), sanitize(v))
			}
			return nil
		},
	}
	c.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return c
}

// newRm deletes a secret from the store and logs the removal.
func newRm() *cobra.Command {
	return &cobra.Command{
		Use:     "rm NAME",
		Aliases: []string{"remove"},
		Short:   "Remove a secret",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			if _, ok := s.Secrets[name]; !ok {
				return fmt.Errorf("no such secret: %s", name)
			}
			delete(s.Secrets, name)
			if err := s.Save(); err != nil {
				return err
			}
			_ = unmarkCanary(name) // best-effort registry cleanup (SEC-04); a stale entry is harmless
			if err := logAudit("rm", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "removed %s\n", name)
			return nil
		},
	}
}

// newDisable suspends a secret without changing its value: it sets a dedicated Disabled flag —
// independent of any real expiry (SEC-13) — so every access path (get/exec/inject/env + MCP,
// including an already-minted handle) refuses it, while the value and the rest of the metadata are
// preserved. Reverse it with `enable`. This is the fast, reversible kill switch for a leak — the
// actual token must still be revoked at its issuer; this only stops arca from handing it out.
//
// Handles are made inert rather than revoked: `enable` must restore the pre-incident state exactly,
// and destroying capabilities on the way in would make the reversal a re-issue.
func newDisable() *cobra.Command {
	return &cobra.Command{
		Use:   "disable NAME",
		Short: "Suspend a secret (refused everywhere) without deleting it; reverse with `enable`",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			sec := s.Secrets[name]
			if sec == nil {
				return fmt.Errorf("no such secret: %s", name)
			}
			sec.Disabled = true // a dedicated kill switch — independent of any real expiry (SEC-13)
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("disable", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "disabled %s (revoke it at the issuer too; `arca enable %s` to restore)\n", name, name)
			return nil
		},
	}
}

// newEnable lifts a `disable` — clearing only the disabled flag, so a real future expiry the secret
// was carrying is preserved (SEC-13). Intent is recorded in the audit log (op "enable"). A secret
// that is unavailable purely because its *expiry* passed is cleared with `set`/`rotate --expires-at`,
// not here — enabling doesn't silently wipe an intentional expiry.
func newEnable() *cobra.Command {
	return &cobra.Command{
		Use:   "enable NAME",
		Short: "Re-enable a disabled secret (keeps any real expiry)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			// Re-enabling lifts the kill switch, so it is anchored to a human (T11). `disable` is
			// not: it only ever restricts, and quarantining a secret should never need a terminal —
			// least of all mid-incident.
			if err := requireOperator("enable",
				fmt.Sprintf("Re-enable %s, lifting the kill switch on it?", name)); err != nil {
				return err
			}
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			sec := s.Secrets[name]
			if sec == nil {
				return fmt.Errorf("no such secret: %s", name)
			}
			sec.Disabled = false
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("enable", name, ""); err != nil {
				return err
			}
			if sec.Expired(time.Now()) {
				fmt.Fprintf(os.Stderr, "enabled %s — note: it is still expired (expires_at is in the past); use `rotate`/`set --expires-at` to change that\n", name)
			} else {
				fmt.Fprintf(os.Stderr, "enabled %s\n", name)
			}
			return nil
		},
	}
}
