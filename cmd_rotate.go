// The rotation commands: rotate, and stale for what is overdue.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/spf13/cobra"
)

// newRotate replaces an existing secret's value while preserving CreatedAt, and logs the
// change as a distinct "rotate" event (vs the initial "set"). Optionally advances the next
// rotation date.
func newRotate() *cobra.Command {
	var rotate, ttl, expiresAt string
	var allowEmpty bool
	c := &cobra.Command{
		Use:   "rotate NAME",
		Short: "Replace an existing secret's value (keeps created_at; logs a rotation)",
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
				return fmt.Errorf("no such secret: %s (use `set` to create)", name)
			}
			recips, err := crypto.ParseRecipients(s.Recipients)
			if err != nil {
				return err
			}
			// `rotate` only ever replaces: it has already refused a missing secret above.
			val, err := readValue("New value: ", allowEmpty)
			if err != nil {
				if errors.Is(err, errEmptyValue) {
					return emptyValueError(name, true)
				}
				return err
			}
			armored, err := crypto.Encrypt(val, recips)
			if err != nil {
				return err
			}
			sec.Value = armored
			sec.UpdatedAt = time.Now().UTC()
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
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("rotate", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "rotated %s\n", name)
			return nil
		},
	}
	c.Flags().StringVar(&rotate, "rotate-after", "", "set the next rotation date (YYYY-MM-DD)")
	c.Flags().StringVar(&ttl, "ttl", "", "refresh expiry to a relative duration (e.g. 30m, 12h, 7d, 2w)")
	c.Flags().StringVar(&expiresAt, "expires-at", "", "refresh expiry to an absolute time (RFC3339 or YYYY-MM-DD)")
	c.Flags().BoolVar(&allowEmpty, "allow-empty", false, "permit storing an empty value (refused by default: it would destroy the stored secret)")
	return c
}

// newStale lists secrets due for rotation: those whose rotate_after is in the past (or within
// --within days). With --missing it instead lists secrets that have no rotation policy at all.
func newStale() *cobra.Command {
	var within int
	var missing, jsonOut bool
	c := &cobra.Command{
		Use:   "stale",
		Short: "List secrets due for rotation (rotate_after past, or within --within days)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			now := time.Now()

			if missing {
				views := []secretView{}
				rows := [][]string{}
				for _, name := range s.Names() {
					sec := s.Secrets[name]
					if sec.RotateAfter != nil {
						continue
					}
					if jsonOut {
						views = append(views, viewOf(name, sec, time.Time{}, 0))
					} else {
						rows = append(rows, sanitizeAll([]string{name, strings.Join(sec.Tags, ","), sec.UpdatedAt.Local().Format("2006-01-02")}))
					}
				}
				if jsonOut {
					return emitJSON(views)
				}
				renderTable([]string{"NAME", "TAGS", "UPDATED"}, rows)
				return nil
			}

			// cutoff = now (+within days): surface anything whose rotation is due or whose hard
			// expiry falls on or before it. With the default --within 0 that means overdue
			// rotations and already-expired secrets; a larger window looks ahead.
			cutoff := now.AddDate(0, 0, within)
			views := []staleView{}
			rows := [][]string{}
			for _, name := range s.Names() {
				sec := s.Secrets[name]
				rotDue := sec.RotateAfter != nil && !sec.RotateAfter.After(cutoff)
				expSoon := sec.ExpiresAt != nil && !sec.ExpiresAt.After(cutoff)
				if !rotDue && !expSoon {
					continue
				}
				ra, ex := "-", "-"
				var status []string
				if rotDue {
					ra = sec.RotateAfter.Format("2006-01-02")
					days := int(now.Sub(*sec.RotateAfter).Hours() / 24)
					if days < 0 { // due in the future but within the window
						status = append(status, fmt.Sprintf("rotate in %dd", -days))
					} else {
						status = append(status, fmt.Sprintf("%dd overdue", days))
					}
				}
				if expSoon {
					ex = sec.ExpiresAt.Local().Format("2006-01-02 15:04")
					if now.After(*sec.ExpiresAt) {
						status = append(status, "EXPIRED")
					} else {
						status = append(status, "expiring")
					}
				}
				if jsonOut {
					views = append(views, staleView{Name: name, RotateAfter: sec.RotateAfter, ExpiresAt: sec.ExpiresAt, Status: status})
				} else {
					rows = append(rows, sanitizeAll([]string{name, ra, ex, strings.Join(status, ", ")}))
				}
			}
			if jsonOut {
				return emitJSON(views)
			}
			renderTable([]string{"NAME", "ROTATE AFTER", "EXPIRES", "STATUS"}, rows)
			return nil
		},
	}
	c.Flags().IntVar(&within, "within", 0, "also include secrets due within N days")
	c.Flags().BoolVar(&missing, "missing", false, "instead, list secrets with no rotation policy")
	c.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return c
}
