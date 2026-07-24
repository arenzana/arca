// Exposure / blast-radius visibility: `who-can-read` and `exposure` make "who can decrypt this,
// and how sensitive is it" something an operator can SEE, rather than discover during an incident.
//
// Under today's single-store model every secret is encrypted to the same recipient set, so
// per-secret readership equals the store's recipients. The commands still frame it per-secret so
// the mental model generalizes if per-tier stores ever land.
package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/store"
)

// sensitiveRe flags secrets whose NAME/tags/description smell high-privilege — a master/admin/root
// credential you'd want on as few machines as possible. Heuristic only: arca sees ciphertext plus
// cleartext metadata, never the credential's real capabilities, so this is a nudge, not a verdict.
var sensitiveRe = regexp.MustCompile(`(?i)(master|root|admin|owner|account[_-]?key|secret[_-]?key|api[_-]?key|private[_-]?key)`)

func looksSensitive(name string, tags []string, desc string) bool {
	if sensitiveRe.MatchString(name) || sensitiveRe.MatchString(desc) {
		return true
	}
	for _, t := range tags {
		if sensitiveRe.MatchString(t) {
			return true
		}
	}
	return false
}

// localRecipientSet returns the recipients derived from the local identity, for marking "(you)"
// in readership output. Best-effort: an unreadable/missing identity just yields an empty set.
func localRecipientSet() map[string]bool {
	out := map[string]bool{}
	ids, err := loadIDs()
	if err != nil {
		return out
	}
	recips, err := crypto.RecipientsFromIdentities(ids)
	if err != nil {
		return out
	}
	for _, r := range recips {
		out[r] = true
	}
	return out
}

// printReadership writes the recipient set with labels and a "(you)" marker.
func printReadership(w *tabwriter.Writer, s *store.Store, mine map[string]bool) {
	for _, r := range s.Recipients {
		label := s.Label(r)
		if label == "" {
			label = "(unlabeled — `arca recipients add --label` to name it)"
		}
		you := ""
		if mine[r] {
			you = "  (you)"
		}
		fmt.Fprintf(w, "  %s\t%s%s\n", r, label, you)
	}
}

func newWhoCanRead() *cobra.Command {
	return &cobra.Command{
		Use:   "who-can-read [NAME]",
		Short: "Show which recipients can decrypt the store (optionally framed for one secret)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			mine := localRecipientSet()
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			defer w.Flush()
			if len(args) == 1 {
				name := args[0]
				sec, ok := s.Secrets[name]
				if !ok {
					return fmt.Errorf("no such secret: %s", name)
				}
				tag := ""
				if looksSensitive(name, sec.Tags, sec.Description) {
					tag = "  ⚠ looks high-privilege"
				}
				fmt.Fprintf(w, "%s%s is readable by %d recipient(s):\n", sanitize(name), tag, len(s.Recipients))
				printReadership(w, s, mine)
				return nil
			}
			fmt.Fprintf(w, "the store (all %d secret(s)) is readable by %d recipient(s):\n", len(s.Secrets), len(s.Recipients))
			printReadership(w, s, mine)
			return nil
		},
	}
}

func newExposure() *cobra.Command {
	var sensitiveOnly bool
	c := &cobra.Command{
		Use:   "exposure",
		Short: "List secrets by blast radius (how many recipients can decrypt each; flags high-privilege names)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			n := len(s.Recipients)
			type row struct {
				name      string
				sensitive bool
			}
			var rows []row
			for _, name := range s.Names() {
				sec := s.Secrets[name]
				sens := looksSensitive(name, sec.Tags, sec.Description)
				if sensitiveOnly && !sens {
					continue
				}
				rows = append(rows, row{name, sens})
			}
			// Sensitive first (biggest concern on top), then alphabetical.
			sort.SliceStable(rows, func(i, j int) bool {
				if rows[i].sensitive != rows[j].sensitive {
					return rows[i].sensitive
				}
				return rows[i].name < rows[j].name
			})
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			defer w.Flush()
			fmt.Fprintf(w, "SECRET\tREADABLE BY\tFLAG\n")
			sensCount := 0
			for _, r := range rows {
				flag := ""
				if r.sensitive {
					flag = "⚠ high-privilege?"
					sensCount++
				}
				fmt.Fprintf(w, "%s\t%d recipient(s)\t%s\n", sanitize(r.name), n, flag)
			}
			w.Flush()
			labeled := 0
			for _, r := range s.Recipients {
				if s.Label(r) != "" {
					labeled++
				}
			}
			fmt.Fprintf(os.Stderr, "\n%d secret(s) each decryptable by %d recipient(s) (%d/%d labeled). %d flagged high-privilege.\n",
				len(s.Secrets), n, labeled, n, sensCount)
			if sensCount > 0 && !sensitiveOnly {
				fmt.Fprintln(os.Stderr, "Review the flagged secrets: are they scoped least-privilege, and does every recipient above need them?")
			}
			return nil
		},
	}
	c.Flags().BoolVar(&sensitiveOnly, "sensitive", false, "show only secrets flagged high-privilege")
	return c
}
