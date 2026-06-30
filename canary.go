package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/store"
)

// canaryValue produces a realistic-looking decoy token so a planted canary is tempting and not
// obviously fake at a glance. The value is random — it authenticates nothing — but matches the
// shape of a real credential of the named kind.
func canaryValue(template string) (string, error) {
	switch template {
	case "", "generic":
		return randomSecret(40, charsetAlnum)
	case "stripe":
		s, err := randomSecret(24, charsetAlnum)
		return "sk_live_" + s, err
	case "github":
		s, err := randomSecret(36, charsetAlnum)
		return "ghp_" + s, err
	case "aws":
		id, err := randomSecret(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
		return "AKIA" + id, err
	case "slack":
		a, err := randomSecret(11, "0123456789")
		if err != nil {
			return "", err
		}
		b, err := randomSecret(24, charsetAlnum)
		return "xoxb-" + a + "-" + b, err
	default:
		return "", fmt.Errorf("unknown template %q (use generic, stripe, github, aws, or slack)", template)
	}
}

// newCanary plants a decoy secret, or (with no NAME) lists the canaries and whether each has been
// tripped. A canary should never legitimately be used; gate() alerts and records a signed audit
// event the moment one is accessed (see tripCanary).
func newCanary() *cobra.Command {
	var template, desc string
	var tags []string
	var listAll bool
	c := &cobra.Command{
		Use:   "canary [NAME]",
		Short: "Plant a decoy secret, or list canaries and their trips",
		Long: "With NAME, create a realistic decoy secret whose use trips an alert and a signed audit\n" +
			"event. With no NAME (or --list), list the canaries in the store and whether each was tripped.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 || listAll {
				return listCanaries()
			}
			name := args[0]
			if err := validName(name); err != nil {
				return err
			}
			val, err := canaryValue(template)
			if err != nil {
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
			armored, err := crypto.Encrypt([]byte(val), recips)
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			sec := s.Secrets[name]
			if sec == nil {
				sec = &store.Secret{CreatedAt: now}
				s.Secrets[name] = sec
			}
			sec.Value = armored
			sec.UpdatedAt = now
			sec.Canary = true
			if len(tags) > 0 {
				sec.Tags = tags
			}
			if desc != "" {
				sec.Description = desc
			}
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("set", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "planted canary %s (shaped like %s) — any use will trip an alert\n", name, template)
			return nil
		},
	}
	c.Flags().StringVar(&template, "template", "generic", "decoy shape: generic | stripe | github | aws | slack")
	c.Flags().StringSliceVar(&tags, "tag", nil, "tags (repeatable or comma-separated)")
	c.Flags().StringVar(&desc, "desc", "", "description")
	c.Flags().BoolVar(&listAll, "list", false, "list canaries and their trip status")
	return c
}

func listCanaries() error {
	s, err := openStore()
	if err != nil {
		return err
	}
	a, err := audit.Open(auditPath())
	if err != nil {
		return err
	}
	defer a.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	defer w.Flush()
	fmt.Fprintln(w, "NAME\tSTATUS\tLAST TRIP\tTRIPS")
	any := false
	for _, name := range s.Names() { // Names() is sorted
		sec := s.Secrets[name]
		if sec == nil || !sec.Canary {
			continue
		}
		any = true
		last, n, _ := a.LastOp(name, "canary")
		status, when := "armed", "never"
		if n > 0 {
			status, when = "TRIPPED", last.Local().Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", name, status, when, n)
	}
	if !any {
		fmt.Fprintln(os.Stderr, "no canaries planted (create one with: arca canary NAME --template stripe)")
	}
	return nil
}
