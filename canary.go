package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/store"
)

// The canary registry records which secrets are decoys. It lives in the local state dir — NOT in
// the git-synced store — so someone who obtains the store file (the exact exfiltration a canary
// exists to catch) cannot tell the decoys from the real secrets and step around them. The decoy's
// value is an ordinary-looking store entry; only the "this is a canary" designation is kept private
// here. See SEC-04. The pre-0.6.2 store flag (store.Secret.Canary) is still honored on read for
// backward compatibility (see isCanary), but new canaries are never written to the store.
func canariesPath() string { return filepath.Join(stateDir(), "canaries.json") }

type canaryFile struct {
	Canaries []string `json:"canaries"`
}

func loadCanaries() (map[string]bool, error) {
	b, err := os.ReadFile(canariesPath()) //#nosec G304 -- path derives from the operator's state dir
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]bool{}, nil
		}
		return nil, err
	}
	var cf canaryFile
	if err := json.Unmarshal(b, &cf); err != nil {
		return nil, fmt.Errorf("parse canaries: %w", err)
	}
	set := make(map[string]bool, len(cf.Canaries))
	for _, n := range cf.Canaries {
		set[n] = true
	}
	return set, nil
}

func saveCanaries(set map[string]bool) error {
	if err := os.MkdirAll(filepath.Dir(canariesPath()), 0o700); err != nil {
		return err
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic on-disk order
	b, err := json.MarshalIndent(canaryFile{Canaries: names}, "", "  ")
	if err != nil {
		return err
	}
	tmp := canariesPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil { //#nosec G304 -- operator state dir
		return err
	}
	return os.Rename(tmp, canariesPath())
}

// migrateLegacyCanaries retroactively applies SEC-04 to a pre-0.6.2 store (FU-5): any cleartext
// `canary:true` flag is copied into the local registry and stripped from the synced store, so an
// off-host attacker who obtains the store can no longer tell decoys from real secrets. Best-effort
// on every load: a registry or save failure leaves the flags in place (still honored by isCanary)
// and warns; the migration retries on the next load. Called with the freshly loaded store, before
// the invoking command uses it.
func migrateLegacyCanaries(s *store.Store) {
	var legacy []string
	for name, sec := range s.Secrets {
		if sec.Canary {
			legacy = append(legacy, name)
		}
	}
	if len(legacy) == 0 {
		return
	}
	for _, name := range legacy {
		if err := markCanary(name); err != nil {
			fmt.Fprintf(os.Stderr, "arca: warning: could not migrate legacy canary flag for %s to the local registry: %v\n", name, err)
			return // never strip a flag that wasn't preserved first
		}
	}
	for _, name := range legacy {
		s.Secrets[name].Canary = false
	}
	if err := s.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "arca: warning: could not strip migrated canary flag(s) from the store: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "arca: migrated %d legacy canary flag(s) out of the synced store into the local registry (SEC-04)\n", len(legacy))
}

// isCanary reports whether name is a decoy: present in the local registry, or carrying the legacy
// pre-0.6.2 store flag. A registry read error is announced but treated as "not a canary" so it
// never blocks an access — canary alerting is best-effort by design (see tripCanary).
func isCanary(name string, sec *store.Secret) bool {
	if sec != nil && sec.Canary { // legacy store flag (pre-SEC-04)
		return true
	}
	set, err := loadCanaries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "arca: warning: could not read canary registry: %v\n", err)
		return false
	}
	return set[name]
}

// markCanary records name as a decoy in the local registry (idempotent).
func markCanary(name string) error {
	set, err := loadCanaries()
	if err != nil {
		return err
	}
	set[name] = true
	return saveCanaries(set)
}

// unmarkCanary removes name from the local registry (idempotent).
func unmarkCanary(name string) error {
	set, err := loadCanaries()
	if err != nil {
		return err
	}
	if !set[name] {
		return nil
	}
	delete(set, name)
	return saveCanaries(set)
}

// renameCanary makes the destination's canary state match the source's, so a renamed decoy keeps
// its designation — and a rename --force onto an existing canary with a *non*-canary source clears
// the stale destination entry (else the real secret now living at that name would trip a
// false-positive alert). See FU-4.
func renameCanary(oldName, newName string) error {
	set, err := loadCanaries()
	if err != nil {
		return err
	}
	wasCanary := set[oldName]
	if !wasCanary && !set[newName] {
		return nil // nothing to change
	}
	delete(set, oldName)
	if wasCanary {
		set[newName] = true
	} else {
		delete(set, newName) // source isn't a decoy → the overwritten destination must not stay one
	}
	return saveCanaries(set)
}

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
			sec.Canary = false // never persist the designation to the (synced) store — SEC-04
			if len(tags) > 0 {
				sec.Tags = tags
			}
			if desc != "" {
				sec.Description = desc
			}
			if err := s.Save(); err != nil {
				return err
			}
			// Record the decoy designation in the local registry, not the store.
			if err := markCanary(name); err != nil {
				return fmt.Errorf("planted %s but failed to arm it as a canary: %w", name, err)
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
	reg, err := loadCanaries()
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	defer w.Flush()
	fmt.Fprintln(w, "NAME\tSTATUS\tLAST TRIP\tTRIPS")
	any := false
	for _, name := range s.Names() { // Names() is sorted
		sec := s.Secrets[name]
		if sec == nil || (!reg[name] && !sec.Canary) { // registry, or the legacy pre-0.6.2 store flag
			continue
		}
		any = true
		last, n, _ := a.LastOp(name, "canary")
		status, when := "armed", "never"
		if n > 0 {
			status, when = "TRIPPED", last.Local().Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\n", sanitize(name), status, when, n)
	}
	if !any {
		fmt.Fprintln(os.Stderr, "no canaries planted (create one with: arca canary NAME --template stripe)")
	}
	return nil
}
