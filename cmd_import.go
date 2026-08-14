// The import command and the dotenv/JSON parsers it reads stdin with.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/secretname"
	"github.com/arenzana/arca/internal/store"
	"github.com/spf13/cobra"
)

// newImport reads dotenv-style KEY=value lines from stdin and stores each, e.g. to migrate
// from a sops file: `sops -d secrets.env | arca import`.
// kvPair is a parsed name→value to import, before encryption.
type kvPair struct{ key, val string }

// parseDotenvSecrets reads KEY=value (dotenv) lines, applying the normalization arca has always
// used: skip blanks/comments, drop a leading `export `, strip surrounding quotes, and refuse
// names that aren't valid secret identifiers (which could inject downstream). dotenv is
// line-oriented, so values are single-line; use `set NAME < file` or --json for multi-line ones.
func parseDotenvSecrets(r io.Reader) ([]kvPair, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20) // allow long values (up to 1 MiB/line)
	var out []kvPair
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if secretname.Validate(k) != nil {
			fmt.Fprintf(os.Stderr, "skip %q: not a valid secret name\n", k)
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`) // drop surrounding quotes
		out = append(out, kvPair{k, v})
	}
	return out, sc.Err()
}

// parseJSONSecrets reads a single flat JSON object of name→value — the shape most secret stores
// emit (AWS Secrets Manager, Vault, 1Password, gcloud). String values pass through verbatim
// (so a JSON-escaped multi-line PEM round-trips); numbers and booleans are stringified; null and
// nested object/array values are skipped with a warning, since a secret is a scalar.
func parseJSONSecrets(r io.Reader) ([]kvPair, error) {
	data, err := readAllLimited(r, maxInputBytes)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse JSON object: %w", err)
	}
	out := make([]kvPair, 0, len(raw))
	for k, rv := range raw {
		if secretname.Validate(k) != nil {
			fmt.Fprintf(os.Stderr, "skip %q: not a valid secret name\n", k)
			continue
		}
		val, ok := jsonScalar(rv)
		if !ok {
			fmt.Fprintf(os.Stderr, "skip %q: value is not a string, number, or boolean\n", k)
			continue
		}
		out = append(out, kvPair{k, val})
	}
	return out, nil
}

// jsonScalar renders a JSON value as the string arca will store, or reports ok=false for
// null/object/array, which aren't scalar secrets.
func jsonScalar(rv json.RawMessage) (string, bool) {
	var v any
	if err := json.Unmarshal(rv, &v); err != nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true // -1 avoids scientific notation for ints
	default:
		return "", false
	}
}

func newImport() *cobra.Command {
	var asJSON, dryRun, overwrite, allowEmpty bool
	var prefix string
	var tags []string
	c := &cobra.Command{
		Use:   "import",
		Short: `Bulk-import secrets from stdin (dotenv KEY=value lines, or --json {"KEY":"value"})`,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// Reading/parsing stdin doesn't touch the store, so do it before taking the lock.
			var pairs []kvPair
			var err error
			if asJSON {
				pairs, err = parseJSONSecrets(os.Stdin)
			} else {
				pairs, err = parseDotenvSecrets(os.Stdin)
			}
			if err != nil {
				return err
			}
			// Apply the optional prefix and re-validate the final name (a prefix can make an
			// otherwise-valid key invalid, e.g. one starting with a digit).
			plan := make([]kvPair, 0, len(pairs))
			for _, p := range pairs {
				name := prefix + p.key
				if secretname.Validate(name) != nil {
					fmt.Fprintf(os.Stderr, "skip %q: not a valid secret name\n", name)
					continue
				}
				plan = append(plan, kvPair{name, p.val})
			}

			// A dry run only previews, so it neither locks nor needs a writable store.
			var unlock func()
			if !dryRun {
				unlock, err = lockStore()
				if err != nil {
					return err
				}
				defer unlock()
			}
			s, err := openStore()
			if err != nil {
				return err
			}
			recips, err := crypto.ParseRecipients(s.Recipients)
			if err != nil {
				return err
			}

			now := time.Now().UTC()
			imported := make([]string, 0, len(plan))
			var overwritten, skipped int
			for _, p := range plan {
				existing := s.Secrets[p.key]
				if existing != nil && !overwrite {
					fmt.Fprintf(os.Stderr, "skip %q: already exists (pass --overwrite to replace)\n", p.key)
					skipped++
					continue
				}
				// The same guard `set` and `rotate` apply, narrowed to where it is destructive:
				// replacing a stored value with an empty one loses it and the store keeps no
				// previous version. Creating an empty secret is merely useless, and a bare `KEY=`
				// is an ordinary line in a real .env file — refusing those would break the common
				// import for no safety gain — so only the overwriting case is skipped.
				if p.val == "" && existing != nil && !allowEmpty {
					fmt.Fprintf(os.Stderr, "skip %q: empty value would destroy the stored secret (pass --allow-empty if you mean it)\n", p.key)
					skipped++
					continue
				}
				if dryRun {
					if existing != nil {
						overwritten++
						fmt.Fprintf(os.Stderr, "would overwrite %q\n", p.key)
					} else {
						fmt.Fprintf(os.Stderr, "would import %q\n", p.key)
					}
					imported = append(imported, p.key)
					continue
				}
				armored, err := crypto.Encrypt([]byte(p.val), recips)
				if err != nil {
					return err
				}
				sec := existing
				if sec == nil {
					sec = &store.Secret{CreatedAt: now}
					s.Secrets[p.key] = sec
				} else {
					overwritten++
				}
				sec.Value = armored
				sec.UpdatedAt = now
				if len(tags) > 0 {
					sec.Tags = tags
				}
				imported = append(imported, p.key)
			}

			if dryRun {
				fmt.Fprintf(os.Stderr, "dry run: %d to import (%d new, %d overwrite), %d skipped\n",
					len(imported), len(imported)-overwritten, overwritten, skipped)
				return nil
			}
			if err := s.Save(); err != nil {
				return err
			}
			// Audit each imported secret, so a bulk load is recorded like any other write
			// rather than being a blind spot in the log.
			for _, k := range imported {
				if err := logAudit("import", k, ""); err != nil {
					return err
				}
			}
			fmt.Fprintf(os.Stderr, "imported %d secret(s) (%d new, %d overwritten), %d skipped\n",
				len(imported), len(imported)-overwritten, overwritten, skipped)
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, `read a JSON object {"KEY":"value"} from stdin instead of dotenv lines`)
	c.Flags().BoolVar(&dryRun, "dry-run", false, "report what would be imported without writing anything")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace secrets that already exist (default: skip them)")
	c.Flags().BoolVar(&allowEmpty, "allow-empty", false, "permit an empty value to replace an existing secret (skipped by default: it would destroy the stored value)")
	c.Flags().StringVar(&prefix, "prefix", "", "prepend this prefix to every imported name")
	c.Flags().StringSliceVar(&tags, "tag", nil, "tags to apply to imported secrets (repeatable or comma-separated)")
	return c
}
