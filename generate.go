package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/store"
)

// Named character sets for `generate`. An unrecognized --charset value is treated as a literal
// custom alphabet.
const (
	charsetAlnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetHex   = "0123456789abcdef"
	charsetFull  = charsetAlnum + "!#$%&()*+,-./:;<=>?@[]^_{|}~"
)

func resolveCharset(name string) string {
	switch name {
	case "", "alnum", "alphanumeric":
		return charsetAlnum
	case "hex":
		return charsetHex
	case "full", "symbols", "ascii":
		return charsetFull
	default:
		return name // a literal custom alphabet
	}
}

// randomSecret returns n characters drawn uniformly from alphabet using crypto/rand (no modulo
// bias: rand.Int produces a uniform index in [0, len(alphabet))).
func randomSecret(n int, alphabet string) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("length must be positive")
	}
	if len(alphabet) < 2 {
		return "", fmt.Errorf("charset must have at least 2 characters")
	}
	max := big.NewInt(int64(len(alphabet)))
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b[i] = alphabet[idx.Int64()]
	}
	return string(b), nil
}

// newGenerate creates a secret with a cryptographically-random value (a password or token) and
// stores it like `set`, so the value is never typed or pasted. By default it isn't printed; use
// --show to emit it once.
func newGenerate() *cobra.Command {
	var length int
	var charset, desc, ttl, expiresAt string
	var tags []string
	var noPrint, requireApproval, show, canary, requireGrant bool
	var rate string
	c := &cobra.Command{
		Use:   "generate NAME",
		Short: "Create a secret with a random value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := validName(name); err != nil {
				return err
			}
			val, err := randomSecret(length, resolveCharset(charset))
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
			if len(tags) > 0 {
				sec.Tags = tags
			}
			if desc != "" {
				sec.Description = desc
			}
			if err := applyExpiry(sec, ttl, expiresAt); err != nil {
				return err
			}
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
					n, w, err := parseRate(rate)
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
					return fmt.Errorf("generated %s but failed to update its canary state: %w", name, err)
				}
			}
			if err := logAudit("generate", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "generated %s (%d chars)\n", name, length)
			if show {
				fmt.Println(val)
			}
			return nil
		},
	}
	c.Flags().IntVarP(&length, "length", "l", 32, "number of characters")
	c.Flags().StringVar(&charset, "charset", "alnum", "alnum | hex | full | <custom alphabet>")
	c.Flags().StringSliceVar(&tags, "tag", nil, "tags (repeatable or comma-separated)")
	c.Flags().StringVar(&desc, "desc", "", "description")
	c.Flags().StringVar(&ttl, "ttl", "", "expire after a relative duration (e.g. 30m, 12h, 7d, 2w)")
	c.Flags().StringVar(&expiresAt, "expires-at", "", "expire at an absolute time (RFC3339 or YYYY-MM-DD)")
	c.Flags().BoolVar(&noPrint, "no-print", false, "exec-only: get/env/inject refuse to reveal it")
	c.Flags().BoolVar(&requireApproval, "require-approval", false, "require human approval (TTY) before each release")
	c.Flags().BoolVar(&show, "show", false, "also print the generated value to stdout")
	c.Flags().BoolVar(&canary, "canary", false, "mark as a decoy: any use trips an alert and a signed audit event")
	c.Flags().BoolVar(&requireGrant, "require-grant", false, "usable only via exec/MCP with a matching active grant")
	c.Flags().StringVar(&rate, "rate", "", "rate limit as N/DURATION (e.g. 10/1h)")
	return c
}
