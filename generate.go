package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/secretname"
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
	var pf policyFlags
	var length int
	var charset string
	var show bool
	c := &cobra.Command{
		Use:   "generate NAME",
		Short: "Create a secret with a random value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := secretname.Validate(name); err != nil {
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
			// T13/R28, same anchor as `set`. `generate` on an existing name replaces the value
			// with a fresh random one, so a refusal here also has to arrive before that write.
			if err := pf.anchor(cmd, "generate", name, s.Secrets[name]); err != nil {
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
			canaryChanged, err := pf.apply(cmd, sec)
			if err != nil {
				return err
			}
			if err := s.Save(); err != nil {
				return err
			}
			if canaryChanged {
				if err := pf.syncCanary(name, "generated"); err != nil {
					return err
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
	pf.register(c)
	c.Flags().IntVarP(&length, "length", "l", 32, "number of characters")
	c.Flags().StringVar(&charset, "charset", "alnum", "alnum | hex | full | <custom alphabet>")
	c.Flags().BoolVar(&show, "show", false, "also print the generated value to stdout")
	// --no-print promises the value never reaches stdout; --show is precisely that disclosure.
	// Refuse the pair instead of honoring one over the other (FU-9) — consume via exec instead.
	c.MarkFlagsMutuallyExclusive("no-print", "show")
	return c
}
