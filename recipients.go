// Multi-recipient / team support. A store encrypts every value to one or more age recipients
// (see Store.Recipients); `set`/`rotate`/`import` already wrap to all of them. These commands
// manage that recipient set and re-wrap existing secrets when it changes — e.g. to add or
// remove a teammate's key. Changing the set does NOT touch existing ciphertext until
// `reencrypt` runs, so the workflow is: recipients add/rm  →  reencrypt.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/store"
)

// reencryptStore decrypts every secret with the local identity and re-wraps it to the store's
// current recipient set, in memory (the caller Saves). It's the shared core of `reencrypt` and the
// auto-re-encrypt that `recipients rm` runs. UpdatedAt is left untouched — only the envelope changes.
func reencryptStore(s *store.Store) (int, error) {
	ids, err := loadIDs()
	if err != nil {
		return 0, err
	}
	recips, err := crypto.ParseRecipients(s.Recipients)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, name := range s.Names() {
		sec := s.Secrets[name]
		plain, err := crypto.Decrypt(sec.Value, ids)
		if err != nil {
			return n, fmt.Errorf("decrypt %s (is your identity still a recipient?): %w", name, err)
		}
		armored, err := crypto.Encrypt(plain, recips)
		if err != nil {
			return n, fmt.Errorf("encrypt %s: %w", name, err)
		}
		sec.Value = armored
		n++
	}
	return n, nil
}

// warnRecipientRevocation spells out the hard truth of SEC-15: removing a recipient (even with the
// re-encryption that now runs automatically) does NOT revoke the removed holder's access to secrets
// they could already read. Re-encryption only protects the *current* store going forward — the
// removed key still decrypts local clones, backups, and every prior version of the git-synced store.
// The only true revocation of a secret is to rotate its value, so the leaked ciphertext goes dead.
func warnRecipientRevocation(w io.Writer, s *store.Store) {
	fmt.Fprintln(w, "\n⚠  Removing a recipient does NOT revoke access to secrets they could already read.")
	fmt.Fprintln(w, "   The removed key can still decrypt any copy it already had — local clones, backups,")
	fmt.Fprintln(w, "   and every prior version of the store in git history. Re-encryption only protects")
	fmt.Fprintln(w, "   the CURRENT store going forward.")
	names := s.Names()
	if len(names) == 0 {
		return
	}
	fmt.Fprintln(w, "   To truly deny the removed holder a secret, ROTATE its value (the old ciphertext")
	fmt.Fprintln(w, "   then decrypts to a dead value):")
	const maxList = 10
	for i, name := range names {
		if i == maxList {
			fmt.Fprintf(w, "     … and %d more (see `arca ls`)\n", len(names)-maxList)
			break
		}
		fmt.Fprintf(w, "     arca rotate %s\n", sanitize(name))
	}
}

// newRecipients is the parent command; bare `arca recipients` lists the current set.
func newRecipients() *cobra.Command {
	c := &cobra.Command{
		Use:   "recipients",
		Short: "Manage the age recipients secrets are encrypted to",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			for _, r := range s.Recipients {
				fmt.Println(r)
			}
			return nil
		},
	}
	c.AddCommand(newRecipientsAdd(), newRecipientsRm())
	return c
}

func newRecipientsAdd() *cobra.Command {
	return &cobra.Command{
		Use:   "add RECIPIENT [RECIPIENT...]",
		Short: "Add age recipient(s) (run `reencrypt` to apply to existing secrets)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			// Validate every recipient parses as an age recipient before mutating anything.
			if _, err := crypto.ParseRecipients(args); err != nil {
				return fmt.Errorf("invalid recipient: %w", err)
			}
			added := 0
			for _, r := range args {
				if contains(s.Recipients, r) {
					continue
				}
				s.Recipients = append(s.Recipients, r)
				added++
			}
			if added == 0 {
				fmt.Fprintln(os.Stderr, "no new recipients")
				return nil
			}
			if err := s.Save(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "added %d recipient(s); run `arca reencrypt` to re-wrap existing secrets\n", added)
			return nil
		},
	}
}

func newRecipientsRm() *cobra.Command {
	var noReencrypt bool
	c := &cobra.Command{
		Use:   "rm RECIPIENT [RECIPIENT...]",
		Short: "Remove age recipient(s), re-wrap existing secrets, and warn what revocation does/doesn't do",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			kept := make([]string, 0, len(s.Recipients))
			for _, r := range s.Recipients {
				if !contains(args, r) {
					kept = append(kept, r)
				}
			}
			if len(kept) == 0 {
				return fmt.Errorf("refusing to remove all recipients (no key could decrypt new secrets)")
			}
			removed := len(s.Recipients) - len(kept)
			if removed == 0 {
				fmt.Fprintln(os.Stderr, "no matching recipients")
				return nil
			}
			s.Recipients = kept
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("recipients-rm", "*", ""); err != nil {
				return err
			}

			// Automatically re-wrap existing ciphertext to the remaining keys, so the *current* store
			// immediately stops being decryptable by the removed one (closing the old rm→reencrypt gap).
			// A failure here (e.g. our identity can't decrypt) is reported, not fatal: the removal stands.
			if noReencrypt {
				fmt.Fprintf(os.Stderr, "removed %d recipient(s); re-encryption skipped (run `arca reencrypt` to apply)\n", removed)
			} else if n, err := reencryptStore(s); err != nil {
				fmt.Fprintf(os.Stderr, "removed %d recipient(s), but automatic re-encryption failed: %v\n  run `arca reencrypt` once your identity can decrypt the store.\n", removed, err)
			} else if err := s.Save(); err != nil {
				return err
			} else {
				_ = logAudit("reencrypt", "*", "")
				fmt.Fprintf(os.Stderr, "removed %d recipient(s) and re-encrypted %d secret(s) to the remaining key(s)\n", removed, n)
			}

			// The essential honesty (SEC-15): re-encryption is not revocation of what was already read.
			warnRecipientRevocation(os.Stderr, s)
			return nil
		},
	}
	c.Flags().BoolVar(&noReencrypt, "no-reencrypt", false, "don't re-wrap existing secrets now (do it later with `arca reencrypt`)")
	return c
}

// newReencrypt decrypts every secret with the local identity and re-wraps it to the current
// recipient set. This is how a recipient change actually takes effect on stored ciphertext.
// UpdatedAt is left untouched: the value content is unchanged, only its encryption envelope.
func newReencrypt() *cobra.Command {
	return &cobra.Command{
		Use:   "reencrypt",
		Short: "Re-encrypt every secret to the current recipient set",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			n, err := reencryptStore(s)
			if err != nil {
				return err
			}
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("reencrypt", "*", ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "re-encrypted %d secret(s) to %d recipient(s)\n", n, len(s.Recipients))
			return nil
		},
	}
}
