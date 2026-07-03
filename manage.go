package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/crypto"
)

// newEdit decrypts a secret into a temporary file, opens it in $EDITOR, and re-encrypts the
// result. Editing inherently hands the plaintext to an external editor, so it briefly touches
// disk: the temp file is created 0600 (in a tmpfs when one is available), then overwritten and
// removed — the same trade-off as `pass edit` / `sops`.
func newEdit() *cobra.Command {
	return &cobra.Command{
		Use:   "edit NAME",
		Short: "Edit a secret's value in $EDITOR",
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
			if err := gate(sec, name, ""); err != nil {
				return err
			}
			// A --no-print secret must never have its plaintext revealed. gate() doesn't check
			// NoPrint (each reader does), and edit would otherwise hand the current value to
			// $EDITOR — which the caller controls (EDITOR=cat / EDITOR='cp {} …'), turning `edit`
			// into a read primitive that get/inject/env/read_secret all refuse. Rotate to change
			// the value of a --no-print secret without disclosing the old one.
			if sec.NoPrint {
				return fmt.Errorf("%s is --no-print; editing would expose its value — use `rotate %s` to replace it without revealing the current value", name, name)
			}
			ids, err := loadIDs()
			if err != nil {
				return err
			}
			plain, err := crypto.Decrypt(sec.Value, ids)
			if err != nil {
				return fmt.Errorf("decrypt %s: %w", name, err)
			}

			edited, err := editInTemp(plain)
			if err != nil {
				return err
			}

			recips, err := crypto.ParseRecipients(s.Recipients)
			if err != nil {
				return err
			}
			armored, err := crypto.Encrypt(edited, recips)
			if err != nil {
				return err
			}
			sec.Value = armored
			sec.UpdatedAt = time.Now().UTC()
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("edit", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "edited %s\n", name)
			return nil
		},
	}
}

// editTempDir picks where the (briefly-plaintext) edit file lives: a RAM-backed tmpfs when one
// is available, else the OS temp dir. It's a var so tests can point it at a failing path.
var editTempDir = func() string {
	if fi, e := os.Stat("/dev/shm"); e == nil && fi.IsDir() {
		return "/dev/shm"
	}
	return os.TempDir()
}

// editInTemp writes content to a private temp file, opens it in $EDITOR (or vi), and returns the
// edited bytes. The temp file is scrubbed (overwritten with zeros) and removed before returning.
func editInTemp(content []byte) (result []byte, err error) {
	f, err := os.CreateTemp(editTempDir(), "arca-edit-*.txt")
	if err != nil {
		return nil, err
	}
	tmp := f.Name()
	defer func() {
		if fi, e := os.Stat(tmp); e == nil {
			_ = os.WriteFile(tmp, make([]byte, fi.Size()), 0o600) // best-effort scrub
		}
		_ = os.Remove(tmp)
	}()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, err
	}
	if _, err := f.Write(content); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	cmd := exec.Command(editor, tmp) //#nosec G204 G702 -- $EDITOR is the operator's own configured editor
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("editor: %w", err)
	}

	edited, err := os.ReadFile(tmp) //#nosec G304 -- our own temp file
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(edited), "\r\n")), nil
}

// newRename renames a secret, preserving its metadata, policy, and created_at history (it just
// moves the entry — no decryption). `mv` is an alias.
func newRename() *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:     "rename OLD NEW",
		Aliases: []string{"mv"},
		Short:   "Rename a secret, preserving its metadata and history",
		Args:    cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			old, dst := args[0], args[1]
			if err := validName(dst); err != nil {
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
			sec := s.Secrets[old]
			if sec == nil {
				return fmt.Errorf("no such secret: %s", old)
			}
			if _, exists := s.Secrets[dst]; exists && !force {
				return fmt.Errorf("%s already exists (use --force to overwrite)", dst)
			}
			s.Secrets[dst] = sec
			delete(s.Secrets, old)
			if err := s.Save(); err != nil {
				return err
			}
			// Move any canary designation so a renamed decoy keeps tripping (SEC-04).
			if err := renameCanary(old, dst); err != nil {
				return fmt.Errorf("renamed %s but failed to move its canary state: %w", old, err)
			}
			if err := logAudit("rename", old, dst); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "renamed %s -> %s\n", old, dst)
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "overwrite an existing destination")
	return c
}

// newAnnotate edits a secret's tags, description, and metadata *without* touching its value or
// decrypting it. `set` re-prompts for the value (and a --no-print secret can't be re-piped at all),
// so annotate is the only path that changes metadata alone. UpdatedAt is left untouched — it tracks
// the last *value* change — and the edit is recorded in the audit log (op=annotate).
func newAnnotate() *cobra.Command {
	var tags, addTags, rmTags, rmMeta []string
	var desc string
	var meta map[string]string
	c := &cobra.Command{
		Use:   "annotate NAME",
		Short: "Edit a secret's tags, description, and metadata (not its value)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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

			changed := false
			if cmd.Flags().Changed("tag") { // replace the whole set
				sec.Tags = tags
				changed = true
			}
			for _, t := range addTags {
				if t != "" && !contains(sec.Tags, t) {
					sec.Tags = append(sec.Tags, t)
					changed = true
				}
			}
			if len(rmTags) > 0 {
				kept := sec.Tags[:0]
				for _, t := range sec.Tags {
					if !contains(rmTags, t) {
						kept = append(kept, t)
					}
				}
				if len(kept) != len(sec.Tags) {
					changed = true
				}
				sec.Tags = kept
			}
			if cmd.Flags().Changed("desc") {
				sec.Description = desc
				changed = true
			}
			if len(meta) > 0 {
				if sec.Meta == nil {
					sec.Meta = map[string]string{}
				}
				for k, v := range meta {
					sec.Meta[k] = v
				}
				changed = true
			}
			for _, k := range rmMeta {
				if _, ok := sec.Meta[k]; ok {
					delete(sec.Meta, k)
					changed = true
				}
			}
			if !changed {
				return fmt.Errorf("nothing to change; pass --tag/--add-tag/--rm-tag, --desc, --meta, or --rm-meta")
			}
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("annotate", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "annotated %s\n", name)
			return nil
		},
	}
	c.Flags().StringSliceVar(&tags, "tag", nil, "replace all tags (repeatable or comma-separated)")
	c.Flags().StringSliceVar(&addTags, "add-tag", nil, "add tags, keeping existing ones")
	c.Flags().StringSliceVar(&rmTags, "rm-tag", nil, "remove tags")
	c.Flags().StringVar(&desc, "desc", "", "set the description (pass an empty string to clear it)")
	c.Flags().StringToStringVar(&meta, "meta", nil, "set metadata entries key=value (repeatable)")
	c.Flags().StringSliceVar(&rmMeta, "rm-meta", nil, "remove metadata keys")
	return c
}
