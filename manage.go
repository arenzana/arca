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
			if err := gate(sec, name); err != nil {
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
