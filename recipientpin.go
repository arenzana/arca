// The local recipient pin: the recipient set this machine has been shown and told to expect.
//
// T12 residual. `recipients add` and `reencrypt` are both terminal-anchored, so a key cannot be
// added *on this machine* without an operator seeing it. That does not cover a key added on
// another machine and pulled in by sync: the store simply arrives carrying a recipient nobody
// here has ever been shown, and no read path looks at the recipient set at all. Every per-secret
// control is irrelevant to that, because re-wrapping never calls gate(). The pin is the baseline
// that makes the change visible.
//
// It deliberately does NOT behave like store.gen. That high-water mark advances by itself the
// moment it sees a higher number, because its job is to catch a generation going *backwards*. A
// recipient set going *forwards* is the attack, so this pin never advances on its own: only an
// anchored operator action moves it.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/arenzana/arca/internal/atomicfile"
	"github.com/arenzana/arca/internal/store"
)

// recipientPinPath is the pinned recipient set for this store (state dir, never synced). It lives
// beside store.gen: both are this machine's memory of what it last saw, and neither may travel
// with the store, or an attacker who controls the store would control the baseline too.
func recipientPinPath() string { return filepath.Join(storeStateDir(), "recipients.pin") }

// readRecipientPin returns the pinned recipient set and whether a pin exists at all. A missing pin
// is not an error: it is the ordinary state of a store that predates this check.
func readRecipientPin() (map[string]bool, bool) {
	b, err := os.ReadFile(recipientPinPath()) //#nosec G304 -- our own state-dir path
	if err != nil {
		return nil, false
	}
	pin := map[string]bool{}
	for _, ln := range strings.Split(string(b), "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			pin[ln] = true
		}
	}
	return pin, true
}

// writeRecipientPin records the store's current recipient set as the accepted baseline. Callers
// must have anchored the action to an operator first: this is what silences the warning, so an
// agent able to reach it unanchored could add a key and then pin away the evidence.
func writeRecipientPin(s *store.Store) error {
	rs := append([]string(nil), s.Recipients...)
	sort.Strings(rs)
	return atomicfile.Write(recipientPinPath(), []byte(strings.Join(rs, "\n")+"\n"), 0o600)
}

// pinAdd accepts exactly these keys into the baseline, leaving anything else that may have
// drifted in still reported. `recipients add` uses it rather than re-pinning from the store,
// because the operator was shown these keys and only these: rewriting the whole set from the
// store would silently accept an unrelated key that arrived by sync in the meantime, turning an
// approval of one key into an approval of every key present.
func pinAdd(keys ...string) error { return mutatePin(keys, true) }

// pinRemove drops these keys from the baseline. `recipients rm` uses it for the same reason, and
// more sharply: rm is deliberately not anchored, since removal only ever restricts. If it
// re-pinned from the store, removing any key would accept every *other* pending change with it,
// which is an unanchored path to silencing the warning this whole check exists to raise.
func pinRemove(keys ...string) error { return mutatePin(keys, false) }

// mutatePin edits the pin in place. A missing pin stays missing: the next load establishes the
// baseline from whatever the store then holds, which is the same trust-on-first-use position the
// store was already in, and is not made worse by this edit.
func mutatePin(keys []string, add bool) error {
	pin, ok := readRecipientPin()
	if !ok {
		return nil
	}
	for _, k := range keys {
		if add {
			pin[k] = true
		} else {
			delete(pin, k)
		}
	}
	out := make([]string, 0, len(pin))
	for k := range pin {
		out = append(out, k)
	}
	sort.Strings(out)
	body := ""
	if len(out) > 0 {
		body = strings.Join(out, "\n") + "\n"
	}
	return atomicfile.Write(recipientPinPath(), []byte(body), 0o600)
}

// recipientDrift compares the store's recipients against the pin. added is the set that can now
// decrypt this store without ever having been shown here, which is the finding that matters;
// removed is reported too, since a key vanishing is a revocation the operator should also see.
// pinned is false when no baseline exists yet, in which case both slices are empty.
func recipientDrift(s *store.Store) (added, removed []string, pinned bool) {
	pin, ok := readRecipientPin()
	if !ok {
		return nil, nil, false
	}
	cur := map[string]bool{}
	for _, r := range s.Recipients {
		cur[r] = true
		if !pin[r] {
			added = append(added, r)
		}
	}
	for r := range pin {
		if !cur[r] {
			removed = append(removed, r)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed, true
}

// pinRecipientsOnFirstUse establishes the baseline when none exists. This is trust-on-first-use
// and carries TOFU's usual caveat: a key injected *before* the first pin is written is baked into
// the baseline and never reported. The alternative, warning on every store that predates the
// check, would train operators to ignore the one warning that matters. store.gen makes the same
// trade by starting its high-water mark at 0. Best-effort by the same reasoning as
// recordStoreGeneration: losing this costs a later warning, never a command.
func pinRecipientsOnFirstUse(s *store.Store) {
	if _, ok := readRecipientPin(); !ok {
		_ = writeRecipientPin(s)
	}
}

// warnIfRecipientsChanged reports recipients that appeared without being shown on this machine.
// It runs on load, so the notice lands before whatever the command was going to do, and it keeps
// firing until an operator accepts the set with `arca recipients pin`. Nothing here writes the
// pin: a warning that silenced itself would report each injected key exactly once.
func warnIfRecipientsChanged(s *store.Store) {
	added, removed, pinned := recipientDrift(s)
	if !pinned {
		pinRecipientsOnFirstUse(s)
		return
	}
	for _, r := range added {
		label := s.Label(r)
		if label == "" {
			label = "unlabeled"
		}
		fmt.Fprintf(os.Stderr, "arca: warning: %s (%s) can decrypt this store but was never added on this machine — if you did not expect it, it can read every secret here, offline and permanently; review with `arca who-can-read`, then accept with `arca recipients pin` or remove it with `arca recipients rm`\n", r, label)
	}
	for _, r := range removed {
		fmt.Fprintf(os.Stderr, "arca: note: %s no longer appears in the recipient set — accept with `arca recipients pin`; note that removing a recipient is not revocation, since it can still decrypt anything it already copied\n", r)
	}
}
