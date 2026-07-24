// Audit escrow (SEC-14, Option B): every sync replicates the local audit log
// off-machine as append-only, age-encrypted segments — audit/<machine-id>/<seq>.age.
//
// The local SQLite log remains the operational, fail-closed witness; escrow adds an
// off-machine copy a local tamperer can't retract. Each segment carries full rows
// (chain hashes, signatures, store generations) plus the chain coordinates of its
// tail — which are exactly an anchor token, so `log --verify --remote` is CheckAnchor
// against a witness this machine cannot quietly rewrite. Escrow is best-effort by
// design: a failure warns and never breaks the sync (let alone an access).
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/remote"
)

// segment is the escrowed unit. It is serialized to JSON and age-encrypted to the
// store's recipients before leaving the machine — event metadata (names, actors)
// never reaches the backend in cleartext.
type segment struct {
	Machine    string            `json:"machine"`
	Seq        int               `json:"seq"`
	FirstID    int64             `json:"first_id"`
	LastID     int64             `json:"last_id"`
	Anchor     string            `json:"anchor"`                // chain coordinates at LastID (arca-anchor:v1:…)
	PrevAnchor string            `json:"prev_anchor,omitempty"` // tail of the previous segment ("" for the first)
	Events     []audit.EscrowRow `json:"events"`
}

// escrowState is the local cursor: what has already been escrowed (state dir).
type escrowState struct {
	LastID     int64  `json:"last_id"`
	Seq        int    `json:"seq"`
	PrevAnchor string `json:"prev_anchor,omitempty"`
}

func escrowStatePath() string { return filepath.Join(stateDir(), "escrow-state.json") }
func machineIDPath() string   { return filepath.Join(stateDir(), "machine-id") }

func loadEscrowState() escrowState {
	var st escrowState
	if b, err := os.ReadFile(escrowStatePath()); err == nil { //#nosec G304 -- our own state dir
		_ = json.Unmarshal(b, &st)
	}
	return st
}

func saveEscrowState(st escrowState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := escrowStatePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, escrowStatePath())
}

var machineIDRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// machineID returns this machine's stable escrow identity: sanitized hostname plus a
// short random suffix, generated once and kept in the state dir. The suffix keeps two
// machines with the same hostname (or a reinstalled one) from colliding on segment
// keys — collisions are harmless (create-only refuses) but noisy.
func machineID() (string, error) {
	if b, err := os.ReadFile(machineIDPath()); err == nil && len(b) > 0 { //#nosec G304 -- our own state dir
		// Re-sanitize on read (SEC-42): the file lives in the state dir, but never trust a value
		// read back into an object key — strip anything outside the safe charset and bound length.
		id := machineIDRe.ReplaceAllString(strings.TrimSpace(string(b)), "-")
		if len(id) > 128 {
			id = id[:128]
		}
		if id != "" {
			return id, nil
		}
	}
	host, _ := os.Hostname()
	host = machineIDRe.ReplaceAllString(host, "-")
	if host == "" {
		host = "machine"
	}
	var suf [4]byte
	if _, err := rand.Read(suf[:]); err != nil {
		return "", err
	}
	id := fmt.Sprintf("%s-%s", host, hex.EncodeToString(suf[:]))
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(machineIDPath(), []byte(id+"\n"), 0o600); err != nil {
		return "", err
	}
	return id, nil
}

// escrowAudit pushes everything not yet escrowed as one new segment. Best-effort:
// callers print the returned error as a warning and move on. recipients are the
// store's — the same keys that can open the store envelope can read the trail.
//
// Self-healing (the create-only slot is already taken): a state dir restored from an
// older backup rewinds the local cursor behind the remote, so every subsequent escrow
// retries an occupied sequence slot and warns forever. On that collision escrowAudit
// reconciles the cursor to the remote's newest segment for this machine and retries
// once, so the stuck cursor recovers on its own. It refuses to reconcile — and surfaces
// the collision — when the local log does not extend that segment (an escrow-identity
// collision with another machine); `arca sync reset-escrow` is the fix for that.
func escrowAudit(ctx context.Context, b remote.Backend, recipients []string) error {
	a, err := audit.Open(auditPath())
	if err != nil {
		return err
	}
	defer a.Close()

	err = escrowOnce(ctx, a, b, recipients)
	if !errors.Is(err, remote.ErrObjectExists) {
		return err // nil, or a non-collision failure the caller warns about
	}
	// The next sequence slot is taken — the local cursor is behind the remote. Adopt
	// the remote's newest segment as the cursor, then retry exactly once. A second
	// collision (e.g. a concurrent writer that grabbed the freed slot first) is left to
	// the next sync rather than looped on here.
	if rerr := reconcileEscrowCursor(ctx, a, b); rerr != nil {
		return rerr
	}
	return escrowOnce(ctx, a, b, recipients)
}

// escrowOnce ships the audit increment since the local cursor as one create-only
// segment and advances the cursor on success. A collision returns remote.ErrObjectExists
// unchanged so escrowAudit can decide whether to reconcile.
func escrowOnce(ctx context.Context, a *audit.Log, b remote.Backend, recipients []string) error {
	st := loadEscrowState()
	rows, err := a.EventsSince(st.LastID)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil // nothing new since the last sync
	}
	last := rows[len(rows)-1].ID
	n, lastHash, err := a.ChainInfoThrough(last)
	if err != nil {
		return err
	}
	anchor := ""
	if n > 0 && lastHash != nil {
		anchor = audit.FormatAnchor(n, lastHash)
	}
	machine, err := machineID()
	if err != nil {
		return err
	}
	seg := segment{
		Machine: machine, Seq: st.Seq + 1,
		FirstID: rows[0].ID, LastID: last,
		Anchor: anchor, PrevAnchor: st.PrevAnchor,
		Events: rows,
	}
	payload, err := json.Marshal(seg)
	if err != nil {
		return err
	}
	sealed, err := sealEnvelope(payload, recipients)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%s%s/%06d.age", remote.KeyAudit, machine, seg.Seq)
	if err := b.PutIfAbsent(ctx, key, sealed); err != nil {
		return err
	}
	return saveEscrowState(escrowState{LastID: last, Seq: seg.Seq, PrevAnchor: anchor})
}

// reconcileEscrowCursor advances a behind cursor to the remote's newest segment for
// this machine, so the next push lands on a free slot. It refuses — returning a
// descriptive error pointing at `arca sync reset-escrow` — when the local log does not
// extend that segment's anchor: the remote segments then belong to another machine
// sharing this escrow identity, and continuing on the same prefix would splice two
// divergent chains.
//
// The membership test is CheckAnchor, not a full Verify: escrow runs on every sync and
// must stay cheap, and Verify would refuse to heal a log that carries an older,
// unrelated integrity finding. A tampered local log that spuriously passes CheckAnchor
// would only advance this cursor — the tamper is still caught by `log --verify` and
// `--remote`, which escrow never substitutes for.
func reconcileEscrowCursor(ctx context.Context, a *audit.Log, b remote.Backend) error {
	segs, err := fetchEscrowedSegments(ctx, b)
	if err != nil {
		return fmt.Errorf("escrow cursor is behind the remote and reconciling it failed: %w", err)
	}
	if len(segs) == 0 {
		return errors.New("escrow cursor is behind the remote but no readable segment history was found for this machine")
	}
	tail := segs[len(segs)-1]
	if cur := loadEscrowState().Seq; tail.Seq <= cur {
		// The occupied slot is not simply ahead of us — advancing wouldn't clear it
		// (e.g. a concurrent writer already lost its CAS). Surface rather than loop.
		return fmt.Errorf("escrow collision at segment #%d but the remote's newest segment is only #%d — not a behind-cursor; not reconciling", cur+1, tail.Seq)
	}
	if tail.Anchor != "" {
		n, h, err := audit.ParseAnchor(tail.Anchor)
		if err != nil {
			return err
		}
		if err := a.CheckAnchor(n, h); err != nil {
			return fmt.Errorf("the remote's newest escrow segment (#%d) is not part of this machine's audit log: %w — the escrow identity likely collides with another machine; run `arca sync reset-escrow`", tail.Seq, err)
		}
	}
	return saveEscrowState(escrowState{LastID: tail.LastID, Seq: tail.Seq, PrevAnchor: tail.Anchor})
}

// currentMachineID returns the stored escrow identity without generating one — empty
// if this machine has never escrowed. Unlike machineID it never writes.
func currentMachineID() string {
	b, err := os.ReadFile(machineIDPath()) //#nosec G304 -- our own state dir
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// reseatEscrowIdentity gives this machine a brand-new escrow identity: it clears the
// machine-id and the escrow cursor so the next escrow starts a fresh append-only
// history under a new prefix. It is the recovery for an escrow-identity collision (two
// machines that ended up with the same machine-id), where reconciling in place is
// unsafe. Secrets, the store, and the local audit log are untouched — only the
// off-machine audit copy restarts under a new name. Returns the old and new ids.
func reseatEscrowIdentity() (oldID, newID string, err error) {
	oldID = currentMachineID()
	if err := os.Remove(machineIDPath()); err != nil && !os.IsNotExist(err) {
		return "", "", err
	}
	if err := os.Remove(escrowStatePath()); err != nil && !os.IsNotExist(err) {
		return "", "", err
	}
	newID, err = machineID() // regenerate a fresh suffix now
	return oldID, newID, err
}

// escrowKeyRegexp matches exactly the segment keys the writer produces for this machine:
// audit/<machine>/<seq>.age. \d{6,} (not \d{6}) because %06d is a minimum width — a Seq past
// 999999 has 7+ digits and must still validate (SEC-43).
func escrowKeyRegexp(machine string) *regexp.Regexp {
	return regexp.MustCompile(`^` + regexp.QuoteMeta(remote.KeyAudit+machine+"/") + `\d{6,}\.age$`)
}

// fetchEscrowedSegments pulls and decrypts this machine's segments, oldest first, and
// checks their continuity (each segment's prev_anchor must equal its predecessor's
// anchor). Returns the parsed segments.
func fetchEscrowedSegments(ctx context.Context, b remote.Backend) ([]segment, error) {
	machine, err := machineID()
	if err != nil {
		return nil, err
	}
	keys, err := b.List(ctx, remote.KeyAudit+machine+"/")
	if err != nil {
		return nil, err
	}
	sort.Strings(keys)
	ids, err := loadIDs()
	if err != nil {
		return nil, err
	}
	// Only fetch/decrypt keys that match the exact segment shape (SEC-39): the backend is
	// untrusted and List returns whatever it likes, so an injected key with a surprising name
	// (or an unbounded count of them) shouldn't reach the decrypt path.
	segKeyRe := escrowKeyRegexp(machine)
	var segs []segment
	for _, k := range keys {
		if !segKeyRe.MatchString(k) {
			return nil, fmt.Errorf("unexpected object under this machine's escrow prefix: %q — the backend injected a non-segment key", k)
		}
		blob, err := b.Get(ctx, k)
		if err != nil {
			return nil, fmt.Errorf("fetch escrow %s: %w", k, err)
		}
		plain, err := crypto.Decrypt(string(blob), ids)
		if err != nil {
			return nil, fmt.Errorf("decrypt escrow %s: %w", k, err)
		}
		var s segment
		if err := json.Unmarshal(plain, &s); err != nil {
			return nil, fmt.Errorf("parse escrow %s: %w", k, err)
		}
		// Continuity is checked from Seq 1: a removed head, a gap, or a broken anchor
		// link all mean the backend's "append-only" was violated.
		if len(segs) == 0 {
			if s.Seq != 1 || s.PrevAnchor != "" {
				return nil, fmt.Errorf("escrow continuity broken: history starts at segment %d — earlier segments were removed from the backend", s.Seq)
			}
		} else if prev := segs[len(segs)-1]; s.Seq != prev.Seq+1 || s.PrevAnchor != prev.Anchor {
			return nil, fmt.Errorf("escrow continuity broken at segment %d: does not extend segment %d — segments were removed or replaced on the backend", s.Seq, prev.Seq)
		}
		segs = append(segs, s)
	}
	return segs, nil
}

// verifyAgainstEscrow confirms the local log still extends the newest escrowed
// anchor — the off-machine witness a local tamperer can't retract. Call only after a
// clean local Verify (same contract as CheckAnchor).
func verifyAgainstEscrow(ctx context.Context, a *audit.Log, b remote.Backend) error {
	segs, err := fetchEscrowedSegments(ctx, b)
	if err != nil {
		return err
	}
	if len(segs) == 0 {
		return fmt.Errorf("no escrowed audit segments for this machine yet — run `arca sync` first")
	}
	tail := segs[len(segs)-1]
	// Tail-truncation guard (SEC-36): the local cursor records the highest Seq this machine has
	// ever escrowed. A backend that DELETES the newest segments (to hide that recent history was
	// rolled back both locally and in escrow) would present a lower tail Seq — the continuity
	// checks pass on the shortened 1..K prefix, but this catches the missing K+1…N.
	if pinned := loadEscrowState().Seq; tail.Seq < pinned {
		return fmt.Errorf("escrow TRUNCATION detected: newest segment on the backend is #%d but this machine escrowed up to #%d — recent segments were deleted from the backend", tail.Seq, pinned)
	}
	if tail.Anchor == "" {
		return fmt.Errorf("newest escrowed segment carries no anchor (pre-chain events only)")
	}
	n, h, err := audit.ParseAnchor(tail.Anchor)
	if err != nil {
		return err
	}
	if err := a.CheckAnchor(n, h); err != nil {
		return fmt.Errorf("local log does not extend the escrowed history: %w", err)
	}
	fmt.Fprintf(os.Stderr, "escrow OK: %d segment(s), local log extends the escrowed anchor (%d chained events at last escrow)\n", len(segs), n)
	return nil
}
