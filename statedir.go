// Per-store state directories (finding R5, design D4).
//
// `xdg.StateDir()` is `$XDG_STATE_HOME/arca` for every store on the machine, so before this change
// `store.gen`, `sync.json`, `sync-state.json`, `grants.json`, `handles.json`, `canaries.json`,
// `escrow-state.json`, the audit DB and the session signing keys were shared by every store a
// machine had. Two stores — the documented personal/work split, which is one `ARCA_STORE` away —
// clobbered each other two ways: a `sync` run against store B reconciled B against store A's
// backend and replaced B's contents, and B's legitimately lower generation tripped the SEC-14
// rollback warning against A's high-water mark. Both are reproduced by tests in this package.
//
// Per-store files now live in `xdg.StateDir()/stores/<key>`, keyed to the store they belong to.
// `machine-id` deliberately stays flat in `xdg.StateDir()`: it identifies the MACHINE to escrow, not
// the store, and keying it per-store would silently fork this machine's escrow identity into one
// lineage per store.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/arenzana/arca/internal/atomicfile"
	"github.com/arenzana/arca/internal/xdg"
)

// legacyStateEntries are the per-store files that lived directly in xdg.StateDir() before D4.
//
// `audit.db`'s two SQLite sidecars are listed explicitly because the log runs in WAL mode
// (internal/audit/audit.go sets `journal_mode=WAL`), so moving the DB without them would strand
// committed events in a WAL the DB no longer points at. `sessions` is a directory and moves whole:
// a missing session key breaks signature verification of that DB's events, so it has to follow
// the DB it signs for.
var legacyStateEntries = []string{
	"store.gen",
	"sync.json",
	"sync-state.json",
	"grants.json",
	"handles.json",
	"canaries.json",
	"escrow-state.json",
	"audit.db",
	"audit.db-wal",
	"audit.db-shm",
	"sessions",
}

// absStorePath is xdg.StorePath() made absolute and symlink-resolved, which is what the per-store key
// is derived from. Two spellings of one store must key to one dir, or an operator who wrote a
// relative path today and an absolute one tomorrow silently loses their grants and sync cursor.
//
// The symlinks are resolved on the *directory*, never on the store file: the file need not exist
// yet (`arca init` computes state paths before creating it), and on macOS the containing dir is
// exactly where the difference lives — $TMPDIR and /var are symlinks to /private/..., so
// `filepath.Abs` alone yields two different absolute paths for one file depending on whether the
// caller arrived via the symlink or via a relative path resolved against a physical cwd.
//
// Residual, stated rather than hidden: a symlink to the store *file* keys to a dir of its own, and
// a store whose parent dir does not exist yet keys by its unresolved path until the dir appears.
// Both split one store into two dirs, which is the conservative direction — a split degrades to
// "this store's state looks fresh", which `arca doctor` names and an operator can repair by moving
// the dir, whereas collapsing two distinct stores onto one dir is the clobber R5 is about.
func absStorePath() string { return resolvePath(xdg.StorePath()) }

// resolvePath makes p absolute and symlink-resolves its containing DIRECTORY, leaving the final
// element alone. Factored out of absStorePath so the audit-redirect check (R4/D2) compares paths
// by the same rule the state key is derived from — two spellings of one path must not read as two
// different paths in one place and one path in the other.
func resolvePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p) // Abs only fails if the cwd is unavailable; degrade, don't panic
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return abs // parent does not exist yet, or is unreadable
	}
	return filepath.Join(dir, filepath.Base(abs))
}

// sameFile reports whether a and b name the same file. The string comparison of resolved paths
// comes first because it is the only one that works before the file exists — the audit DB is
// routinely named before it is created. os.SameFile is the fallback for the cases string equality
// cannot see: a case-insensitive filesystem (Windows CI runs this code), a hard link, or a bind
// mount. It can only run when both paths already resolve to something on disk.
//
// One of the two paths is $ARCA_AUDIT — attacker-influenced by construction, since deciding what
// to do about an attacker's chosen path is this function's entire job. gosec's taint analysis is
// right that the value is untrusted and wrong that it is a traversal: nothing here opens, reads or
// writes the path, the only output is a bool, and a stat that fails yields false, which is the
// refusing answer. Both stats carry the annotation because either argument may be the tainted one.
func sameFile(a, b string) bool {
	ra, rb := resolvePath(a), resolvePath(b)
	if ra == rb {
		return true
	}
	fa, err := os.Stat(ra) //#nosec G703 -- metadata only, never opened; a failed stat refuses
	if err != nil {
		return false
	}
	fb, err := os.Stat(rb) //#nosec G703 -- metadata only, never opened; a failed stat refuses
	if err != nil {
		return false
	}
	return os.SameFile(fa, fb)
}

// storeStateKey is the directory name for the active store: the first 16 hex digits of
// sha256(absolute store path). Hashing rather than escaping the path keeps the name a safe,
// bounded filename on every platform regardless of what the operator pointed ARCA_STORE at.
func storeStateKey() string {
	h := sha256.Sum256([]byte(absStorePath()))
	return hex.EncodeToString(h[:8])
}

// storesRoot is the parent of every per-store state dir.
func storesRoot() string { return filepath.Join(xdg.StateDir(), "stores") }

// storeStateDir is the state directory for the active store. It has the same shape as xdg.StateDir():
// it resolves the active store internally and takes no argument, so every path helper built on it
// keeps its signature and the change stays inside the helper block at the top of each file
// (a hard constraint of D4, not a preference).
//
// Adoption of the pre-D4 flat layout is triggered from here rather than from main() on purpose: a
// path helper is the only place guaranteed to run before anything reads one of these files. An
// explicit call in main() would be one refactor away from a code path that computes a state path
// first and silently reads an empty dir.
func storeStateDir() string {
	dir := filepath.Join(storesRoot(), storeStateKey())
	adoptLegacyState(dir)
	tightenStateDirMode(dir)
	return dir
}

// tightenStateDirMode best-effort tightens a pre-existing state dir to 0700 (audit L2).
// MkdirAll(0700) is a no-op on a directory that already exists, so a state dir created
// by hand at 0755 would stay that way — and every 0600 file inside (grants, handles,
// sync.json credentials) would be listable by anyone on the machine.
func tightenStateDirMode(dir string) {
	if runtime.GOOS == "windows" {
		return // ACLs, not mode bits
	}
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o077 == 0 {
		return
	}
	_ = os.Chmod(dir, 0o700) //#nosec G302 -- a directory needs the execute bit; 0700 is the correct (and tightening) mode here, G302's 0600 expectation is for files
}

// adoptedByPath records which store adopted this machine's pre-D4 flat state. Its contents are the
// adopter's absolute store path; its existence means the claim has been made.
func adoptedByPath() string { return filepath.Join(xdg.StateDir(), "adopted-by") }

// adoptedBy returns the store path that claimed this machine's legacy state, or "" if none has.
func adoptedBy() string {
	b, err := os.ReadFile(adoptedByPath()) //#nosec G304 -- our own state dir
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// adoptLegacyState performs the one-time move of the pre-D4 flat files into dst.
//
// The trigger is D4's: the legacy files exist and nothing has claimed them. That is correct for the
// one-store case whether or not $ARCA_STORE is set, and for the two-store case it reproduces
// exactly today's behaviour (those stores already share this state), so it cannot regress anyone.
// A second, distinct store gets a fresh dir and `arca doctor` explains it.
//
// The move is done in place rather than staged-then-published. An earlier draft moved the entries
// into a temp dir and published by renaming it onto `stores/`, which is atomic but fails outright
// once `stores/` exists — and it exists as soon as any process that declined to adopt writes its
// own per-store file. The staged entries were by then the ONLY copy, so the atomic-publish design
// could strand exactly the files it was protecting. Moving in place has no such state: every entry
// is either in the shared dir or in the per-store dir, an interrupted run leaves both readable, and
// the owner's next run finishes the job.
//
// Every failure here is a warning, never fatal: a state dir that could not be adopted degrades to
// an empty one, which is recoverable (the legacy files are still on disk, un-deleted), whereas
// refusing to run would lock an operator out of their own secrets over a bookkeeping problem.
//
// Cost note, since every path helper calls this: the common steady state is one small read of
// `adopted-by`. The 11-stat scan for leftovers only runs on a machine that has not finished
// adopting, which is a transient by construction.
func adoptLegacyState(dst string) {
	if owner := adoptedBy(); owner != "" && owner != absStorePath() {
		return // another store owns this machine's legacy state; its leftovers are not ours to take
	}
	if !anyLegacyState() {
		return // fresh install, or the move already completed
	}
	unlock, err := lockAdoption()
	if err != nil {
		if errors.Is(err, errAdoptionInProgress) {
			// Another process is adopting right now. Wait for it instead of racing ahead: reading
			// our paths mid-adoption risks persisting an empty grants.json over grants that are
			// about to land. If it never finishes we carry on with an un-adopted dir, which is a
			// warning-level degradation and not worse than the pre-D4 behaviour.
			waitForAdoption()
			return
		}
		// Anything else — an unwritable state dir, most likely — is our failure, not someone
		// else's progress. Waiting on it would burn the wait budget in silence and report nothing.
		warnAdoption(err)
		return
	}
	defer unlock()

	// Re-check under the lock: a holder that finished while we were reaching for it may have
	// claimed the state for a different store, or moved the last entry out.
	if owner := adoptedBy(); owner != "" && owner != absStorePath() {
		return
	}
	if !anyLegacyState() {
		return
	}
	claimAndMoveLegacyState(dst)
}

// claimAndMoveLegacyState claims the machine's legacy state for the active store and moves it into
// dst. Callers hold the adoption lock.
func claimAndMoveLegacyState(dst string) {
	// Claim before moving anything. Which store owns this state has to be decided atomically, or a
	// run interrupted mid-move leaves entries behind that a *different* store would sweep into its
	// own dir on its next command — silently handing one store's grants and sync cursor to another,
	// which is the failure this whole slice exists to prevent.
	if err := atomicfile.Write(adoptedByPath(), []byte(absStorePath()+"\n"), 0o600); err != nil {
		warnAdoption(fmt.Errorf("claim the shared state: %w", err))
		return
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		warnAdoption(fmt.Errorf("create %s: %w", dst, err))
		return
	}
	for _, name := range legacyStateEntries {
		from := filepath.Join(xdg.StateDir(), name)
		if _, err := os.Stat(from); err != nil {
			continue // never existed, or an earlier attempt already moved it
		}
		to := filepath.Join(dst, name)
		if _, err := os.Stat(to); err == nil {
			// Both copies exist, so an earlier run that could not adopt still had to work and wrote
			// fresh state here. The per-store copy is the newer one; overwriting it with the shared
			// one would undo whatever that run recorded. Leave the shared copy alone and let
			// `arca doctor` put it in front of the operator, who is the only one who can say which
			// of the two they want.
			warnAdoption(fmt.Errorf("%s exists in both %s and %s, so the shared copy was left in place", name, xdg.StateDir(), dst))
			continue
		}
		if err := os.Rename(from, to); err != nil {
			// Report and keep going: one unmovable entry must not strand the other ten.
			warnAdoption(fmt.Errorf("move %s: %w", name, err))
		}
	}
}

// adoptLockPath is the O_EXCL lock serializing adoption. The store lock cannot be used for this:
// it lives next to the store, it is already held by some callers that compute state paths, and
// taking it here would deadlock.
func adoptLockPath() string { return filepath.Join(xdg.StateDir(), "stores.lock") }

// errAdoptionInProgress means a live holder has the adoption lock — the one lock failure that is
// someone else's progress rather than our failure. It is a distinct error because the two get
// opposite handling: wait for a holder, warn about anything else. Collapsing them (an earlier
// draft returned a bare error for both) turns an unwritable state dir into a silent two-second
// stall followed by no diagnostic at all.
var errAdoptionInProgress = errors.New("another process is adopting the shared state dir")

// lockAdoption takes the adoption lock, reclaiming one left behind by a crash. Adoption is a
// handful of renames, so anything older than staleLockAge (shared with lock.go) is dead.
// The reclaim is a rename-steal, not a blind unlink — the same races lock.go fixed apply here
// (audit L12): two processes must not both "reclaim", and an unlink must not delete a lock
// that was re-created in the meantime.
func lockAdoption() (func(), error) {
	if err := os.MkdirAll(xdg.StateDir(), 0o700); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(adoptLockPath(), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //#nosec G304 -- our own state dir
		if err == nil {
			token, terr := lockToken()
			if terr != nil {
				_ = f.Close()
				_ = os.Remove(adoptLockPath())
				return nil, terr
			}
			if _, werr := f.WriteString(token); werr != nil {
				_ = f.Close()
				_ = os.Remove(adoptLockPath())
				return nil, werr
			}
			_ = f.Close()
			lock, tok := adoptLockPath(), token
			return func() {
				// Remove only if we still own it: a reclaimed/recreated lock carries
				// someone else's token (lock.go's release discipline).
				if b, rerr := os.ReadFile(lock); rerr == nil && string(b) == tok { //#nosec G304 -- our own lock path
					_ = os.Remove(lock)
				}
			}, nil
		}
		if !os.IsExist(err) {
			return nil, err // not contention: an unwritable state dir, most likely
		}
		fi, serr := os.Stat(adoptLockPath())
		if serr != nil || time.Since(fi.ModTime()) < staleLockAge {
			return nil, errAdoptionInProgress
		}
		// Stale: reclaim by winning an atomic rename, exactly as lockStoreFor does.
		token, terr := lockToken()
		if terr != nil {
			return nil, terr
		}
		if os.Rename(adoptLockPath(), adoptLockPath()+".steal."+token) == nil {
			_ = os.Remove(adoptLockPath() + ".steal." + token) // we won: drop it, re-create ours next iteration
			continue
		}
		return nil, errAdoptionInProgress // lost the race; a live reclaimer is adopting
	}
	return nil, fmt.Errorf("could not acquire %s", adoptLockPath())
}

// waitForAdoption blocks briefly for another process's adoption to finish, which it detects by the
// lock being released. Bounded well under staleLockAge: adoption is a handful of renames, so if the
// holder has not released by now it is not going to.
func waitForAdoption() {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(adoptLockPath()); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// legacyStateLeftovers lists the pre-D4 flat entries still sitting in xdg.StateDir(), in the declared
// order. `doctor` names them, because "some state was left behind" is not actionable and
// "grants.json and audit.db were left behind" is.
func legacyStateLeftovers() []string {
	var out []string
	for _, name := range legacyStateEntries {
		if _, err := os.Stat(filepath.Join(xdg.StateDir(), name)); err == nil {
			out = append(out, name)
		}
	}
	return out
}

// anyLegacyState reports whether any pre-D4 flat file is still sitting in xdg.StateDir().
func anyLegacyState() bool { return len(legacyStateLeftovers()) > 0 }

// warnAdoption reports an adoption problem on stderr. Adoption is bookkeeping; it warns rather
// than failing the command an operator actually ran.
func warnAdoption(err error) {
	fmt.Fprintf(os.Stderr, "arca: warning: could not adopt the shared state dir into a per-store one: %v\n", err)
}
