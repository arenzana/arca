package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Store mutations are a read-modify-write (load → change → save). Without a lock, two concurrent
// `arca set`/`rotate`/… could each load the same store and the second Save would clobber the
// first's change (a lost update). lockStore serializes those with an exclusive lock file next to
// the store. It's advisory and dependency-free (an O_EXCL create, portable across OSes).
//
// A lock left by a *crashed* process is reclaimed after staleLockAge. To keep a live-but-slow
// holder (notably `arca edit`, which holds the lock across an interactive $EDITOR session) from
// being mistaken for a crash, the holder heartbeats the lock's mtime while it's held — so only a
// process that has actually stopped ages out. The lock file carries a per-acquisition token so
// (a) release removes the lock only if we still own it, and (b) a stale lock is reclaimed by
// winning an atomic rename rather than a blind unlink — closing the two races the old code had:
// a released process deleting a successor's lock, and two processes both "stealing" the same lock.
//
// The timeouts are package vars so tests can shorten them.
var (
	lockTimeout  = 15 * time.Second
	staleLockAge = 30 * time.Second
)

// lockStore acquires the store lock and returns a release func. Call it at the top of a mutating
// command and `defer` the result so the whole load→save sequence is serialized.
func lockStore() (release func(), err error) {
	lock := storePath() + ".lock"
	token, err := lockToken()
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(lockTimeout)
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //#nosec G304 -- lock path derives from the operator-controlled store path, not untrusted input
		if err == nil {
			_, werr := f.WriteString(token)
			cerr := f.Close()
			if werr != nil || cerr != nil {
				_ = os.Remove(lock)
				if werr != nil {
					return nil, werr
				}
				return nil, cerr
			}
			return heartbeat(lock, token), nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		// Held by someone else. Reclaim only if it looks abandoned (mtime older than staleLockAge),
		// and then only by *winning* an atomic rename — os.Rename of a given path succeeds for at
		// most one racer, so two processes can't both reclaim, and a blind unlink can't delete a
		// lock that was re-created in the meantime. On success we immediately retry the O_EXCL
		// create; on failure (lost the race, or a filesystem that refuses the rename) we must NOT
		// spin — fall through to the deadline check and sleep like ordinary contention.
		if fi, statErr := os.Stat(lock); statErr == nil && time.Since(fi.ModTime()) > staleLockAge {
			if os.Rename(lock, lock+".steal."+token) == nil {
				_ = os.Remove(lock + ".steal." + token) // we won: drop the abandoned lock, re-create ours next iteration
				continue
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("store is locked by another arca process (remove %s if it is stale)", lock)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// heartbeat starts a goroutine that refreshes the lock's mtime while it's held, so a live holder is
// never reclaimed as stale, and returns a release func that stops the heartbeat and removes the
// lock — but only if it still holds our token (a lock reclaimed by another process while we ran
// carries a different token, and we must not delete that successor's lock).
func heartbeat(lock, token string) (release func()) {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(staleLockAge / 3)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-t.C:
				_ = os.Chtimes(lock, now, now) // best-effort; a removed lock just errors
			}
		}
	}()
	return func() {
		close(stop)
		<-done                                                             // ensure no Chtimes races with the removal below
		if b, err := os.ReadFile(lock); err == nil && string(b) == token { //#nosec G304 -- our own lock path
			_ = os.Remove(lock)
		}
	}
}

// lockToken returns a value unique to this acquisition: the PID (human-useful in the lock file)
// plus 128 bits of randomness so it can't collide or be guessed/forged across acquisitions. The
// token is also used to build a temp filename for the steal-rename, so it must be filesystem-safe —
// a '-' separator, never ':' (which is illegal in a Windows path).
func lockToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return strconv.Itoa(os.Getpid()) + "-" + hex.EncodeToString(b[:]), nil
}
