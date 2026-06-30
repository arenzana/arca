package main

import (
	"fmt"
	"os"
	"time"
)

// Store mutations are a read-modify-write (load → change → save). Without a lock, two
// concurrent `arca set`/`rotate`/… could each load the same store and the second Save would
// clobber the first's change (a lost update). lockStore serializes those with an exclusive lock
// file next to the store. It's advisory and dependency-free (an O_EXCL create, portable across
// OSes); a lock older than staleLockAge is treated as abandoned by a crashed process and stolen.
//
// The timeouts are package vars so tests can shorten them.
//
// lockTimeout is generous on purpose: a write holds the lock for a full
// load→encrypt→save→audit cycle, so under contention (many agents, or a slow /
// networked filesystem) the last of N writers waits for the N-1 ahead of it.
// 15s leaves headroom for that without masking a genuinely stuck lock, which the
// staleLockAge steal handles separately.
var (
	lockTimeout  = 15 * time.Second
	staleLockAge = 30 * time.Second
)

// lockStore acquires the store lock and returns a release func. Call it at the top of a
// mutating command and `defer` the result so the whole load→save sequence is serialized.
func lockStore() (release func(), err error) {
	lock := storePath() + ".lock"
	deadline := time.Now().Add(lockTimeout)
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //#nosec G304 -- lock path derives from the operator-controlled store path, not untrusted input
		if err == nil {
			f.Close()
			return func() { _ = os.Remove(lock) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		// Held by someone else: steal it if it's stale (left by a crash), otherwise wait.
		if fi, statErr := os.Stat(lock); statErr == nil && time.Since(fi.ModTime()) > staleLockAge {
			_ = os.Remove(lock)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("store is locked by another arca process (remove %s if it is stale)", lock)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
