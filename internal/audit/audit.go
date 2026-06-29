// Package audit is arca's access log: an append-only history of every secret access, backed
// by a local SQLite database.
//
// It is deliberately kept *separate* from the JSON store. The store is the git-synced source
// of truth and should only change on real mutations; reads, by contrast, are frequent and
// local. Putting read tracking here means a `get` never rewrites (and never churns the git
// history of) the store, while still letting `log`/`show` answer "who read this, and when?".
//
// Because arca is meant to sit in front of AI agents, each event captures not just the OS
// caller (ppid/command) but the accessing Identity — an explicit $ARCA_ACTOR plus an
// auto-detected agent name/version/session (see detectIdentity in the main package).
package audit

import (
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo); registers the "sqlite" driver
)

// Log is an open handle to the audit database.
type Log struct{ db *sql.DB }

// Event is one recorded access.
type Event struct {
	TS      time.Time
	Op      string // read | set | rotate | rm | exec | env | inject
	Name    string // secret name
	PPID    int    // parent process id (best-effort OS caller)
	Caller  string // parent command name, when known (e.g. set by `exec`)
	Actor   string // explicit $ARCA_ACTOR
	Agent   string // detected AI agent, e.g. "claude-code"
	Version string // agent version
	Session string // agent session id
}

// Identity describes who/what is accessing a secret, recorded alongside each event so the
// audit log can attribute access to a specific human label and/or AI agent session.
type Identity struct {
	Actor   string // explicit $ARCA_ACTOR
	Agent   string // detected AI agent, e.g. "claude-code"
	Version string // agent version
	Session string // agent session id
}

// Open opens (creating if needed) the SQLite audit DB at path, ensuring the schema exists.
// The file is created 0600 and the parent directory 0700.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// Wait briefly rather than failing immediately if another arca process holds the lock.
	if _, err := db.Exec(`PRAGMA busy_timeout=5000;`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS events (
		id      INTEGER PRIMARY KEY AUTOINCREMENT,
		ts      TEXT    NOT NULL,
		op      TEXT    NOT NULL,
		name    TEXT    NOT NULL,
		ppid    INTEGER,
		caller  TEXT,
		actor   TEXT,
		agent   TEXT,
		version TEXT,
		session TEXT
	);`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_name ON events(name);`); err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0o600) // best-effort tighten in case the file pre-existed
	return &Log{db: db}, nil
}

// Close releases the database handle.
func (l *Log) Close() error { return l.db.Close() }

// Record appends one access event with the caller and the accessing identity. Timestamps are
// stored as UTC RFC3339 strings for easy, sortable, human-readable rows.
func (l *Log) Record(op, name, caller string, id Identity) error {
	_, err := l.db.Exec(
		`INSERT INTO events (ts, op, name, ppid, caller, actor, agent, version, session)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339), op, name, os.Getppid(), caller,
		id.Actor, id.Agent, id.Version, id.Session,
	)
	return err
}

// LastRead returns the most recent access time and the total access count for a secret,
// counting only the "use" operations (read/exec/env/inject) rather than mutations. Used by
// `show` and `ls --reads` to surface usage without storing it in the (synced) store.
func (l *Log) LastRead(name string) (time.Time, int, error) {
	var ts sql.NullString
	var count int
	row := l.db.QueryRow(
		`SELECT MAX(ts), COUNT(*) FROM events
		   WHERE name=? AND op IN ('read','exec','env','inject')`, name)
	if err := row.Scan(&ts, &count); err != nil {
		return time.Time{}, 0, err
	}
	if !ts.Valid { // never accessed
		return time.Time{}, 0, nil
	}
	t, _ := time.Parse(time.RFC3339, ts.String)
	return t, count, nil
}

// Recent returns the latest events (newest first), optionally filtered to a single secret.
func (l *Log) Recent(name string, limit int) ([]Event, error) {
	q := `SELECT ts, op, name, ppid, caller, actor, agent, version, session FROM events`
	args := []any{}
	if name != "" {
		q += ` WHERE name=?`
		args = append(args, name)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := l.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var tsStr string
		// Nullable text columns: older rows (or unset fields) come back as NULL.
		var caller, actor, agent, ver, session sql.NullString
		if err := rows.Scan(&tsStr, &e.Op, &e.Name, &e.PPID, &caller, &actor, &agent, &ver, &session); err != nil {
			return nil, err
		}
		e.TS, _ = time.Parse(time.RFC3339, tsStr)
		e.Caller = caller.String
		e.Actor = actor.String
		e.Agent = agent.String
		e.Version = ver.String
		e.Session = session.String
		out = append(out, e)
	}
	return out, rows.Err()
}
