// Package audit is the local, append-only access log backed by SQLite.
// It is deliberately separate from the (git-synced) store so reads never churn the store.
package audit

import (
	"database/sql"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Log struct{ db *sql.DB }

type Event struct {
	TS     time.Time
	Op     string
	Name   string
	PPID   int
	Caller string
	Actor  string
}

func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000;`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS events (
		id     INTEGER PRIMARY KEY AUTOINCREMENT,
		ts     TEXT    NOT NULL,
		op     TEXT    NOT NULL,
		name   TEXT    NOT NULL,
		ppid   INTEGER,
		caller TEXT,
		actor  TEXT
	);`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_events_name ON events(name);`); err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	return &Log{db: db}, nil
}

func (l *Log) Close() error { return l.db.Close() }

// Record appends one access event. actor identifies the agent/session (e.g. $ARCA_ACTOR).
func (l *Log) Record(op, name, caller, actor string) error {
	_, err := l.db.Exec(
		`INSERT INTO events (ts, op, name, ppid, caller, actor) VALUES (?,?,?,?,?,?)`,
		time.Now().UTC().Format(time.RFC3339), op, name, os.Getppid(), caller, actor,
	)
	return err
}

// LastRead returns the most recent access time and the total access count for a secret.
func (l *Log) LastRead(name string) (time.Time, int, error) {
	var ts sql.NullString
	var count int
	row := l.db.QueryRow(
		`SELECT MAX(ts), COUNT(*) FROM events WHERE name=? AND op IN ('read','exec','env')`, name)
	if err := row.Scan(&ts, &count); err != nil {
		return time.Time{}, 0, err
	}
	if !ts.Valid {
		return time.Time{}, 0, nil
	}
	t, _ := time.Parse(time.RFC3339, ts.String)
	return t, count, nil
}

// Recent returns the latest events, optionally filtered by name.
func (l *Log) Recent(name string, limit int) ([]Event, error) {
	q := `SELECT ts, op, name, ppid, caller, actor FROM events`
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
		var caller, actor sql.NullString
		if err := rows.Scan(&tsStr, &e.Op, &e.Name, &e.PPID, &caller, &actor); err != nil {
			return nil, err
		}
		e.TS, _ = time.Parse(time.RFC3339, tsStr)
		e.Caller = caller.String
		e.Actor = actor.String
		out = append(out, e)
	}
	return out, rows.Err()
}
