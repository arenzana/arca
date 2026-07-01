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
//
// # Tamper-evidence
//
// Each event is hash-chained into the previous one (hashᵢ = SHA-256(hashᵢ₋₁ ‖ canonical(eventᵢ)))
// so that editing, deleting, or reordering any past event breaks the chain and is detectable.
// When a Signer is attached, each event's chain hash is also signed with the session's Ed25519
// key, so history cannot be rewritten without that key and events are bound to a session rather
// than to an unverified environment string. Verify() walks and checks the whole chain. This is
// tamper-*evident*, not tamper-proof: see docs/THREAT-MODEL.md for the boundary.
package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo); registers the "sqlite" driver
)

// Log is an open handle to the audit database.
type Log struct {
	db     *sql.DB
	signer *Signer // optional; when set, events are signed
}

// Event is one recorded access.
type Event struct {
	TS      time.Time
	Op      string // read | set | rotate | rm | exec | env | inject | import | redact
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

// Signer signs each event's chain hash with a session-scoped Ed25519 key. SessionID labels the
// signer in the log; its public key is recorded once so Verify can check the signatures.
type Signer struct {
	SessionID string
	Priv      ed25519.PrivateKey
	Pub       ed25519.PublicKey
}

// genesis is the fixed anchor the chain starts from, so the first event's prev_hash is a known
// constant and deleting it is detectable.
func genesis() []byte {
	h := sha256.Sum256([]byte("arca-audit-v1"))
	return h[:]
}

// eventBytes is the canonical, deterministic serialization hashed for each event: length-prefixed
// fields in a fixed order. A verifier must produce identical bytes, so the encoding is explicit
// and never depends on map ordering or struct layout.
func eventBytes(ts, op, name, caller, actor, agent, version, session string, ppid int) []byte {
	var b bytes.Buffer
	put := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s))) //#nosec G115 -- a length is non-negative and audit fields are far below 4GiB; this only feeds the chain hash
		b.Write(n[:])
		b.WriteString(s)
	}
	put(ts)
	put(op)
	put(name)
	put(caller)
	put(actor)
	put(agent)
	put(version)
	put(session)
	var p [8]byte
	binary.BigEndian.PutUint64(p[:], uint64(ppid)) //#nosec G115 -- a pid is non-negative; the value only feeds the chain hash
	b.Write(p[:])
	return b.Bytes()
}

func chainHash(prev, eb []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write(eb)
	return h.Sum(nil)
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
	// A single connection serializes the read-head-then-append step that the hash chain needs,
	// and is plenty for arca's low write volume (short-lived processes recording a few events).
	db.SetMaxOpenConns(1)
	// Wait briefly rather than failing immediately if another arca process holds the lock.
	if _, err := db.Exec(`PRAGMA busy_timeout=5000;`); err != nil {
		db.Close()
		return nil, err
	}
	// WAL improves read/write concurrency for the "many short-lived arca processes in front of
	// an agent" pattern; ignore failure (e.g. a read-only/networked fs) and fall back to the
	// default rollback journal, which is still correct.
	_, _ = db.Exec(`PRAGMA journal_mode=WAL;`)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	_ = os.Chmod(path, 0o600) // best-effort tighten in case the file pre-existed
	return &Log{db: db}, nil
}

// migrate creates the schema and adds the tamper-evidence columns to a pre-existing events table.
func migrate(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS events (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			ts        TEXT    NOT NULL,
			op        TEXT    NOT NULL,
			name      TEXT    NOT NULL,
			ppid      INTEGER,
			caller    TEXT,
			actor     TEXT,
			agent     TEXT,
			version   TEXT,
			session   TEXT,
			prev_hash BLOB,
			hash      BLOB,
			sig       BLOB,
			signer_id TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_events_name ON events(name);`,
		`CREATE TABLE IF NOT EXISTS signers (
			id      TEXT PRIMARY KEY,
			pubkey  BLOB NOT NULL,
			created TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS audit_head (
			id        INTEGER PRIMARY KEY CHECK(id=1),
			last_hash BLOB,
			n         INTEGER
		);`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	// Add the chain columns to an events table created before this version (CREATE above only
	// applies to a fresh DB). A duplicate-column error means the column already exists.
	for _, col := range []string{
		"ALTER TABLE events ADD COLUMN prev_hash BLOB",
		"ALTER TABLE events ADD COLUMN hash BLOB",
		"ALTER TABLE events ADD COLUMN sig BLOB",
		"ALTER TABLE events ADD COLUMN signer_id TEXT",
	} {
		if _, err := db.Exec(col); err != nil && !isDupColumn(err) {
			return err
		}
	}
	return nil
}

func isDupColumn(err error) bool {
	return err != nil && bytes.Contains([]byte(err.Error()), []byte("duplicate column name"))
}

// Close releases the database handle.
func (l *Log) Close() error { return l.db.Close() }

// UseSigner attaches a session signer so subsequent Records are signed.
func (l *Log) UseSigner(s *Signer) { l.signer = s }

// Record appends one access event, chaining it to the previous event's hash (and signing that
// hash when a Signer is attached). The head read + append run in one BEGIN IMMEDIATE transaction
// so concurrent arca processes can't fork the chain. Timestamps are UTC RFC3339.
func (l *Log) Record(op, name, caller string, id Identity) error {
	ts := time.Now().UTC().Format(time.RFC3339)
	ppid := os.Getppid()
	ctx := context.Background()

	conn, err := l.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	// Current chain head: the latest row's hash, or genesis when the chain is empty (or the last
	// row predates chaining and has a NULL hash).
	var prev []byte
	switch err := conn.QueryRowContext(ctx, "SELECT hash FROM events ORDER BY id DESC LIMIT 1").Scan(&prev); err {
	case nil:
	case sql.ErrNoRows:
		prev = nil
	default:
		return err
	}
	if prev == nil {
		prev = genesis()
	}

	eb := eventBytes(ts, op, name, caller, id.Actor, id.Agent, id.Version, id.Session, ppid)
	h := chainHash(prev, eb)

	var sig []byte
	var signerID any
	if l.signer != nil {
		sig = ed25519.Sign(l.signer.Priv, h)
		signerID = l.signer.SessionID
		if _, err := conn.ExecContext(ctx,
			"INSERT OR IGNORE INTO signers(id, pubkey, created) VALUES(?,?,?)",
			l.signer.SessionID, []byte(l.signer.Pub), ts); err != nil {
			return err
		}
	}

	if _, err := conn.ExecContext(ctx,
		`INSERT INTO events (ts, op, name, ppid, caller, actor, agent, version, session, prev_hash, hash, sig, signer_id)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ts, op, name, ppid, caller, id.Actor, id.Agent, id.Version, id.Session, prev, h, sig, signerID,
	); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO audit_head(id, last_hash, n) VALUES(1, ?, 1)
		 ON CONFLICT(id) DO UPDATE SET last_hash=excluded.last_hash, n=audit_head.n+1`, h); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return err
	}
	committed = true
	return nil
}

// VerifyResult summarizes an integrity check of the log.
type VerifyResult struct {
	OK       bool   // chain and signatures all consistent
	Checked  int    // number of hash-chained events verified
	Legacy   int    // rows predating chaining (NULL hash), not verifiable
	Signed   int    // events with a valid signature
	BrokenID int64  // event id where verification first failed (0 if OK)
	Reason   string // why it failed
}

// Verify walks the chain in order, recomputing each event's hash from its predecessor and checking
// any signature against the recorded signer public key. It reports the first inconsistency. It
// cannot, on its own, detect deletion of the most recent events (tail truncation) beyond what the
// recorded head count reveals — external anchoring is the mitigation (see the design note).
func (l *Log) Verify() (VerifyResult, error) {
	// The audit DB uses a single connection, so a query while iterating another query's rows would
	// deadlock. Read each result set fully (signers, then events, then head) before the next.
	pubs, err := l.loadSigners()
	if err != nil {
		return VerifyResult{}, err
	}
	evs, err := l.loadChainRows()
	if err != nil {
		return VerifyResult{}, err
	}

	res := VerifyResult{OK: true}
	var expect []byte // expected prev_hash of the next chained row
	first := true
	fail := func(id int64, reason string) VerifyResult {
		return VerifyResult{Checked: res.Checked, Legacy: res.Legacy, Signed: res.Signed, BrokenID: id, Reason: reason}
	}

	for _, e := range evs {
		if e.hash == nil { // legacy row written before chaining existed
			res.Legacy++
			continue
		}
		if first {
			if !bytes.Equal(e.prev, genesis()) {
				return fail(e.id, "chain does not start at genesis (an earlier event may have been deleted)"), nil
			}
			first = false
		} else if !bytes.Equal(e.prev, expect) {
			return fail(e.id, "broken link: prev_hash does not match the previous event (deletion or reordering)"), nil
		}
		if !bytes.Equal(chainHash(e.prev, e.bytes), e.hash) {
			return fail(e.id, "event content was altered (recomputed hash mismatch)"), nil
		}
		if e.sig != nil {
			pub := pubs[e.signerID]
			if pub == nil || !ed25519.Verify(pub, e.hash, e.sig) {
				return fail(e.id, "invalid signature for the recording session"), nil
			}
			res.Signed++
		}
		res.Checked++
		expect = e.hash
	}

	// Compare against the recorded head: a smaller count or different last hash suggests the tail
	// was truncated (or the head was not updated by a tamperer).
	var headHash []byte
	var headN int
	switch err := l.db.QueryRow("SELECT last_hash, n FROM audit_head WHERE id=1").Scan(&headHash, &headN); err {
	case nil:
		if res.Checked != headN || (expect != nil && !bytes.Equal(expect, headHash)) {
			return VerifyResult{Checked: res.Checked, Legacy: res.Legacy, Signed: res.Signed, Reason: "head mismatch: recent events may have been truncated"}, nil
		}
	case sql.ErrNoRows:
		// no head recorded (e.g. only legacy rows) — nothing to compare
	default:
		return VerifyResult{}, err
	}
	return res, nil
}

// loadSigners reads every recorded signer public key into a map.
func (l *Log) loadSigners() (map[string]ed25519.PublicKey, error) {
	rows, err := l.db.Query("SELECT id, pubkey FROM signers")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pubs := map[string]ed25519.PublicKey{}
	for rows.Next() {
		var id string
		var pk []byte
		if err := rows.Scan(&id, &pk); err != nil {
			return nil, err
		}
		if len(pk) == ed25519.PublicKeySize {
			pubs[id] = ed25519.PublicKey(pk)
		}
	}
	return pubs, rows.Err()
}

// chainRow is one event materialized for verification, with its canonical bytes precomputed.
type chainRow struct {
	id              int64
	prev, hash, sig []byte
	signerID        string
	bytes           []byte
}

// loadChainRows reads all events (oldest first) into memory so verification makes no nested query.
func (l *Log) loadChainRows() ([]chainRow, error) {
	rows, err := l.db.Query(
		`SELECT id, ts, op, name, ppid, caller, actor, agent, version, session, prev_hash, hash, sig, signer_id
		   FROM events ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []chainRow
	for rows.Next() {
		var id int64
		var ppid sql.NullInt64 // legacy/hand-edited rows may lack a ppid
		var ts, op, name string
		var caller, actor, agent, ver, session, signerID sql.NullString
		var prev, hash, sig []byte
		if err := rows.Scan(&id, &ts, &op, &name, &ppid, &caller, &actor, &agent, &ver, &session, &prev, &hash, &sig, &signerID); err != nil {
			return nil, err
		}
		out = append(out, chainRow{
			id: id, prev: prev, hash: hash, sig: sig, signerID: signerID.String,
			bytes: eventBytes(ts, op, name, caller.String, actor.String, agent.String, ver.String, session.String, int(ppid.Int64)),
		})
	}
	return out, rows.Err()
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

// LastOp returns the most recent time and total count of a specific op for a secret. Used to
// surface canary trips (op="canary") without scanning the whole log.
func (l *Log) LastOp(name, op string) (time.Time, int, error) {
	var ts sql.NullString
	var count int
	row := l.db.QueryRow(`SELECT MAX(ts), COUNT(*) FROM events WHERE name=? AND op=?`, name, op)
	if err := row.Scan(&ts, &count); err != nil {
		return time.Time{}, 0, err
	}
	if !ts.Valid {
		return time.Time{}, 0, nil
	}
	t, _ := time.Parse(time.RFC3339, ts.String)
	return t, count, nil
}

// CountOpSince counts events for a secret with a given op at or after a time. Used to compute how
// many times a just-in-time grant has been used (op="exec") since it was issued.
func (l *Log) CountOpSince(name, op string, since time.Time) (int, error) {
	var count int
	row := l.db.QueryRow(
		`SELECT COUNT(*) FROM events WHERE name=? AND op=? AND ts>=?`,
		name, op, since.UTC().Format(time.RFC3339))
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// CountUsesSince counts "use" events (read/exec/env/inject) for a secret at or after a time — the
// same op set as LastRead — for per-secret rate limiting.
func (l *Log) CountUsesSince(name string, since time.Time) (int, error) {
	var count int
	row := l.db.QueryRow(
		`SELECT COUNT(*) FROM events
		   WHERE name=? AND op IN ('read','exec','env','inject') AND ts>=?`,
		name, since.UTC().Format(time.RFC3339))
	if err := row.Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
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
