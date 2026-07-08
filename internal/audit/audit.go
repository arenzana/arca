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
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo); registers the "sqlite" driver
)

// Schema markers recorded in SQLite's PRAGMA user_version, set once when a DB is first migrated:
//
//   - schemaLegacy: the DB already held pre-chain (NULL-hash) rows when hash-chaining was applied.
//     Its legacy prefix is genuine history and is tolerated by Verify.
//   - schemaChained: the DB has only ever held chained rows. A NULL-hash (legacy) row appearing in
//     such a DB — or a missing head — is therefore a tamper signal, not benign history: it's how a
//     "legacy downgrade" (NULL every hash, drop the head) tries to fake a clean verification.
//
// A DB predating this marker reads as user_version 0 and is treated as schemaLegacy for leniency.
const (
	schemaLegacy  = 1
	schemaChained = 2
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

// eventBytesGen extends eventBytes with the store generation the event observed (SEC-14). A row
// with a NULL store_gen hashes with the original encoding, a row carrying a generation hashes
// with it appended — the choice is bound by the hash, so flipping a row's store_gen between
// NULL and a value (or editing the value) after the fact breaks verification.
func eventBytesGen(ts, op, name, caller, actor, agent, version, session string, ppid, storeGen int) []byte {
	b := eventBytes(ts, op, name, caller, actor, agent, version, session, ppid)
	var g [8]byte
	binary.BigEndian.PutUint64(g[:], uint64(storeGen)) //#nosec G115 -- a generation is a non-negative save counter; the value only feeds the chain hash
	return append(b, g[:]...)
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
		"ALTER TABLE events ADD COLUMN store_gen INTEGER", // store generation observed by the event (SEC-14)
	} {
		if _, err := db.Exec(col); err != nil && !isDupColumn(err) {
			return err
		}
	}

	// Record, once, whether this DB has ever carried pre-chain (NULL-hash) rows. A DB that has only
	// ever held chained rows is marked schemaChained, so a legacy row (or a deleted head) appearing
	// afterwards is treated by Verify as tamper rather than benign history. A DB with a genuine
	// pre-chain prefix is marked schemaLegacy and keeps tolerating those rows. Marked only when the
	// version is still 0 (a fresh DB, or one predating this marker) so the decision is made once.
	var uv int
	if err := db.QueryRow("PRAGMA user_version").Scan(&uv); err != nil {
		return err
	}
	if uv == 0 {
		var legacy int
		if err := db.QueryRow("SELECT COUNT(*) FROM events WHERE hash IS NULL").Scan(&legacy); err != nil {
			return err
		}
		mark := schemaChained
		if legacy > 0 {
			mark = schemaLegacy
		}
		// user_version can't be a bound parameter; mark is a trusted in-process constant, never
		// attacker input.
		if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version=%d", mark)); err != nil { //#nosec G201 -- mark is a constant, not user input
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
	return l.RecordGen(op, name, caller, id, 0)
}

// RecordGen is Record carrying the store generation the operation observed (SEC-14): binding the
// generation into the hashed (and signed) event makes a store rollback detectable from the
// tamper-evident log itself, not just from the local high-water-mark heuristic. A storeGen of 0
// means "unknown" (no store was loaded) and records NULL with the original event encoding.
func (l *Log) RecordGen(op, name, caller string, id Identity, storeGen int) error {
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
	var genCol any // NULL when the generation is unknown; the encoding choice is bound by the hash
	if storeGen > 0 {
		eb = eventBytesGen(ts, op, name, caller, id.Actor, id.Agent, id.Version, id.Session, ppid, storeGen)
		genCol = storeGen
	}
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
		`INSERT INTO events (ts, op, name, ppid, caller, actor, agent, version, session, prev_hash, hash, sig, signer_id, store_gen)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ts, op, name, ppid, caller, id.Actor, id.Agent, id.Version, id.Session, prev, h, sig, signerID, genCol,
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
	Unsigned int    // chained events with NO signature (a stripped sig looks like this)
	BrokenID int64  // event id where verification first failed (0 if OK)
	Reason   string // why it failed

	// Store-generation cross-check (SEC-14). Events record the store generation they observed;
	// because the value is bound into each event's hash, the sequence is as tamper-evident as
	// the chain itself. MaxStoreGen is the highest generation any verified event carries (0 if
	// none carry one). GenRegressedID is the first event whose generation is LOWER than one
	// recorded before it — evidence the store was rolled back while auditing continued — or 0.
	// A regression does not fail the chain (the log itself is honest); callers decide severity.
	MaxStoreGen    int
	GenRegressedID int64

	// LastHash is the hash of the newest verified chained event (nil when none) — with Checked,
	// the material for an external anchor (see FormatAnchor).
	LastHash []byte
}

// FormatAnchor renders a compact, externally-storable snapshot of the chain head: the number of
// chained events and the newest event's hash. Everything the in-DB chain protects lives on the
// same disk, so the one rewrite it cannot see is the store and the audit DB rolled back
// *together* to a consistent older state. An anchor stored off the machine — a password manager,
// a git note, another host — closes that: a later `log --verify --anchor` fails if the log no
// longer extends the anchored head.
func FormatAnchor(n int, hash []byte) string {
	return fmt.Sprintf("arca-anchor:v1:%d:%x", n, hash)
}

// ParseAnchor parses a FormatAnchor token.
func ParseAnchor(s string) (int, []byte, error) {
	var n int
	var hexHash string
	if _, err := fmt.Sscanf(s, "arca-anchor:v1:%d:%s", &n, &hexHash); err != nil || n <= 0 {
		return 0, nil, fmt.Errorf("not a valid anchor token (want arca-anchor:v1:<n>:<hex>): %q", s)
	}
	h, err := hex.DecodeString(hexHash)
	if err != nil || len(h) != sha256.Size {
		return 0, nil, fmt.Errorf("anchor hash is not a %d-byte hex digest: %q", sha256.Size, s)
	}
	return n, h, nil
}

// CheckAnchor confirms the chain still extends an anchored head: at least n chained events
// exist and the nth one's hash equals want. Call it only after a clean Verify — the stored
// hashes are trustworthy only once the chain has been recomputed from genesis.
func (l *Log) CheckAnchor(n int, want []byte) error {
	evs, err := l.loadChainRows()
	if err != nil {
		return err
	}
	count := 0
	for _, e := range evs {
		if e.hash == nil {
			continue // legacy rows are not chained and never counted toward an anchor
		}
		count++
		if count == n {
			if !bytes.Equal(e.hash, want) {
				return fmt.Errorf("anchor MISMATCH at event %d: the log diverged from the anchored history (rewritten from before the anchor)", n)
			}
			return nil
		}
	}
	return fmt.Errorf("the log holds only %d chained event(s) but the anchor was minted at %d — the audit log was rolled back or truncated", count, n)
}

// Verify walks the chain in order, recomputing each event's hash from its predecessor and checking
// any signature against the recorded signer public key. It reports the first inconsistency. It
// cannot, on its own, detect deletion of the most recent events (tail truncation) beyond what the
// recorded head count reveals — an externally stored anchor is the mitigation (FormatAnchor /
// CheckAnchor, surfaced as `log --verify` / `--anchor`).
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
	// schema tells us whether this DB is allowed to contain legacy (NULL-hash) rows. A born-chained
	// DB (schemaChained) that suddenly has them — or has lost its head — has been tampered with.
	var schema int
	if err := l.db.QueryRow("PRAGMA user_version").Scan(&schema); err != nil {
		return VerifyResult{}, err
	}

	res := VerifyResult{OK: true}
	var expect []byte // expected prev_hash of the next chained row
	first := true
	fail := func(id int64, reason string) VerifyResult {
		return VerifyResult{Checked: res.Checked, Legacy: res.Legacy, Signed: res.Signed, Unsigned: res.Unsigned, BrokenID: id, Reason: reason}
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
		} else {
			res.Unsigned++ // a chained-but-unsigned row (also what a stripped signature looks like)
		}
		// Store-generation cross-check (SEC-14): the generation is hash-bound, so a verified row's
		// value is trustworthy. A later event observing a LOWER generation than an earlier one
		// means the store went backwards under an honest log — rollback evidence, not log tamper.
		if e.storeGen > 0 {
			if e.storeGen < res.MaxStoreGen && res.GenRegressedID == 0 {
				res.GenRegressedID = e.id
			}
			if e.storeGen > res.MaxStoreGen {
				res.MaxStoreGen = e.storeGen
			}
		}
		res.Checked++
		expect = e.hash
	}

	// A legacy (NULL-hash) row in a DB that has only ever been chained is not benign history: it's
	// how a "legacy downgrade" (NULL every hash so the chain loop skips them) fakes a clean verify.
	// Fail loudly instead of reporting the rows as unverifiable-but-OK.
	if schema >= schemaChained && res.Legacy > 0 {
		return VerifyResult{
			Checked: res.Checked, Legacy: res.Legacy, Signed: res.Signed, Unsigned: res.Unsigned,
			Reason: "unchained (legacy) rows in a fully-chained log — possible legacy-downgrade tamper, or an older arca binary wrote to this DB",
		}, nil
	}

	// Compare against the recorded head: a smaller count or different last hash suggests the tail
	// was truncated (or the head was not updated by a tamperer).
	var headHash []byte
	var headN int
	switch err := l.db.QueryRow("SELECT last_hash, n FROM audit_head WHERE id=1").Scan(&headHash, &headN); err {
	case nil:
		if res.Checked != headN || (expect != nil && !bytes.Equal(expect, headHash)) {
			return VerifyResult{Checked: res.Checked, Legacy: res.Legacy, Signed: res.Signed, Unsigned: res.Unsigned, Reason: "head mismatch: recent events may have been truncated"}, nil
		}
	case sql.ErrNoRows:
		// A missing head is normal only for a genuinely empty log (or a pure pre-chain legacy DB
		// that never chained anything). If any chained rows were verified, or this is a born-chained
		// DB that holds any rows at all, the head — the truncation anchor — was deleted: a tamper.
		if res.Checked > 0 || (schema >= schemaChained && res.Legacy > 0) {
			return VerifyResult{
				Checked: res.Checked, Legacy: res.Legacy, Signed: res.Signed, Unsigned: res.Unsigned,
				Reason: "audit_head is missing — the integrity anchor (truncation guard) was deleted",
			}, nil
		}
	default:
		return VerifyResult{}, err
	}
	res.LastHash = expect
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
	storeGen        int // 0 = the row carries no generation (NULL)
}

// loadChainRows reads all events (oldest first) into memory so verification makes no nested query.
func (l *Log) loadChainRows() ([]chainRow, error) {
	rows, err := l.db.Query(
		`SELECT id, ts, op, name, ppid, caller, actor, agent, version, session, prev_hash, hash, sig, signer_id, store_gen
		   FROM events ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []chainRow
	for rows.Next() {
		var id int64
		var ppid, gen sql.NullInt64 // legacy/hand-edited rows may lack a ppid; store_gen is NULL pre-SEC-14
		var ts, op, name string
		var caller, actor, agent, ver, session, signerID sql.NullString
		var prev, hash, sig []byte
		if err := rows.Scan(&id, &ts, &op, &name, &ppid, &caller, &actor, &agent, &ver, &session, &prev, &hash, &sig, &signerID, &gen); err != nil {
			return nil, err
		}
		// The row's encoding follows its store_gen: NULL hashes with the original event bytes,
		// a value hashes with the generation appended. A tamperer can't move a row between the
		// two encodings (or edit the generation) without breaking its hash.
		eb := eventBytes(ts, op, name, caller.String, actor.String, agent.String, ver.String, session.String, int(ppid.Int64))
		if gen.Valid {
			eb = eventBytesGen(ts, op, name, caller.String, actor.String, agent.String, ver.String, session.String, int(ppid.Int64), int(gen.Int64))
		}
		out = append(out, chainRow{
			id: id, prev: prev, hash: hash, sig: sig, signerID: signerID.String,
			bytes: eb, storeGen: int(gen.Int64),
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
