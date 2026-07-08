// JSON output for the read/inspect commands (ls, show, log, stale). Agents and scripts get a
// stable, parseable shape via --json; the human-facing tabwriter output stays the default.
package main

import (
	"encoding/json"
	"os"
	"time"

	"github.com/arenzana/arca/internal/store"
)

// secretView is the JSON representation of a secret's metadata — never the value.
type secretView struct {
	Name            string            `json:"name"`
	Tags            []string          `json:"tags,omitempty"`
	Description     string            `json:"description,omitempty"`
	Created         time.Time         `json:"created"`
	Updated         time.Time         `json:"updated"`
	RotateAfter     *time.Time        `json:"rotate_after,omitempty"`
	ExpiresAt       *time.Time        `json:"expires_at,omitempty"`
	Expired         bool              `json:"expired,omitempty"`
	NoPrint         bool              `json:"no_print,omitempty"`
	RequireApproval bool              `json:"require_approval,omitempty"`
	Meta            map[string]string `json:"meta,omitempty"`
	LastRead        *time.Time        `json:"last_read,omitempty"`
	Reads           int               `json:"reads,omitempty"`
}

// viewOf builds a secretView, attaching last-read info when it is known (zero time = never).
func viewOf(name string, sec *store.Secret, lastRead time.Time, reads int) secretView {
	v := secretView{
		Name: name, Tags: sec.Tags, Description: sec.Description,
		Created: sec.CreatedAt, Updated: sec.UpdatedAt,
		RotateAfter: sec.RotateAfter, ExpiresAt: sec.ExpiresAt, Expired: sec.Expired(time.Now()),
		NoPrint: sec.NoPrint, RequireApproval: sec.RequireApproval, Meta: sec.Meta,
		Reads: reads,
	}
	if !lastRead.IsZero() {
		v.LastRead = &lastRead
	}
	return v
}

// eventView is the JSON representation of one audit event.
type eventView struct {
	Time    time.Time `json:"time"`
	Op      string    `json:"op"`
	Name    string    `json:"name"`
	Agent   string    `json:"agent,omitempty"`
	Version string    `json:"version,omitempty"`
	Session string    `json:"session,omitempty"`
	Actor   string    `json:"actor,omitempty"`
	Caller  string    `json:"caller,omitempty"`
}

// staleView is the JSON representation of a rotation-due / expiring secret.
type staleView struct {
	Name        string     `json:"name"`
	RotateAfter *time.Time `json:"rotate_after,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Status      []string   `json:"status"`
}

// emitJSON writes v to stdout as indented JSON with a trailing newline. The bytes pass through
// sanitizeJSONBytes so metadata control characters that Go's encoder leaves raw (DEL/C1) can't
// reach a consumer's terminal (FU-6) — the JSON analogue of the SEC-07 table sanitizer.
func emitJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(sanitizeJSONBytes(b), '\n'))
	return err
}
