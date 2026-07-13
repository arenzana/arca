// `arca doctor`: a read-only, secure-by-default health check. It turns the security tribal knowledge
// ("don't commit your identity key", "who can decrypt this?", "is a master key on too many hosts?",
// "is the MCP server wide open to agents?") into one command every user can run. Findings are ranked
// by severity, each with a one-line why and the exact remediation; `--json` for CI (non-zero exit on
// any HIGH), `--fix` applies only the unambiguously safe repairs.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/store"
)

type severity int

const (
	sevOK severity = iota
	sevLow
	sevMed
	sevHigh
)

func (s severity) label() string {
	switch s {
	case sevHigh:
		return "HIGH"
	case sevMed:
		return "MED"
	case sevLow:
		return "LOW"
	default:
		return "OK"
	}
}

type finding struct {
	Severity string `json:"severity"`
	Check    string `json:"check"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Remedy   string `json:"remedy,omitempty"`
	sev      severity
}

func f(check string, sev severity, title, detail, remedy string) finding {
	return finding{Severity: sev.label(), Check: check, Title: title, Detail: detail, Remedy: remedy, sev: sev}
}

// doctorEnv is the shared, pre-loaded state the checks inspect (loaded once, read-only).
type doctorEnv struct {
	store        *store.Store
	storeErr     error
	identityPath string
	storePath    string
}

// gitRoot walks up from dir looking for a `.git` entry (dir or file). Returns the repo root, or "".
// Dependency-free stand-in for `git rev-parse` — enough to catch "identity key inside a git repo".
func gitRoot(dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// --- checks ---------------------------------------------------------------

func checkIdentity(e *doctorEnv) []finding {
	var out []finding
	fi, err := os.Stat(e.identityPath)
	if err != nil {
		// No identity file is normal when the key is a plugin/hardware stanza or SOPS_AGE_KEY_FILE;
		// report it low so it's visible without being alarming.
		return []finding{f("identity", sevLow, "identity key file not found at the default path",
			e.identityPath+" — fine if you use SOPS_AGE_KEY_FILE/ARCA_IDENTITY or a hardware key", "")}
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		out = append(out, f("identity", sevHigh,
			fmt.Sprintf("identity key is mode %o (group/other can read it)", perm),
			"anyone who can read this file can decrypt every secret you can", "chmod 600 "+e.identityPath+"   (or run `arca doctor --fix`)"))
	}
	if root := gitRoot(filepath.Dir(e.identityPath)); root != "" {
		out = append(out, f("identity", sevHigh,
			"identity key lives inside a git repository",
			"your age PRIVATE key is under "+root+" — committing it exposes every secret",
			"move the key out of the repo, or ensure it is gitignored and never committed"))
	}
	if len(out) == 0 {
		out = append(out, f("identity", sevOK, "identity key permissions and location look safe", "", ""))
	}
	return out
}

func checkReadership(e *doctorEnv) []finding {
	if e.store == nil {
		return nil
	}
	n := len(e.store.Recipients)
	unlabeled := 0
	for _, r := range e.store.Recipients {
		if e.store.Label(r) == "" {
			unlabeled++
		}
	}
	sev := sevOK
	detail := fmt.Sprintf("%d recipient(s) can decrypt the store", n)
	if unlabeled > 0 {
		sev = sevLow
		detail += fmt.Sprintf("; %d unlabeled (can't tell who/which machine they are)", unlabeled)
	}
	return []finding{f("readership", sev, "store decryption blast radius", detail,
		"review with `arca who-can-read`; name keys via `arca recipients add <key> --label name@machine`")}
}

func checkSensitive(e *doctorEnv) []finding {
	if e.store == nil {
		return nil
	}
	var names []string
	for _, name := range e.store.Names() {
		sec := e.store.Secrets[name]
		if looksSensitive(name, sec.Tags, sec.Description) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return []finding{f("sensitive", sevOK, "no obviously high-privilege secret names", "", "")}
	}
	sort.Strings(names)
	sev := sevLow
	if len(e.store.Recipients) > 1 {
		sev = sevMed // a master-looking secret readable on multiple machines is the real concern
	}
	preview := names
	if len(preview) > 8 {
		preview = preview[:8]
	}
	return []finding{f("sensitive", sev,
		fmt.Sprintf("%d secret(s) look high-privilege, each readable by %d recipient(s)", len(names), len(e.store.Recipients)),
		fmt.Sprintf("%v — confirm each is least-privilege (scoped, not a master/root key) and that every recipient needs it", preview),
		"inspect with `arca exposure`; prefer bucket/service-scoped credentials over master keys")}
}

func checkRotationExpiry(e *doctorEnv) []finding {
	if e.store == nil {
		return nil
	}
	now := time.Now()
	var dueRot, expired, disabled int
	for _, name := range e.store.Names() {
		sec := e.store.Secrets[name]
		if sec.RotateAfter != nil && !sec.RotateAfter.After(now) {
			dueRot++
		}
		if sec.Expired(now) {
			expired++
		}
		if sec.Disabled {
			disabled++
		}
	}
	var out []finding
	if dueRot > 0 {
		out = append(out, f("rotation", sevLow, fmt.Sprintf("%d secret(s) past their rotate-after date", dueRot),
			"", "see `arca stale`, then `arca rotate NAME`"))
	}
	if expired > 0 {
		out = append(out, f("expiry", sevLow, fmt.Sprintf("%d expired secret(s) still present", expired),
			"expired secrets are refused everywhere but linger in the store", "`arca rm NAME` or re-`set`/`rotate` with a new expiry"))
	}
	if disabled > 0 {
		out = append(out, f("expiry", sevLow, fmt.Sprintf("%d disabled secret(s)", disabled),
			"", "`arca enable NAME` to restore or `arca rm NAME` to prune"))
	}
	if len(out) == 0 {
		out = append(out, f("rotation", sevOK, "no overdue rotations or expired/disabled leftovers", "", ""))
	}
	return out
}

func checkAgentExposure(e *doctorEnv) []finding {
	if e.store == nil {
		return nil
	}
	total := len(e.store.Secrets)
	exposed := 0
	for _, name := range e.store.Names() {
		if e.store.Secrets[name].AgentExposed {
			exposed++
		}
	}
	// arca can't know how the MCP server is launched, so it reports the standing risk: without
	// --strict, ALL secrets are reachable by a connected agent.
	sev := sevMed
	if total == 0 {
		sev = sevOK
	}
	return []finding{f("agents", sev,
		"MCP agent exposure is deny-by-default only under --strict",
		fmt.Sprintf("%d/%d secret(s) are agent-exposed; if you run `arca mcp` WITHOUT --strict, an agent can reach all %d", exposed, total, total),
		"run the server as `arca mcp --strict` (or ARCA_AGENT_STRICT=1) and `arca agent allow NAME` only what agents need")}
}

func checkAudit(_ *doctorEnv) []finding {
	a, err := audit.Open(auditPath())
	if err != nil {
		return []finding{f("audit", sevMed, "could not open the audit log", err.Error(), "")}
	}
	defer a.Close()
	res, err := a.Verify()
	if err != nil {
		return []finding{f("audit", sevMed, "audit verification could not run", err.Error(), "")}
	}
	if !res.OK {
		return []finding{f("audit", sevHigh, "audit chain is BROKEN",
			fmt.Sprintf("%s (checked %d event(s))", res.Reason, res.Checked),
			"investigate tampering/rollback; see `arca log --verify`")}
	}
	// Off-machine tamper-evidence: is a durable witness (sync/escrow, or an external anchor) in place?
	if _, err := syncURL(); err != nil {
		return []finding{f("audit", sevLow,
			fmt.Sprintf("audit chain OK (%d event(s)) but no off-machine witness", res.Checked),
			"a local-only log can be rewritten by whoever controls this machine",
			"configure `arca sync` (escrows the audit off-host) or pin an external anchor")}
	}
	return []finding{f("audit", sevOK, fmt.Sprintf("audit chain verifies (%d event(s)), sync witness configured", res.Checked), "", "")}
}

func checkSync(_ *doctorEnv) []finding {
	url, err := syncURL()
	if err != nil {
		return []finding{f("sync", sevLow, "sync is not configured",
			"the store lives only on this machine — a disk loss loses it", "`arca sync init URL` to replicate to an S3-compatible backend")}
	}
	cfg := loadSyncConfig()
	detail := "backend: " + url
	if cfg.AccessKey != "" || cfg.SecretKey != "" {
		detail += " (credentials stored at rest in the state dir, 0600)"
	}
	return []finding{f("sync", sevOK, "sync configured", detail, "")}
}

var doctorChecks = []func(*doctorEnv) []finding{
	checkIdentity, checkReadership, checkSensitive, checkRotationExpiry, checkAgentExposure, checkAudit, checkSync,
}

func runDoctor() []finding {
	e := &doctorEnv{identityPath: identityPath(), storePath: storePath()}
	if s, err := store.Load(storePath()); err == nil {
		e.store = s
	} else {
		e.storeErr = err
	}
	var all []finding
	if e.store == nil {
		all = append(all, f("store", sevLow, "no store loaded", e.storeErr.Error(), "`arca init` to create one"))
	}
	for _, c := range doctorChecks {
		all = append(all, c(e)...)
	}
	return all
}

// fixIdentityPerms is the one unambiguously safe auto-repair: tighten a loose identity key to 0600.
func fixIdentityPerms() (bool, error) {
	p := identityPath()
	fi, err := os.Stat(p)
	if err != nil {
		return false, nil
	}
	if fi.Mode().Perm()&0o077 == 0 {
		return false, nil
	}
	return true, os.Chmod(p, 0o600)
}

// errDoctorHigh is returned (silently) when doctor finds a HIGH severity issue, so `arca doctor`
// exits non-zero as a CI gate without os.Exit (which would kill in-process tests). SilenceErrors on
// the command keeps cobra from printing it — the findings are already the output.
var errDoctorHigh = fmt.Errorf("doctor: high-severity findings")

func newDoctor() *cobra.Command {
	var jsonOut, fix bool
	c := &cobra.Command{
		Use:           "doctor",
		Short:         "Security & health check of your arca setup (read-only; --fix applies safe repairs)",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			if fix {
				if fixed, err := fixIdentityPerms(); err != nil {
					return err
				} else if fixed {
					fmt.Fprintln(os.Stderr, "fixed: identity key permissions set to 600")
				}
			}
			findings := runDoctor()
			// Order most-severe first for display.
			sort.SliceStable(findings, func(i, j int) bool { return findings[i].sev > findings[j].sev })
			if jsonOut {
				if err := emitJSON(findings); err != nil {
					return err
				}
			} else {
				var high, med, low int
				for _, fnd := range findings {
					switch fnd.sev {
					case sevHigh:
						high++
					case sevMed:
						med++
					case sevLow:
						low++
					}
					if fnd.sev == sevOK {
						continue // keep the report focused on what needs attention
					}
					fmt.Printf("[%-4s] %s\n", fnd.Severity, fnd.Title)
					if fnd.Detail != "" {
						fmt.Printf("        %s\n", fnd.Detail)
					}
					if fnd.Remedy != "" {
						fmt.Printf("        → %s\n", fnd.Remedy)
					}
				}
				if high+med+low == 0 {
					fmt.Println("✓ all checks clear")
				} else {
					fmt.Printf("\n%d high, %d medium, %d low. (OK checks hidden.)\n", high, med, low)
				}
			}
			// Non-zero exit on any HIGH so `arca doctor` is a usable CI gate.
			for _, fnd := range findings {
				if fnd.sev == sevHigh {
					return errDoctorHigh
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&jsonOut, "json", false, "output findings as JSON")
	c.Flags().BoolVar(&fix, "fix", false, "apply the unambiguously safe repairs (e.g. chmod the identity key to 600)")
	return c
}
