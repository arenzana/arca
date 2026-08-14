// Command arca is an age-encrypted secret store with cleartext metadata and a local audit log,
// designed to sit safely in front of AI agents.
//
// The CLI is intentionally split into three "access shapes" with different trust levels:
//
//   - get / env    — reveal a value to stdout (blocked for --no-print secrets);
//   - inject       — resolve arca://NAME references in a template to stdout (also blocked for
//     --no-print secrets);
//   - exec         — inject values into a subprocess's environment, so a command can *use* a
//     secret while the value never appears on arca's stdout or in an agent's
//     context. This is the sanctioned path for --no-print secrets.
//
// Every access is written to the audit log with the calling AI agent's name/version/session
// (auto-detected) plus an explicit $ARCA_ACTOR, so `arca log` can answer who touched what.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/arenzana/arca/internal/atomicfile"
	"github.com/arenzana/arca/internal/audit"
	"github.com/arenzana/arca/internal/crypto"
	"github.com/arenzana/arca/internal/store"
)

// version is set at release time via -ldflags "-X main.version=...".
var version = "dev"

// appVersion returns the build version: the ldflags-injected value for a release build, the
// module version from the build info for a `go install module@version` build, or "dev".
func appVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

// versionView is the full build stamp: version plus the VCS commit/date Go embeds and the
// toolchain/platform. Emitted by `arca version` (and `--json` for scripts/agents).
type versionView struct {
	Version  string `json:"version"`
	Commit   string `json:"commit,omitempty"`
	Date     string `json:"date,omitempty"`
	Go       string `json:"go"`
	Platform string `json:"platform"`
}

func buildStamp() versionView {
	v := versionView{Version: appVersion(), Go: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				v.Commit = s.Value
			case "vcs.time":
				v.Date = s.Value
			}
		}
	}
	return v
}

// formatVersion renders the build stamp for humans as an aligned key/value table (the commit is
// short-hashed to 12 chars; the commit/date rows are omitted when the values aren't embedded, e.g.
// a `go build` without VCS). Label column width is computed so every value lines up.
func formatVersion(v versionView) string {
	commit := v.Commit
	if len(commit) > 12 {
		commit = commit[:12]
	}
	rows := [][2]string{{"version", v.Version}}
	if commit != "" {
		rows = append(rows, [2]string{"commit", commit})
	}
	if v.Date != "" {
		rows = append(rows, [2]string{"built", v.Date})
	}
	rows = append(rows, [2]string{"go", v.Go}, [2]string{"platform", v.Platform})

	w := 0
	for _, r := range rows {
		if len(r[0]) > w {
			w = len(r[0])
		}
	}
	var b strings.Builder
	b.WriteString("arca\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "  %-*s  %s\n", w+1, r[0]+":", r[1])
	}
	return b.String()
}

// newVersion prints the build stamp. `arca --version` already prints just the version string;
// this subcommand adds the commit, build date, and toolchain, and a --json form.
func newVersion() *cobra.Command {
	var jsonOut bool
	c := &cobra.Command{
		Use:   "version",
		Short: "Print version, commit, and build info",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			v := buildStamp()
			if jsonOut {
				return emitJSON(v)
			}
			fmt.Print(formatVersion(v))
			return nil
		},
	}
	c.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return c
}

func main() {
	// Every command that touches a value holds it in cleartext on the heap for the life of the
	// process: `get` and `inject` decrypt to stdout, `exec` and the MCP tools additionally keep
	// the value in redactPattern and in the child's environment, and `reencrypt` holds every
	// secret in the store at once. A core dump on a host that collects them would contain all of
	// it, defeating every disclosure control arca applies above. Do this before the command runs,
	// once, for the whole binary rather than per-command — there is no command for which leaving
	// core dumps enabled is the better default, and a per-command allow-list is a branch to get
	// wrong later.
	//
	// Best-effort: a host that refuses is not a reason to refuse service, but the operator should
	// know the exposure is still open.
	if err := disableCoreDumps(); err != nil {
		fmt.Fprintf(os.Stderr, "arca: warning: could not disable core dumps (%v) — a crash dump could contain secret values\n", err)
	}
	// Cobra prints the error itself (SilenceErrors=false); we just set the exit code.
	if err := newRoot().Execute(); err != nil {
		os.Exit(1)
	}
}

// newRoot builds the command tree. It's a constructor (not a package-level var) so tests can
// get a fresh, isolated command instance per invocation.
func newRoot() *cobra.Command {
	// Per-invocation state: the real CLI builds one root per process; in-process tests
	// build one per command and must not leak the previous command's store view.
	curStore, loadedGeneration = nil, -1
	root := &cobra.Command{
		Use:           "arca",
		Short:         "age-encrypted secrets with metadata and an audit log",
		Long:          "arca stores secrets as age-encrypted values with cleartext metadata in a JSON\nstore, and records every access in a local SQLite audit log.",
		Version:       appVersion(),
		SilenceUsage:  true, // don't dump usage on every runtime error
		SilenceErrors: false,
	}
	cmds := []*cobra.Command{
		newInit(), newSet(), newGet(), newRotate(), newLs(), newShow(), newStale(),
		newRm(), newDisable(), newEnable(), newImport(), newInject(), newExec(), newEnv(), newLog(), newMCP(),
		newRecipients(), newReencrypt(), newGenerate(), newEdit(), newRename(), newAnnotate(), newCanary(),
		newGrant(), newGrants(), newRevoke(), newHandle(), newSync(), newVersion(),
		newWhoCanRead(), newExposure(), newAgent(), newDoctor(),
	}
	root.AddCommand(cmds...)
	registerCompletions(cmds)
	// The audit-redirect refusal (R4/D2) runs before any command's work, so a refused command
	// has not already written the store or disclosed a secret. Root is the only place in the tree
	// that sets a persistent pre-run hook: cobra runs the nearest one and stops, so a hook added
	// to a subcommand later would silently shadow this one. If that ever becomes necessary, the
	// subcommand's hook must call checkAuditRedirect() itself.
	//
	// `arca --version` and `arca --help` return inside cobra before persistent hooks run, which is
	// why they stay usable under the refusal. That is fine: neither reads a secret or the log.
	root.PersistentPreRunE = func(_ *cobra.Command, _ []string) error { return checkAuditRedirect() }
	// Opportunistic auto-sync runs strictly AFTER a command's real work — never in an
	// access path — and only when enabled (`arca sync auto on` / ARCA_SYNC_AUTO=1).
	// The sync command itself is excluded (it already synced, or failed loudly).
	root.PersistentPostRun = func(cmd *cobra.Command, _ []string) {
		invokedSync := false
		for c := cmd; c != nil; c = c.Parent() {
			if c.Name() == "sync" {
				invokedSync = true
				break
			}
		}
		maybeAutoSync(invokedSync)
	}
	return root
}

// ----------------------------------------------------------------------------
// Paths. All three locations are overridable via env so the store can be pointed at a
// dotfiles repo (git-synced) while the audit DB stays local, and tests can sandbox everything.
// ----------------------------------------------------------------------------

// xdgHome returns $env if set, else $HOME/def — an XDG-with-fallback helper.
func xdgHome(env, def string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, def)
}

func configDir() string { return filepath.Join(xdgHome("XDG_CONFIG_HOME", ".config"), "arca") }
func stateDir() string  { return filepath.Join(xdgHome("XDG_STATE_HOME", ".local/state"), "arca") }

// storePath is the JSON store (git-syncable). Override with $ARCA_STORE.
func storePath() string {
	if p := os.Getenv("ARCA_STORE"); p != "" {
		return p
	}
	return filepath.Join(configDir(), "store.json")
}

// defaultAuditPath is where the audit DB lives when $ARCA_AUDIT is not set: inside the active
// store's state dir, because it is per-store data. Two stores sharing one audit DB interleave
// their chains, so `log --verify` on either reads the other's events as its own.
//
// Calling this resolves the store state dir, which triggers one-time legacy adoption (D4).
// checkAuditRedirect deliberately calls it only after the cheap env checks have already decided
// the answer might be "refuse", so an ordinary command never pays for it twice and a *refused*
// command does not silently perform a state migration on its way out.
func defaultAuditPath() string { return filepath.Join(storeStateDir(), "audit.db") }

// auditPath is the local SQLite audit DB (do not sync). Override with $ARCA_AUDIT.
//
// $ARCA_AUDIT wins, which is how an operator deliberately points several stores at one log — but
// only for a caller that is not a detected AI agent. See checkAuditRedirect.
func auditPath() string {
	if p := os.Getenv("ARCA_AUDIT"); p != "" {
		return p
	}
	return defaultAuditPath()
}

// checkAuditRedirect refuses the whole command when a detected agent has pointed $ARCA_AUDIT at
// anything other than this store's own audit DB (finding R4, ruling D2).
//
// The exploit it closes: auditPath() honours the environment unconditionally, and an agent
// controls its own environment. Redirecting the DB to a scratch file gives the agent an audit log
// nobody reads, an empty rate-limit window on every secret (checkRateLimit counts events in *that*
// DB), and a canary registry whose trips land somewhere the operator never looks — all while
// `arca log`, `arca canary --list` and `arca doctor` stay clean against the real log.
//
// It refuses rather than ignoring the variable and falling back to the real DB. Ignoring is the
// worse failure: the agent believes it is unaudited and behaves accordingly, while the operator
// gets a log that silently contradicts the environment they can see. Refusing is the fail-closed
// direction and it is the direction that is visible from both sides.
//
// Deliberately NOT anchored to a controlling terminal the way the lax-ARCA_STRICT_AUDIT hatch is
// (SEC-06). strictAudit() grants the TTY hatch only to a caller that is *not* a detected agent —
// "an AI agent must not be able to weaken fail-closed auditing on itself" — and redirecting the
// audit log is precisely that. An agent under a pty (tmux, a pty-allocating harness) has a
// controlling terminal, so a TTY hatch here would hand the exploit straight back. The escape for a
// human whose shell happens to export an agent marker is to unset the marker, which the error says.
func checkAuditRedirect() error {
	p := os.Getenv("ARCA_AUDIT")
	if p == "" {
		return nil // not overridden; nothing to refuse
	}
	id := detectIdentity()
	if id.Agent == "" {
		return nil // an operator may point several stores at one log
	}
	// Only now is the state dir worth resolving: both checks above are pure env reads.
	if sameFile(p, defaultAuditPath()) {
		return nil // pointed at the default anyway — no redirection, nothing gained
	}
	// The agent name and the path both come from the environment the agent controls, and this
	// string lands on the operator's terminal — sanitize before writing (SEC-07).
	return fmt.Errorf("refusing to run: $ARCA_AUDIT points the audit log at %s, but this process is detected as the agent %q — an agent must not redirect its own audit log. Unset $ARCA_AUDIT (the log for this store lives in %s), or unset the agent marker if you are a human",
		sanitize(p), sanitize(id.Agent), sanitize(defaultAuditPath()))
}

// identityPath is the age private key. It defaults to reusing the caller's existing
// $SOPS_AGE_KEY_FILE so arca shares one key with sops; override with $ARCA_IDENTITY.
func identityPath() string {
	if p := os.Getenv("ARCA_IDENTITY"); p != "" {
		return p
	}
	if p := os.Getenv("SOPS_AGE_KEY_FILE"); p != "" {
		return p
	}
	return filepath.Join(configDir(), "identity.txt")
}

// ----------------------------------------------------------------------------
// Shared helpers.
// ----------------------------------------------------------------------------

// openStore loads the JSON store and warns if it looks rolled back — its monotonic generation
// counter went backwards versus the highest we've recorded locally. That catches a git revert, a
// sync conflict, or an attacker restoring an old copy to resurrect a rotated or deleted secret
// (SEC-14). It's a best-effort *warning*, not a hard stop: the high-water mark is a local heuristic
// (a machine owner can delete it), and a store can legitimately be fresh on a new machine.
func openStore() (*store.Store, error) {
	s, err := store.Load(storePath())
	if err != nil {
		return nil, err
	}
	warnIfStoreRolledBack(s.Generation)
	migrateLegacyCanaries(s)
	if loadedGeneration < 0 {
		loadedGeneration = s.Generation // first load of this invocation = the pre-command generation
	}
	curStore = s
	return s, nil
}

// curStore is the store handle this invocation loaded, kept so recordAudit can bind the store
// generation the operation observed into its (hashed, signed) audit event (SEC-14). Save bumps
// Generation in memory, so an event logged after a write records the post-write generation.
// arca is a short-lived single-command process; there is exactly one store per invocation.
var curStore *store.Store

// loadedGeneration is the store generation as first loaded this invocation (-1 = never loaded);
// curStore.Generation moving past it is how auto-sync knows the command mutated the store.
var loadedGeneration = -1

// storeGenPath is the local high-water mark of the store generation (state dir, never synced).
func storeGenPath() string { return filepath.Join(storeStateDir(), "store.gen") }

// storeGenHWM reads the local high-water mark without advancing it (0 if unset). Used as a
// durable rollback floor on pull (SEC-35): the newest store generation this machine has ever
// observed, which a network attacker cannot lower without also controlling the local state dir.
func storeGenHWM() int {
	if b, err := os.ReadFile(storeGenPath()); err == nil { //#nosec G304 -- our own state-dir path
		n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		return n
	}
	return 0
}

func warnIfStoreRolledBack(gen int) {
	if regressed, prev := recordStoreGeneration(gen); regressed {
		warnStoreRolledBack(gen, prev)
	}
}

// warnStoreRolledBack emits the SEC-14 rollback notice. It is split out of
// warnIfStoreRolledBack so a caller that must not write can still warn: the sync snapshot is
// taken outside the store lock (D1 invariant I2), and recordStoreGeneration writes store.gen.
// The high-water mark advances later, in sync's commit path, under the lock.
func warnStoreRolledBack(gen, prev int) {
	fmt.Fprintf(os.Stderr, "arca: warning: the store looks rolled back (generation %d < last seen %d) — a rotated or deleted secret may have been resurrected; check the store's git history\n", gen, prev)
}

// recordStoreGeneration compares gen against the local high-water mark, advances the mark when gen
// is higher, and reports whether gen regressed (a possible rollback) plus the mark it was compared
// against. A rollback does NOT lower the mark, so the warning persists until the store advances
// past it again. All file I/O is best-effort — a warning heuristic must never break a command.
func recordStoreGeneration(gen int) (regressed bool, prev int) {
	hwm := 0
	if b, err := os.ReadFile(storeGenPath()); err == nil { //#nosec G304 -- our own state-dir path
		hwm, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	if gen < hwm {
		return true, hwm
	}
	if gen > hwm {
		// Deliberately best-effort, including the parent-dir fsync inside the helper: this is a
		// warning heuristic, and losing the high-water mark to a crash costs a missed warning,
		// never a command. Every other state writer treats the same error as fatal.
		_ = atomicfile.Write(storeGenPath(), []byte(strconv.Itoa(gen)), 0o600)
	}
	return false, hwm
}
func loadIDs() ([]age.Identity, error) { return crypto.LoadIdentities(identityPath()) }

// logAudit records one access event. Auditing is fail-closed by DEFAULT: if the audit log
// cannot be written, the operation is aborted (the error is returned). For reads, callers log
// *before* revealing the secret, so a secret that cannot be audited is never disclosed.
//
// Set ARCA_STRICT_AUDIT to a falsey value (0/false/off/no) to opt into best-effort auditing,
// where a failed audit write is swallowed and never breaks the operation. The override is
// honored only for a human at a controlling terminal (SEC-06).
func logAudit(op, name, caller string) error {
	if err := recordAudit(op, name, caller); err != nil {
		if strictAudit() {
			return fmt.Errorf("audit failed (fail-closed; a human at a terminal may set ARCA_STRICT_AUDIT=0 to override): %w", err)
		}
		// best-effort: swallow
	}
	return nil
}

// recordAudit opens the audit log and writes one event with the auto-detected identity.
func recordAudit(op, name, caller string) error {
	// When the caller isn't set explicitly (exec/run_with_secrets pass the command), record the
	// process that invoked arca — so `log` shows who ran a get/set, not a blank.
	if caller == "" {
		caller = parentCommand()
	}
	a, err := audit.Open(auditPath())
	if err != nil {
		return err
	}
	defer a.Close()
	// Sign events with the session key so the log is tamper-evident and attributable. If the key
	// can't be set up, still record (chained but unsigned) rather than dropping the audit entry —
	// but warn, because a silently unsigned event is indistinguishable from a stripped signature at
	// verify time (see `log --verify --require-signed`).
	if s, err := auditSigner(); err == nil {
		a.UseSigner(s)
	} else {
		fmt.Fprintf(os.Stderr, "arca: warning: recording an UNSIGNED audit event (signer unavailable: %v)\n", err)
	}
	gen := 0
	if curStore != nil {
		gen = curStore.Generation
	}
	return a.RecordGen(op, name, caller, detectIdentity(), gen)
}

// strictAudit reports whether fail-closed auditing is in effect. It is the DEFAULT; set
// ARCA_STRICT_AUDIT to a falsey value (0/false/off/no/lax) to opt into best-effort auditing.
func strictAudit() bool {
	// An AI agent must not be able to weaken fail-closed auditing on itself; the lax override
	// is honored only for a non-agent caller. Detection is env-based and an agent controls its
	// own environment, so the override is additionally anchored to the one thing an agent
	// can't conjure: a controlling terminal (SEC-06). No terminal, no laxness.
	if detectIdentity().Agent != "" || !hasControllingTTY() {
		return true
	}
	switch strings.ToLower(os.Getenv("ARCA_STRICT_AUDIT")) {
	case "0", "false", "off", "no", "lax", "best-effort":
		return false
	}
	return true
}

// hasControllingTTY reports whether the process has a controlling terminal. It anchors the
// human-only escape hatches (lax ARCA_STRICT_AUDIT, `get --no-log`) the same way approval is
// anchored (SEC-06): agent detection is advisory — an agent can scrub its own env markers —
// but it cannot open /dev/tty (or CONIN$) when no human terminal exists.
func hasControllingTTY() bool {
	in, out, err := openTTY()
	if err != nil {
		return false
	}
	in.Close()
	if out != in {
		out.Close()
	}
	return true
}

// osUser returns the local OS username, used as the default audit actor when $ARCA_ACTOR isn't set.
func osUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	return os.Getenv("USERNAME") // Windows
}

// parentCommand best-effort resolves the command that invoked arca (the parent process), used as
// the default audit caller. It's memoized because a short-lived arca process has one parent, and
// the macOS/BSD path shells out to `ps`.
var (
	parentOnce sync.Once
	parentVal  string
)

func parentCommand() string {
	parentOnce.Do(func() { parentVal = computeParentCommand() })
	return parentVal
}

func computeParentCommand() string {
	ppid := os.Getppid()
	// Linux exposes the parent's name directly.
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", ppid)); err == nil { //#nosec G304 -- /proc path built from our own ppid
		return strings.TrimSpace(string(b))
	}
	return psCommand(ppid) // macOS / BSD fallback
}

// psCommand asks `ps` for a pid's command name. Split out so it's directly testable (ps exists on
// Linux too, even though computeParentCommand prefers /proc there).
func psCommand(pid int) string {
	out, err := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output() //#nosec G204 -- fixed args; pid is an int
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(filepath.Base(strings.TrimSpace(string(out))), "-") // strip login-shell "-"
}

// agentSig identifies one AI coding-agent runtime by the environment variables it injects into the
// commands it launches. Detection is ADVISORY, not a security boundary: these vars are set by the
// agent's own runtime, so a *cooperating* agent is attributed correctly, but a hostile one can unset
// them — which is why the load-bearing control (--require-approval) is anchored on a real terminal,
// not on this (see SEC-06). Detection drives audit attribution, output redaction (SEC-11), and the
// advisory ARCA_STRICT_AUDIT / --no-log knobs.
//
// Key ONLY on runtime/session markers a harness sets — never on API-key vars (OPENAI_API_KEY,
// GEMINI_API_KEY, ANTHROPIC_API_KEY, …), which countless non-agent scripts set and would
// misclassify. To add an agent, append a row here. Any agent not listed can still self-identify via
// the generic AI_AGENT variable below.
type agentSig struct {
	name    string        // canonical agent name recorded in the audit log
	detect  []string      // agent is present if ANY of these env vars is non-empty
	session string        // env var holding a session id, if the agent exposes one
	version func() string // derive a version string, if available
}

var agentSignatures = []agentSig{
	{
		name:    "claude-code",
		detect:  []string{"CLAUDECODE", "CLAUDE_CODE_SESSION_ID"},
		session: "CLAUDE_CODE_SESSION_ID",
		// Claude Code's binary lives under .../<version>/claude, so the version falls out of the path.
		version: func() string { return firstSemver(os.Getenv("CLAUDE_CODE_EXECPATH")) },
	},
	{name: "cursor", detect: []string{"CURSOR_TRACE_ID"}, session: "CURSOR_TRACE_ID"},
	{name: "gemini-cli", detect: []string{"GEMINI_CLI"}},                                 // Gemini CLI sets GEMINI_CLI=1 in shell subprocesses
	{name: "codex", detect: []string{"CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED"}}, // OpenAI Codex sandbox markers
}

// customAgentSignatures parses ARCA_AGENT_MARKERS — a comma-separated list of `name=ENVVAR` pairs —
// so an operator can teach arca to recognize an agent that isn't built in (opencode, Kimi, Aider,
// Copilot CLI, …) without a code change, e.g.
//
//	ARCA_AGENT_MARKERS="opencode=OPENCODE,kimi=KIMI_CODE_HOME"
//
// The right-hand side is an env-var NAME whose presence marks the agent — NOT a value, and pointedly
// NOT an API-key var, which non-agent scripts also set. Any agent can equally self-identify with the
// generic AI_AGENT variable.
func customAgentSignatures() []agentSig {
	raw := os.Getenv("ARCA_AGENT_MARKERS")
	if raw == "" {
		return nil
	}
	var sigs []agentSig
	for _, pair := range strings.Split(raw, ",") {
		name, envvar, ok := strings.Cut(strings.TrimSpace(pair), "=")
		name, envvar = strings.TrimSpace(name), strings.TrimSpace(envvar)
		if !ok || name == "" || envvar == "" {
			continue
		}
		sigs = append(sigs, agentSig{name: name, detect: []string{envvar}})
	}
	return sigs
}

// agentEnvVars returns every environment variable the detection table (and the AI_AGENT fallback)
// consults. Tests clear these so the suite is deterministic no matter which agent launched it.
func agentEnvVars() []string {
	seen := map[string]bool{}
	var out []string
	add := func(k string) {
		if k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, sig := range agentSignatures {
		for _, k := range sig.detect {
			add(k)
		}
		add(sig.session)
	}
	add("CLAUDE_CODE_EXECPATH")
	add("AI_AGENT")
	return out
}

// detectIdentity figures out who/what is accessing a secret: the explicit $ARCA_ACTOR plus an
// auto-detected AI agent (name, version, session) from well-known environment variables. This
// is what lets `arca log` attribute access to a specific agent session without the user
// having to configure anything.
func detectIdentity() audit.Identity {
	id := audit.Identity{Actor: os.Getenv("ARCA_ACTOR")}
	if id.Actor == "" {
		id.Actor = osUser() // fall back to the OS user so the actor is never blank
	}
	// Built-in signatures first (canonical names win), then any operator-registered custom markers.
	sigs := agentSignatures
	if custom := customAgentSignatures(); len(custom) > 0 {
		sigs = append(append([]agentSig{}, agentSignatures...), custom...)
	}
	for _, sig := range sigs {
		if !envSet(sig.detect...) {
			continue
		}
		id.Agent = sig.name
		if sig.session != "" {
			id.Session = os.Getenv(sig.session)
		}
		if sig.version != nil {
			id.Version = sig.version()
		}
		break
	}
	// Generic fallback for any other agent: AI_AGENT="name_version_agent"
	// (e.g. "claude-code_2-1-181_agent"); the version uses '-' for '.'.
	if id.Agent == "" {
		if ai := os.Getenv("AI_AGENT"); ai != "" {
			parts := strings.SplitN(ai, "_", 3)
			id.Agent = parts[0]
			if len(parts) > 1 {
				id.Version = strings.ReplaceAll(parts[1], "-", ".")
			}
		}
	}
	return id
}

// envSet reports whether any of the named environment variables is non-empty.
func envSet(keys ...string) bool {
	for _, k := range keys {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

var semverRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

// firstSemver pulls the first "X.Y.Z" out of s (e.g. a version embedded in a path), or "".
func firstSemver(s string) string { return semverRe.FindString(s) }

// shortID truncates long ids (e.g. session UUIDs) for compact table display.
func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// readValue reads a secret from a TTY without echo, or from piped stdin. Secrets are NEVER
// taken as command-line arguments (which would leak via shell history / `ps`).
// maxInputBytes caps a single secret value / inject template read from stdin (DoS guard).
const maxInputBytes = 16 << 20 // 16 MiB

// readAllLimited reads up to max bytes from r, erroring if the input exceeds it rather than
// silently truncating.
func readAllLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("input exceeds the %d-byte limit", max)
	}
	return b, nil
}

// errEmptyValue reports that the value read was empty and the caller did not opt into that.
// Callers translate it into a message naming the secret, because "empty" means something very
// different for a new secret than for one that already holds a value.
var errEmptyValue = errors.New("empty value")

// readValue reads a secret value from the terminal (hidden) or from stdin.
//
// An empty read is refused unless allowEmpty. The failure it guards is the one that costs a
// secret: `producer | arca set PRODKEY` where the producer fails and prints nothing. Stdin
// closes empty, arca reports success, and the previous ciphertext is gone — there is no undo,
// because the store only keeps the current value. Refusing costs a flag; storing costs the
// secret. allowEmpty is a required parameter rather than an option struct so a future caller
// has to decide rather than inherit the unsafe default by omission.
func readValue(prompt string, allowEmpty bool) ([]byte, error) {
	var b []byte
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		p, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, err
		}
		b = p
	} else {
		p, err := readAllLimited(os.Stdin, maxInputBytes)
		if err != nil {
			return nil, err
		}
		// Strip a single trailing newline (from `echo`/editors) but preserve internal newlines,
		// so multi-line secrets like PEM keys round-trip intact.
		b = []byte(strings.TrimRight(string(p), "\r\n"))
	}
	if len(b) == 0 && !allowEmpty {
		return nil, errEmptyValue
	}
	return b, nil
}

// emptyValueError explains a refused empty read in terms of what it would have done: replacing
// a stored value is destructive and unrecoverable, creating an empty one is merely useless.
func emptyValueError(name string, replacing bool) error {
	if replacing {
		return fmt.Errorf("refusing to store an empty value for %s: it would destroy the stored secret and there is no undo "+
			"(a failed upstream command in a pipe reads as empty stdin); pass --allow-empty if you mean it", name)
	}
	return fmt.Errorf("refusing to store an empty value for %s: pass --allow-empty if you mean it", name)
}

func contains(ss []string, x string) bool {
	for _, s := range ss {
		if s == x {
			return true
		}
	}
	return false
}

// shellQuote single-quotes a value for safe `eval` in a POSIX shell (used by `env`).
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// nameRe is the allowed shape of a secret name: a valid shell / environment-variable
// identifier. Enforced on every write (set/import) so a name can never inject shell when
// emitted by `env` (used via `eval "$(arca env)"`) or hijack a variable like LD_PRELOAD when
// injected by `exec`. `inject` already restricts arca://NAME references to this same shape.
var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// reservedEnvNames are environment-variable names that must never be used as a secret name: a
// value injected under one of them (via exec/env/run_with_secrets/handle) hijacks the child
// process rather than being consumed by it. LD_*/DYLD_* load attacker code into the dynamic
// linker; PATH/CDPATH redirect binary lookup; IFS/BASH_ENV/ENV/SHELLOPTS/PS*/PROMPT_COMMAND alter
// shell parsing; the language-runtime hooks below inject libraries or startup code. Because the
// store keeps recipient public keys in cleartext and is meant to be git-synced, anyone who can
// write the store could otherwise craft a correctly-encrypted entry under one of these names and
// get code execution on the operator's next `arca exec`. The shape check (nameRe) alone does NOT
// stop this — every name here is a valid identifier. Matched case-insensitively so a case-folding
// platform (Windows) or a confusable can't slip through.
var reservedEnvNames = map[string]bool{
	"PATH": true, "IFS": true, "BASH_ENV": true, "ENV": true, "SHELLOPTS": true,
	"BASHOPTS": true, "CDPATH": true, "PS1": true, "PS2": true, "PS3": true, "PS4": true,
	"PROMPT_COMMAND": true, "GLOBIGNORE": true, "FIGNORE": true,
	"PERL5LIB": true, "PERL5OPT": true, "PYTHONPATH": true, "PYTHONSTARTUP": true,
	"NODE_OPTIONS": true, "RUBYOPT": true, "RUBYLIB": true, "GEM_PATH": true,
	"GIT_SSH": true, "GIT_SSH_COMMAND": true, "GIT_EXTERNAL_DIFF": true, "GIT_PAGER": true,
	"HOSTALIASES": true, "TERMINFO": true, "TERMCAP": true, "PAGER": true, "EDITOR": true,
}

// reservedName reports whether name would hijack a child process if injected as an environment
// variable. It matches reservedEnvNames case-insensitively plus the dynamic-linker prefixes
// LD_* and DYLD_* (which cover LD_PRELOAD, LD_LIBRARY_PATH, DYLD_INSERT_LIBRARIES, and kin).
func reservedName(name string) bool {
	u := strings.ToUpper(name)
	if reservedEnvNames[u] {
		return true
	}
	return strings.HasPrefix(u, "LD_") || strings.HasPrefix(u, "DYLD_")
}

// validName rejects names that aren't safe identifiers, or that would hijack a child process's
// environment (reserved names like PATH/LD_PRELOAD). It is enforced on every write and re-checked
// at every env-injection site, so an already-poisoned store can't be used either.
func validName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid secret name %q: must match [A-Za-z_][A-Za-z0-9_]*", name)
	}
	if reservedName(name) {
		return fmt.Errorf("secret name %q is a reserved environment variable and can't be used: injecting it would hijack the child process", name)
	}
	return nil
}

// approve enforces a per-secret human approval gate before a value is released. It requires an
// interactive confirmation on the controlling terminal (/dev/tty on Unix, CONIN$/CONOUT$ on
// Windows) every single time — there is deliberately NO environment pre-approval (SEC-06).
//
// The rationale: `--require-approval` means "a person approves each use." arca's earlier
// ARCA_APPROVAL=allow escape tried to let a non-agent pre-approve, gated by env-var-based agent
// detection — but an AI agent controls its own environment, so it could unset the detection vars,
// look like a human, and self-approve. Rather than trust the environment, arca now requires the one
// thing an agent genuinely lacks: a controlling terminal. A human confirms; an agent (no TTY) is
// refused. For "operator authorizes once, then a script or agent runs unattended", use `grant` or
// `handle` — the operator sets it up interactively and the agent scripts against it.
//
// ARCA_APPROVAL=deny still short-circuits to a refusal (fail-safe; the environment can only
// *restrict* access, never grant it).
func approve(name, who string) error {
	switch strings.ToLower(os.Getenv("ARCA_APPROVAL")) {
	case "deny", "no", "0", "false", "off":
		return fmt.Errorf("approval denied for %s", name)
	}
	in, out, err := openTTY()
	if err != nil {
		return fmt.Errorf("%s requires human approval on a terminal, and none is available — to use it unattended, authorize it with `grant`/`handle` instead", name)
	}
	defer in.Close()
	if out != in {
		defer out.Close()
	}
	fmt.Fprintf(out, "Release %q to %s? [y/N] ", name, who)
	var resp string
	_, _ = fmt.Fscanln(in, &resp)
	if strings.EqualFold(strings.TrimSpace(resp), "y") {
		return nil
	}
	return fmt.Errorf("approval declined for %s", name)
}

// approverWho returns a short human-readable descriptor of the requester for the prompt.
func approverWho() string {
	id := detectIdentity()
	switch {
	case id.Agent != "":
		w := id.Agent
		if id.Version != "" {
			w += "/" + id.Version
		}
		if id.Session != "" {
			w += " (" + shortID(id.Session) + ")"
		}
		return w
	case id.Actor != "":
		return id.Actor
	}
	return "this process"
}

// gate runs the approval check for a secret if it requires one. A no-op otherwise.
// gate enforces per-secret policy on every access path. cmdline is the command line the secret is
// about to be used in — set by the command-bearing paths (exec, MCP run_with_secrets), empty for
// the rest (get/env/inject, MCP read_secret).
func gate(sec *store.Secret, name, cmdline string) error {
	// A canary is a decoy that should never legitimately be used: any access through this gate is
	// a tripwire. Alert and record it, and let the access proceed — the value is fake, and letting
	// the caller take it keeps the trap useful (an agent exfiltrating it doesn't learn it was caught).
	// The designation lives in the local registry, not the synced store (SEC-04); isCanary also
	// honors the legacy pre-0.6.2 store flag.
	//
	// The one thing that does block is a trip that could not be RECORDED (D2): an unrecordable
	// tripwire is not a tripwire, and every other access path in arca is already fail-closed on its
	// audit write. Note the ordering — the canary check runs before the Disabled and expiry
	// refusals, so a decoy that is also disabled still records its trip before being refused.
	if isCanary(name, sec) {
		if err := tripCanary(name); err != nil {
			return err
		}
	}
	// A disabled secret (the kill switch) is refused on every access path until re-enabled.
	if sec.Disabled {
		return fmt.Errorf("%s is disabled (`arca enable %s` to restore)", name, name)
	}
	// Hard expiry is checked next: an expired secret is refused on every access path,
	// before any approval prompt or decryption.
	if sec.Expired(time.Now()) {
		return fmt.Errorf("%s expired at %s", name, sec.ExpiresAt.UTC().Format(time.RFC3339))
	}
	// A require-grant secret is usable only through a command-bearing path and only with a matching
	// active grant. Without a command (get/env/inject), there's nothing to authorize against.
	if sec.RequireGrant {
		if cmdline == "" {
			return fmt.Errorf("%s requires a grant and is usable only via exec / run_with_secrets", name)
		}
		if err := checkGrant(name, cmdline); err != nil {
			return err
		}
	}
	// A rate-limited secret is refused once it has been used its allowed number of times within the
	// window — a throttle on a secret an agent is hammering.
	if sec.RateLimit > 0 {
		if err := checkRateLimit(sec, name); err != nil {
			return err
		}
	}
	if sec.RequireApproval {
		return approve(name, approverWho())
	}
	return nil
}

// checkRateLimit enforces a per-secret "N uses per window" cap using the audit log. The current
// access hasn't been recorded yet, so it is allowed iff the prior uses within the window are below
// the cap. A refusal is itself recorded (op=ratelimit) as a throttle signal.
func checkRateLimit(sec *store.Secret, name string) error {
	win, winStr := rateWindow(sec.RateWindow)
	a, err := audit.Open(auditPath())
	if err != nil {
		return err
	}
	defer a.Close()
	used, err := a.CountUsesSince(name, time.Now().Add(-win))
	if err != nil {
		return err
	}
	if used >= sec.RateLimit {
		_ = logAudit("ratelimit", name, "")
		return fmt.Errorf("%s rate limit reached: %d use(s) in the last %s (max %d)", name, used, winStr, sec.RateLimit)
	}
	if used+1 == sec.RateLimit {
		fmt.Fprintf(os.Stderr, "note: %s is at its last permitted use in this %s window\n", name, winStr)
	}
	return nil
}

// rateWindow resolves a stored RateWindow to the window actually enforced, returning both the
// duration and the string form used in messages. An empty window means the documented 1h default;
// an unparseable one can only come from a hand-edited store, and falling back to 1h keeps a
// malformed field from disabling the cap entirely.
//
// Extracted from checkRateLimit so requirePolicyOperator (operator.go) compares rate limits by the
// same rule that enforces them. A second copy of this defaulting would let the anchor guard a
// policy the access path does not apply.
func rateWindow(stored string) (time.Duration, string) {
	winStr := stored
	if winStr == "" {
		winStr = "1h"
	}
	win, err := parseTTL(winStr)
	if err != nil {
		return time.Hour, "1h"
	}
	return win, winStr
}

// parseRate parses a "--rate N/DURATION" value (e.g. "10/1h") into a use cap and a window string.
func parseRate(s string) (int, string, error) {
	n, dur, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return 0, "", fmt.Errorf("rate must look like N/DURATION, e.g. 10/1h")
	}
	count, err := strconv.Atoi(strings.TrimSpace(n))
	if err != nil || count <= 0 {
		return 0, "", fmt.Errorf("rate count must be a positive integer (got %q)", strings.TrimSpace(n))
	}
	dur = strings.TrimSpace(dur)
	if _, err := parseTTL(dur); err != nil {
		return 0, "", fmt.Errorf("rate window %q: %w", dur, err)
	}
	return count, dur, nil
}

// tripCanary records and announces that a decoy secret was used — a strong signal that something
// is enumerating or exfiltrating secrets. The audit event (op=canary) is hash-chained and signed
// like any other, so the trip can't be quietly scrubbed.
//
// It returns an error only when the trip could not be RECORDED (R4, ruling D2). The access itself
// stays non-blocking when a canary trips — the value is fake, and letting the caller take it is
// what keeps the trap useful, since an agent exfiltrating a decoy does not learn it was caught.
// Those are two different questions, and the old `_ = logAudit(...)` answered both with "carry on":
// it made the tripwire the one event in arca that was not fail-closed, so a caller who could break
// the audit log could trip canaries at will and leave the operator with the terminal warning as the
// only trace — on a stderr stream that same caller reads. Callers must propagate this error.
func tripCanary(name string) error {
	id := detectIdentity()
	who := id.Agent
	if who == "" {
		who = id.Actor
	}
	if who == "" {
		who = "an unidentified caller"
	}
	// who/session are attacker-controlled for a detected agent; sanitize before writing to the
	// operator's terminal so a crafted $AI_AGENT/$ARCA_ACTOR can't inject escapes (SEC-07).
	fmt.Fprintf(os.Stderr, "⚠  CANARY TRIPPED: %q was accessed by %s", sanitize(name), sanitize(who))
	if id.Session != "" {
		fmt.Fprintf(os.Stderr, " (session %s)", sanitize(shortID(id.Session)))
	}
	fmt.Fprintln(os.Stderr, " — this secret is a decoy and should never be used.")
	// Fail-closed on the RECORD, not on the trip: logAudit already swallows the error under
	// best-effort auditing (a non-agent human at a terminal who set ARCA_STRICT_AUDIT=0), so this
	// inherits exactly the strictness the rest of the audit path has, no new policy of its own.
	if err := logAudit("canary", name, ""); err != nil {
		return fmt.Errorf("canary %s tripped but the trip could not be recorded: %w", sanitize(name), err)
	}
	return nil
}

// parseTTL parses a relative duration for --ttl. It extends Go's time.ParseDuration (ns…h)
// with 'd' (days) and 'w' (weeks) suffixes, the units people actually reach for with secrets.
func parseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if n := len(s); n >= 2 {
		switch s[n-1] {
		case 'd', 'w':
			num, err := strconv.ParseFloat(s[:n-1], 64)
			if err != nil {
				return 0, fmt.Errorf("invalid duration %q", s)
			}
			hours := 24.0
			if s[n-1] == 'w' {
				hours = 24 * 7
			}
			return time.Duration(num * hours * float64(time.Hour)), nil
		}
	}
	return time.ParseDuration(s)
}

// applyExpiry sets sec.ExpiresAt from the mutually-exclusive --ttl (relative) and
// --expires-at (absolute RFC3339 or YYYY-MM-DD) flags. It is a no-op when neither is given,
// so re-setting a secret without the flags preserves any existing expiry.
func applyExpiry(sec *store.Secret, ttl, expiresAt string) error {
	switch {
	case ttl != "" && expiresAt != "":
		return fmt.Errorf("use either --ttl or --expires-at, not both")
	case ttl != "":
		d, err := parseTTL(ttl)
		if err != nil {
			return fmt.Errorf("ttl: %w", err)
		}
		if d <= 0 {
			return fmt.Errorf("ttl must be positive")
		}
		t := time.Now().UTC().Add(d)
		sec.ExpiresAt = &t
	case expiresAt != "":
		t, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			if t, err = time.Parse("2006-01-02", expiresAt); err != nil {
				return fmt.Errorf("expires-at: want RFC3339 or YYYY-MM-DD, got %q", expiresAt)
			}
		}
		t = t.UTC()
		sec.ExpiresAt = &t
	}
	return nil
}
