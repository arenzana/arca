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
	"bufio"
	"context"
	"encoding/json"
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
	}
	root.AddCommand(cmds...)
	registerCompletions(cmds)
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

// auditPath is the local SQLite audit DB (do not sync). Override with $ARCA_AUDIT.
func auditPath() string {
	if p := os.Getenv("ARCA_AUDIT"); p != "" {
		return p
	}
	return filepath.Join(stateDir(), "audit.db")
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
func storeGenPath() string { return filepath.Join(stateDir(), "store.gen") }

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
		fmt.Fprintf(os.Stderr, "arca: warning: the store looks rolled back (generation %d < last seen %d) — a rotated or deleted secret may have been resurrected; check the store's git history\n", gen, prev)
	}
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
		if err := os.MkdirAll(filepath.Dir(storeGenPath()), 0o700); err == nil {
			tmp := storeGenPath() + ".tmp"
			if os.WriteFile(tmp, []byte(strconv.Itoa(gen)), 0o600) == nil { //#nosec G304 -- our own state-dir path
				_ = os.Rename(tmp, storeGenPath())
			}
		}
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

func readValue(prompt string) ([]byte, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return b, err
	}
	b, err := readAllLimited(os.Stdin, maxInputBytes)
	if err != nil {
		return nil, err
	}
	// Strip a single trailing newline (from `echo`/editors) but preserve internal newlines,
	// so multi-line secrets like PEM keys round-trip intact.
	return []byte(strings.TrimRight(string(b), "\r\n")), nil
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
	// a tripwire. Alert and record it, but let the access proceed — the value is fake, and letting
	// the caller take it keeps the trap useful (an agent exfiltrating it doesn't learn it was caught).
	// The designation lives in the local registry, not the synced store (SEC-04); isCanary also
	// honors the legacy pre-0.6.2 store flag.
	if isCanary(name, sec) {
		tripCanary(name)
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
	winStr := sec.RateWindow
	if winStr == "" {
		winStr = "1h"
	}
	win, err := parseTTL(winStr)
	if err != nil {
		win = time.Hour
		winStr = "1h"
	}
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
func tripCanary(name string) {
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
	_ = logAudit("canary", name, "") // best-effort: never block the access on the alert itself
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

// ----------------------------------------------------------------------------
// Commands.
// ----------------------------------------------------------------------------

// newInit creates the store, deriving the recipient from the caller's existing age key (or
// generating one if none exists). It refuses to clobber an existing store without --force.
func newInit() *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "init",
		Short: "Initialize the store (reuses $SOPS_AGE_KEY_FILE or generates an identity)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, err := os.Stat(storePath()); err == nil && !force {
				return fmt.Errorf("store already exists at %s (use --force)", storePath())
			}
			idPath := identityPath()
			var recips []string
			if fi, err := os.Stat(idPath); err == nil {
				// Reuse the existing identity (e.g. the sops age key). Warn if its file is
				// readable by group/other — the private key should be 0600.
				if fi.Mode()&0o077 != 0 {
					fmt.Fprintf(os.Stderr, "warning: identity %s is group/world-accessible (%#o); consider chmod 600\n", idPath, fi.Mode().Perm())
				}
				ids, err := crypto.LoadIdentities(idPath)
				if err != nil {
					return err
				}
				if recips, err = crypto.RecipientsFromIdentities(ids); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "using identity %s\n", idPath)
			} else {
				// No key yet: generate one and persist it 0600.
				idStr, rec, err := crypto.GenerateIdentity()
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(idPath), 0o700); err != nil {
					return err
				}
				// O_EXCL: create exclusively (never follow a pre-planted symlink or clobber an
				// existing file) so the private key can't be redirected to an attacker path.
				f, err := os.OpenFile(idPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //#nosec G304 -- idPath comes from config/env (ARCA_IDENTITY / XDG), not untrusted input
				if err != nil {
					return err
				}
				if _, err := f.WriteString(idStr + "\n"); err != nil {
					f.Close()
					return err
				}
				if err := f.Close(); err != nil {
					return err
				}
				recips = []string{rec}
				fmt.Fprintf(os.Stderr, "generated new identity at %s\n", idPath)
			}
			if err := store.New(storePath(), recips).Save(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "initialized store at %s\nrecipients: %s\n", storePath(), strings.Join(recips, ", "))
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "overwrite an existing store")
	return c
}

// newSet adds or updates a secret. The value comes from a TTY/stdin (never an arg). On an
// existing secret it preserves CreatedAt and only touches the fields the user supplied.
func newSet() *cobra.Command {
	var tags []string
	var desc, rotate, ttl, expiresAt string
	var meta map[string]string
	var noPrint, requireApproval, canary, requireGrant bool
	var rate string
	c := &cobra.Command{
		Use:   "set NAME",
		Short: "Add or update a secret (value from TTY or stdin)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := validName(name); err != nil {
				return err
			}
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			recips, err := crypto.ParseRecipients(s.Recipients)
			if err != nil {
				return err
			}
			val, err := readValue("Value: ")
			if err != nil {
				return err
			}
			armored, err := crypto.Encrypt(val, recips)
			if err != nil {
				return err
			}

			now := time.Now().UTC()
			sec := s.Secrets[name]
			if sec == nil { // new secret
				sec = &store.Secret{CreatedAt: now}
				s.Secrets[name] = sec
			}
			sec.Value = armored
			sec.UpdatedAt = now
			if len(tags) > 0 {
				sec.Tags = tags
			}
			if desc != "" {
				sec.Description = desc
			}
			if rotate != "" {
				t, err := time.Parse("2006-01-02", rotate)
				if err != nil {
					return fmt.Errorf("rotate-after: %w", err)
				}
				sec.RotateAfter = &t
			}
			if err := applyExpiry(sec, ttl, expiresAt); err != nil {
				return err
			}
			if len(meta) > 0 {
				if sec.Meta == nil {
					sec.Meta = map[string]string{}
				}
				for k, v := range meta {
					sec.Meta[k] = v
				}
			}
			// Only change the policy when the flag was actually given, so re-setting a secret
			// doesn't silently clear its no-print bit.
			if cmd.Flags().Changed("no-print") {
				sec.NoPrint = noPrint
			}
			if cmd.Flags().Changed("require-approval") {
				sec.RequireApproval = requireApproval
			}
			canaryChanged := cmd.Flags().Changed("canary")
			if canaryChanged {
				sec.Canary = false // never persist the designation to the (synced) store — SEC-04
			}
			if cmd.Flags().Changed("require-grant") {
				sec.RequireGrant = requireGrant
			}
			if cmd.Flags().Changed("rate") {
				if rate == "" {
					sec.RateLimit, sec.RateWindow = 0, ""
				} else {
					n, w, err := parseRate(rate)
					if err != nil {
						return err
					}
					sec.RateLimit, sec.RateWindow = n, w
				}
			}
			if err := s.Save(); err != nil {
				return err
			}
			if canaryChanged {
				update := unmarkCanary
				if canary {
					update = markCanary
				}
				if err := update(name); err != nil {
					return fmt.Errorf("saved %s but failed to update its canary state: %w", name, err)
				}
			}
			if err := logAudit("set", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "stored %s\n", name)
			return nil
		},
	}
	c.Flags().StringSliceVar(&tags, "tag", nil, "tags (repeatable or comma-separated)")
	c.Flags().StringVar(&desc, "desc", "", "description")
	c.Flags().StringVar(&rotate, "rotate-after", "", "rotation date (YYYY-MM-DD)")
	c.Flags().StringVar(&ttl, "ttl", "", "expire after a relative duration (e.g. 30m, 12h, 7d, 2w)")
	c.Flags().StringVar(&expiresAt, "expires-at", "", "expire at an absolute time (RFC3339 or YYYY-MM-DD)")
	c.Flags().StringToStringVar(&meta, "meta", nil, "extra metadata key=value (repeatable)")
	c.Flags().BoolVar(&noPrint, "no-print", false, "exec-only: get/env/inject refuse to reveal it")
	c.Flags().BoolVar(&requireApproval, "require-approval", false, "require human approval (TTY) before each release")
	c.Flags().BoolVar(&canary, "canary", false, "mark as a decoy: any use trips an alert and a signed audit event")
	c.Flags().BoolVar(&requireGrant, "require-grant", false, "usable only via exec/MCP with a matching active grant")
	c.Flags().StringVar(&rate, "rate", "", "rate limit as N/DURATION (e.g. 10/1h); empty clears it")
	return c
}

// newGet decrypts and prints one secret. It refuses --no-print secrets (the whole point of
// that flag is that the value must not reach stdout) and records a "read" in the audit log.
func newGet() *cobra.Command {
	var nl, noLog bool
	c := &cobra.Command{
		Use:   "get NAME",
		Short: "Decrypt and print one secret (records a read)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			s, err := openStore()
			if err != nil {
				return err
			}
			sec := s.Secrets[name]
			if sec == nil {
				return fmt.Errorf("no such secret: %s", name)
			}
			if sec.NoPrint {
				return fmt.Errorf("%s is marked --no-print; use `exec` instead", name)
			}
			if err := gate(sec, name, ""); err != nil {
				return err
			}
			ids, err := loadIDs()
			if err != nil {
				return err
			}
			plain, err := crypto.Decrypt(sec.Value, ids)
			if err != nil {
				return fmt.Errorf("decrypt %s: %w", name, err)
			}
			// Log before revealing: under fail-closed auditing, a read that cannot be recorded must
			// not disclose the value. --no-log may suppress the record for a human, but never for an
			// AI agent (which can't suppress its own trail) and never for a rate-limited secret — the
			// audit log IS the rate counter, so honoring --no-log there would let a human bypass the
			// limit by reading in a loop (SEC-12). "Human" is anchored to a controlling terminal,
			// not env-based agent detection, which an agent can scrub (SEC-06).
			human := detectIdentity().Agent == "" && hasControllingTTY()
			if !noLog || !human || sec.RateLimit > 0 {
				if noLog && human && sec.RateLimit > 0 {
					fmt.Fprintf(os.Stderr, "note: --no-log ignored for %s (it is rate-limited)\n", name)
				} else if noLog && !human {
					fmt.Fprintf(os.Stderr, "note: --no-log ignored for %s (no interactive terminal)\n", name)
				}
				if err := logAudit("read", name, ""); err != nil {
					return err
				}
			}
			os.Stdout.Write(plain) // raw, no trailing newline unless -n
			if nl {
				fmt.Println()
			}
			return nil
		},
	}
	c.Flags().BoolVarP(&nl, "newline", "n", false, "append a trailing newline")
	c.Flags().BoolVar(&noLog, "no-log", false, "do not record this read")
	return c
}

// newLs lists secrets and their metadata. It never decrypts; with --reads it joins the audit
// DB for last-read/count, which is why that data lives outside the store.
func newLs() *cobra.Command {
	var tag string
	var reads, jsonOut bool
	c := &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List secrets and metadata (no decryption)",
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			var a *audit.Log
			if reads || jsonOut { // --json always enriches with last-read when available
				if a, err = audit.Open(auditPath()); err == nil {
					defer a.Close()
				}
			}
			if jsonOut {
				views := []secretView{}
				for _, name := range s.Names() {
					sec := s.Secrets[name]
					if tag != "" && !contains(sec.Tags, tag) {
						continue
					}
					var lr time.Time
					var cnt int
					if a != nil {
						lr, cnt, _ = a.LastRead(name)
					}
					views = append(views, viewOf(name, sec, lr, cnt))
				}
				return emitJSON(views)
			}
			showReads := reads && a != nil
			headers := []string{"NAME", "TAGS", "UPDATED", "DESCRIPTION"}
			if showReads {
				headers = []string{"NAME", "TAGS", "UPDATED", "LAST READ", "READS", "DESCRIPTION"}
			}
			rows := [][]string{}
			for _, name := range s.Names() {
				sec := s.Secrets[name]
				if tag != "" && !contains(sec.Tags, tag) {
					continue
				}
				updated := sec.UpdatedAt.Local().Format("2006-01-02")
				// Flag disabled/expired secrets so they're visible at a glance (e.g. during a leak).
				desc := sec.Description
				if sec.Disabled {
					desc = strings.TrimSpace("[disabled] " + desc)
				} else if sec.Expired(time.Now()) {
					desc = strings.TrimSpace("[expired] " + desc)
				}
				if showReads {
					lr, cnt, _ := a.LastRead(name)
					lrs := "never"
					if !lr.IsZero() {
						lrs = lr.Local().Format("2006-01-02 15:04")
					}
					rows = append(rows, sanitizeAll([]string{name, strings.Join(sec.Tags, ","), updated, lrs, strconv.Itoa(cnt), desc}))
				} else {
					rows = append(rows, sanitizeAll([]string{name, strings.Join(sec.Tags, ","), updated, desc}))
				}
			}
			renderTable(headers, rows)
			return nil
		},
	}
	c.Flags().StringVar(&tag, "tag", "", "filter by tag")
	c.Flags().BoolVar(&reads, "reads", false, "include last-read / read-count from the audit log")
	c.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return c
}

// newShow prints one secret's metadata (never the value), enriched with last-read info from
// the audit DB.
func newShow() *cobra.Command {
	var jsonOut bool
	c := &cobra.Command{
		Use:   "show NAME",
		Short: "Show metadata for a secret (no decryption)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			s, err := openStore()
			if err != nil {
				return err
			}
			sec := s.Secrets[name]
			if sec == nil {
				return fmt.Errorf("no such secret: %s", name)
			}
			var lr time.Time
			var cnt int
			if a, err := audit.Open(auditPath()); err == nil {
				lr, cnt, _ = a.LastRead(name)
				a.Close()
			}
			if jsonOut {
				return emitJSON(viewOf(name, sec, lr, cnt))
			}
			fmt.Printf("name:         %s\n", sanitize(name))
			fmt.Printf("created:      %s\n", sec.CreatedAt.Local().Format(time.RFC3339))
			fmt.Printf("updated:      %s\n", sec.UpdatedAt.Local().Format(time.RFC3339))
			if lr.IsZero() {
				fmt.Printf("last read:    never\n")
			} else {
				fmt.Printf("last read:    %s (%d total)\n", lr.Local().Format(time.RFC3339), cnt)
			}
			if sec.NoPrint {
				fmt.Printf("policy:       no-print (exec-only)\n")
			}
			if sec.RequireApproval {
				fmt.Printf("policy:       requires approval\n")
			}
			if sec.RateLimit > 0 {
				win := sec.RateWindow
				if win == "" {
					win = "1h"
				}
				fmt.Printf("policy:       rate-limited (%d per %s)\n", sec.RateLimit, win)
			}
			if len(sec.Tags) > 0 {
				fmt.Printf("tags:         %s\n", sanitize(strings.Join(sec.Tags, ", ")))
			}
			if sec.Description != "" {
				fmt.Printf("description:  %s\n", sanitize(sec.Description))
			}
			if sec.RotateAfter != nil {
				fmt.Printf("rotate after: %s\n", sec.RotateAfter.Format("2006-01-02"))
			}
			if sec.Disabled {
				fmt.Printf("status:       DISABLED (refused on every access path; `arca enable %s` to restore)\n", name)
			}
			if sec.ExpiresAt != nil {
				state := "valid"
				if sec.Expired(time.Now()) {
					state = "EXPIRED — refused on every access path"
				}
				fmt.Printf("expires:      %s (%s)\n", sec.ExpiresAt.Local().Format(time.RFC3339), state)
			}
			for k, v := range sec.Meta {
				fmt.Printf("meta.%s: %s\n", sanitize(k), sanitize(v))
			}
			return nil
		},
	}
	c.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return c
}

// newRm deletes a secret from the store and logs the removal.
func newRm() *cobra.Command {
	return &cobra.Command{
		Use:     "rm NAME",
		Aliases: []string{"remove"},
		Short:   "Remove a secret",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			if _, ok := s.Secrets[name]; !ok {
				return fmt.Errorf("no such secret: %s", name)
			}
			delete(s.Secrets, name)
			if err := s.Save(); err != nil {
				return err
			}
			_ = unmarkCanary(name) // best-effort registry cleanup (SEC-04); a stale entry is harmless
			if err := logAudit("rm", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "removed %s\n", name)
			return nil
		},
	}
}

// newDisable suspends a secret without changing its value: it stamps expiry at "now" so every
// access path (get/exec/inject/env + MCP) refuses it, while the value and the rest of the metadata
// are preserved. Reverse it with `enable`. This is the fast, reversible kill switch for a leak —
// the actual token must still be revoked at its issuer; this only stops arca from handing it out.
func newDisable() *cobra.Command {
	return &cobra.Command{
		Use:   "disable NAME",
		Short: "Suspend a secret (refused everywhere) without deleting it; reverse with `enable`",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			sec := s.Secrets[name]
			if sec == nil {
				return fmt.Errorf("no such secret: %s", name)
			}
			sec.Disabled = true // a dedicated kill switch — independent of any real expiry (SEC-13)
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("disable", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "disabled %s (revoke it at the issuer too; `arca enable %s` to restore)\n", name, name)
			return nil
		},
	}
}

// newEnable lifts a `disable` — clearing only the disabled flag, so a real future expiry the secret
// was carrying is preserved (SEC-13). Intent is recorded in the audit log (op "enable"). A secret
// that is unavailable purely because its *expiry* passed is cleared with `set`/`rotate --expires-at`,
// not here — enabling doesn't silently wipe an intentional expiry.
func newEnable() *cobra.Command {
	return &cobra.Command{
		Use:   "enable NAME",
		Short: "Re-enable a disabled secret (keeps any real expiry)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			sec := s.Secrets[name]
			if sec == nil {
				return fmt.Errorf("no such secret: %s", name)
			}
			sec.Disabled = false
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("enable", name, ""); err != nil {
				return err
			}
			if sec.Expired(time.Now()) {
				fmt.Fprintf(os.Stderr, "enabled %s — note: it is still expired (expires_at is in the past); use `rotate`/`set --expires-at` to change that\n", name)
			} else {
				fmt.Fprintf(os.Stderr, "enabled %s\n", name)
			}
			return nil
		},
	}
}

// newImport reads dotenv-style KEY=value lines from stdin and stores each, e.g. to migrate
// from a sops file: `sops -d secrets.env | arca import`.
// kvPair is a parsed name→value to import, before encryption.
type kvPair struct{ key, val string }

// parseDotenvSecrets reads KEY=value (dotenv) lines, applying the normalization arca has always
// used: skip blanks/comments, drop a leading `export `, strip surrounding quotes, and refuse
// names that aren't valid secret identifiers (which could inject downstream). dotenv is
// line-oriented, so values are single-line; use `set NAME < file` or --json for multi-line ones.
func parseDotenvSecrets(r io.Reader) ([]kvPair, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20) // allow long values (up to 1 MiB/line)
	var out []kvPair
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if validName(k) != nil {
			fmt.Fprintf(os.Stderr, "skip %q: not a valid secret name\n", k)
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`) // drop surrounding quotes
		out = append(out, kvPair{k, v})
	}
	return out, sc.Err()
}

// parseJSONSecrets reads a single flat JSON object of name→value — the shape most secret stores
// emit (AWS Secrets Manager, Vault, 1Password, gcloud). String values pass through verbatim
// (so a JSON-escaped multi-line PEM round-trips); numbers and booleans are stringified; null and
// nested object/array values are skipped with a warning, since a secret is a scalar.
func parseJSONSecrets(r io.Reader) ([]kvPair, error) {
	data, err := readAllLimited(r, maxInputBytes)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse JSON object: %w", err)
	}
	out := make([]kvPair, 0, len(raw))
	for k, rv := range raw {
		if validName(k) != nil {
			fmt.Fprintf(os.Stderr, "skip %q: not a valid secret name\n", k)
			continue
		}
		val, ok := jsonScalar(rv)
		if !ok {
			fmt.Fprintf(os.Stderr, "skip %q: value is not a string, number, or boolean\n", k)
			continue
		}
		out = append(out, kvPair{k, val})
	}
	return out, nil
}

// jsonScalar renders a JSON value as the string arca will store, or reports ok=false for
// null/object/array, which aren't scalar secrets.
func jsonScalar(rv json.RawMessage) (string, bool) {
	var v any
	if err := json.Unmarshal(rv, &v); err != nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true // -1 avoids scientific notation for ints
	default:
		return "", false
	}
}

func newImport() *cobra.Command {
	var asJSON, dryRun, overwrite bool
	var prefix string
	var tags []string
	c := &cobra.Command{
		Use:   "import",
		Short: `Bulk-import secrets from stdin (dotenv KEY=value lines, or --json {"KEY":"value"})`,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// Reading/parsing stdin doesn't touch the store, so do it before taking the lock.
			var pairs []kvPair
			var err error
			if asJSON {
				pairs, err = parseJSONSecrets(os.Stdin)
			} else {
				pairs, err = parseDotenvSecrets(os.Stdin)
			}
			if err != nil {
				return err
			}
			// Apply the optional prefix and re-validate the final name (a prefix can make an
			// otherwise-valid key invalid, e.g. one starting with a digit).
			plan := make([]kvPair, 0, len(pairs))
			for _, p := range pairs {
				name := prefix + p.key
				if validName(name) != nil {
					fmt.Fprintf(os.Stderr, "skip %q: not a valid secret name\n", name)
					continue
				}
				plan = append(plan, kvPair{name, p.val})
			}

			// A dry run only previews, so it neither locks nor needs a writable store.
			var unlock func()
			if !dryRun {
				unlock, err = lockStore()
				if err != nil {
					return err
				}
				defer unlock()
			}
			s, err := openStore()
			if err != nil {
				return err
			}
			recips, err := crypto.ParseRecipients(s.Recipients)
			if err != nil {
				return err
			}

			now := time.Now().UTC()
			imported := make([]string, 0, len(plan))
			var overwritten, skipped int
			for _, p := range plan {
				existing := s.Secrets[p.key]
				if existing != nil && !overwrite {
					fmt.Fprintf(os.Stderr, "skip %q: already exists (pass --overwrite to replace)\n", p.key)
					skipped++
					continue
				}
				if dryRun {
					if existing != nil {
						overwritten++
						fmt.Fprintf(os.Stderr, "would overwrite %q\n", p.key)
					} else {
						fmt.Fprintf(os.Stderr, "would import %q\n", p.key)
					}
					imported = append(imported, p.key)
					continue
				}
				armored, err := crypto.Encrypt([]byte(p.val), recips)
				if err != nil {
					return err
				}
				sec := existing
				if sec == nil {
					sec = &store.Secret{CreatedAt: now}
					s.Secrets[p.key] = sec
				} else {
					overwritten++
				}
				sec.Value = armored
				sec.UpdatedAt = now
				if len(tags) > 0 {
					sec.Tags = tags
				}
				imported = append(imported, p.key)
			}

			if dryRun {
				fmt.Fprintf(os.Stderr, "dry run: %d to import (%d new, %d overwrite), %d skipped\n",
					len(imported), len(imported)-overwritten, overwritten, skipped)
				return nil
			}
			if err := s.Save(); err != nil {
				return err
			}
			// Audit each imported secret, so a bulk load is recorded like any other write
			// rather than being a blind spot in the log.
			for _, k := range imported {
				if err := logAudit("import", k, ""); err != nil {
					return err
				}
			}
			fmt.Fprintf(os.Stderr, "imported %d secret(s) (%d new, %d overwritten), %d skipped\n",
				len(imported), len(imported)-overwritten, overwritten, skipped)
			return nil
		},
	}
	c.Flags().BoolVar(&asJSON, "json", false, `read a JSON object {"KEY":"value"} from stdin instead of dotenv lines`)
	c.Flags().BoolVar(&dryRun, "dry-run", false, "report what would be imported without writing anything")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace secrets that already exist (default: skip them)")
	c.Flags().StringVar(&prefix, "prefix", "", "prepend this prefix to every imported name")
	c.Flags().StringSliceVar(&tags, "tag", nil, "tags to apply to imported secrets (repeatable or comma-separated)")
	return c
}

var refRe = regexp.MustCompile(`arca://[A-Za-z_][A-Za-z0-9_]*`)

// newInject resolves arca://NAME references on stdin and writes the result to stdout — so an
// agent can put references in a config/template and have them filled in at render time,
// manipulating references rather than secrets. no-print secrets are refused (use exec); every
// resolved secret is audited.
func newInject() *cobra.Command {
	return &cobra.Command{
		Use:   "inject",
		Short: "Resolve arca://NAME references on stdin, writing the result to stdout",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			ids, err := loadIDs()
			if err != nil {
				return err
			}
			data, err := readAllLimited(os.Stdin, maxInputBytes)
			if err != nil {
				return err
			}
			// ReplaceAllStringFunc can't return an error, so we capture the first failure in a
			// closure variable and surface it after the scan (leaving the reference untouched).
			var firstErr error
			out := refRe.ReplaceAllStringFunc(string(data), func(m string) string {
				name := strings.TrimPrefix(m, "arca://")
				sec := s.Secrets[name]
				switch {
				case sec == nil:
					if firstErr == nil {
						firstErr = fmt.Errorf("no such secret: %s", name)
					}
					return m
				case sec.NoPrint:
					if firstErr == nil {
						firstErr = fmt.Errorf("%s is marked --no-print; use `exec`, not inject", name)
					}
					return m
				}
				if err := gate(sec, name, ""); err != nil {
					if firstErr == nil {
						firstErr = err
					}
					return m
				}
				plain, err := crypto.Decrypt(sec.Value, ids)
				if err != nil {
					if firstErr == nil {
						firstErr = fmt.Errorf("decrypt %s: %w", name, err)
					}
					return m
				}
				if err := logAudit("inject", name, ""); err != nil {
					if firstErr == nil {
						firstErr = err
					}
					return m
				}
				return string(plain)
			})
			if firstErr != nil {
				return firstErr
			}
			fmt.Print(out)
			return nil
		},
	}
}

// newExec runs a command with selected secrets injected as environment variables. This is the
// "use without revealing" path: the command can read $NAME, but the value never lands on
// arca's stdout or in an agent's context. It's also the only way to use a --no-print secret.
func newExec() *cobra.Command {
	var only []string
	var redactMode string
	var reveal bool
	c := &cobra.Command{
		Use:   "exec [--only a,b] -- command [args...]",
		Short: "Run a command with secrets injected as env (audited)",
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("no command given")
			}
			s, err := openStore()
			if err != nil {
				return err
			}
			ids, err := loadIDs()
			if err != nil {
				return err
			}
			names := s.Names()
			if len(only) > 0 { // least privilege: inject just what was asked for
				names = only
			}
			switch redactMode {
			case "auto", "on", "off":
			default:
				return fmt.Errorf("--redact must be auto, on, or off (got %q)", redactMode)
			}

			caller := filepath.Base(args[0])   // recorded as the audit "caller"
			cmdline := strings.Join(args, " ") // matched against a require-grant secret's command pattern
			env := os.Environ()
			var injected []redactPattern
			for _, name := range names {
				sec := s.Secrets[name]
				if sec == nil {
					return fmt.Errorf("no such secret: %s", name)
				}
				// Defense in depth against a poisoned/hand-edited store: never inject a name
				// that isn't a valid identifier (e.g. LD_PRELOAD-style or `=`-bearing names).
				if validName(name) != nil {
					fmt.Fprintf(os.Stderr, "skip %q: not a valid env name\n", name)
					continue
				}
				if err := gate(sec, name, cmdline); err != nil {
					return err
				}
				plain, err := crypto.Decrypt(sec.Value, ids)
				if err != nil {
					return fmt.Errorf("decrypt %s: %w", name, err)
				}
				env = append(env, name+"="+string(plain))
				injected = append(injected, redactPattern{name: name, value: plain})
				if err := logAudit("exec", name, caller); err != nil {
					return err
				}
			}

			cmd := exec.Command(args[0], args[1:]...) //#nosec G204 -- `arca exec` deliberately runs the user-specified command
			cmd.Env = env
			cmd.Stdin = os.Stdin

			// Redact injected secret values from the child's output so a command that prints one
			// doesn't leak it to whoever reads stdout/stderr (an AI agent, a log). Default `auto`
			// redacts only a stream that isn't an interactive terminal — i.e. one being captured —
			// and passes a real TTY straight through (a human at a prompt, no buffering latency).
			pats := buildRedactPatterns(injected, reveal, os.Stderr)
			// `auto` redacts a captured (non-terminal) stream and steps aside for a human at a real
			// TTY. But an AI agent commonly allocates a PTY to capture a child's output, which would
			// otherwise disable redaction — so a detected agent always gets redaction regardless of
			// the TTY check (SEC-11).
			agent := detectIdentity().Agent != ""
			redactStream := func(f *os.File) bool {
				switch redactMode {
				case "off":
					return false
				case "on":
					return true
				default:
					return len(pats) > 0 && (agent || !term.IsTerminal(int(f.Fd())))
				}
			}
			var redactors []*redactWriter
			if cmd.Stdout = os.Stdout; len(pats) > 0 && redactStream(os.Stdout) {
				rw := newRedactWriter(os.Stdout, pats)
				cmd.Stdout = rw
				redactors = append(redactors, rw)
			}
			if cmd.Stderr = os.Stderr; len(pats) > 0 && redactStream(os.Stderr) {
				rw := newRedactWriter(os.Stderr, pats)
				cmd.Stderr = rw
				redactors = append(redactors, rw)
			}

			runErr := cmd.Run()
			// Flush held-back tails and record any catches before honoring the exit code (which
			// may os.Exit). A secret appearing in output is a potential leak, so it's audited.
			for _, rw := range redactors {
				if err := rw.Flush(); err != nil {
					fmt.Fprintf(os.Stderr, "redact: flush failed: %v\n", err)
				}
			}
			caught := map[string]int{}
			for _, rw := range redactors {
				for name, n := range rw.hits {
					caught[name] += n
				}
			}
			for name, n := range caught {
				fmt.Fprintf(os.Stderr, "redact: caught %s in output (%d occurrence(s))\n", name, n)
				if err := logAudit("redact", name, caller); err != nil {
					fmt.Fprintf(os.Stderr, "redact: audit failed for %s: %v\n", name, err)
				}
			}

			if runErr != nil {
				// Propagate the child's exit code so `arca exec -- foo` behaves like `foo`.
				if ee, ok := runErr.(*exec.ExitError); ok {
					os.Exit(ee.ExitCode())
				}
				return runErr
			}
			return nil
		},
	}
	c.Flags().StringSliceVar(&only, "only", nil, "subset of secrets to inject (default: all)")
	c.Flags().StringVar(&redactMode, "redact", "auto", "redact injected secret values from output: auto (captured streams only), on, or off")
	c.Flags().BoolVar(&reveal, "reveal", false, "when redacting, reveal a few characters of long secrets instead of the name (weaker)")
	// Stop flag parsing at the first positional arg so the wrapped command's own flags
	// (e.g. `-auto-approve`) aren't interpreted by arca.
	c.Flags().SetInterspersed(false)
	return c
}

// newEnv dumps all secrets as shell assignments for `eval "$(arca env)"`. Each secret is
// audited (op "env"), and --no-print secrets are skipped so they can't be revealed this way.
func newEnv() *cobra.Command {
	var noExport bool
	c := &cobra.Command{
		Use:   "env",
		Short: `Print shell assignments for eval "$(arca env)" (audited per secret)`,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			ids, err := loadIDs()
			if err != nil {
				return err
			}
			for _, name := range s.Names() {
				// Defense in depth: never emit `export <name>=…` for a name that isn't a valid
				// identifier — a crafted name in a poisoned store could otherwise inject shell
				// when the output is run via `eval "$(arca env)"`.
				if validName(name) != nil {
					fmt.Fprintf(os.Stderr, "skip %q: not a valid env name\n", name)
					continue
				}
				if s.Secrets[name].NoPrint {
					fmt.Fprintf(os.Stderr, "skip %s (--no-print)\n", name)
					continue
				}
				// Don't let one unusable secret blank out the whole `eval "$(arca env)"`: skip the
				// ones that simply can't be released here — disabled/expired (turned off) and
				// require-grant (needs a command to authorize against). An interactive approval
				// denial below is a deliberate "no" and still fails the command. Mirrors the
				// --no-print / invalid-name skips above.
				if s.Secrets[name].Disabled || s.Secrets[name].Expired(time.Now()) {
					fmt.Fprintf(os.Stderr, "skip %s (disabled/expired)\n", name)
					continue
				}
				if s.Secrets[name].RequireGrant {
					fmt.Fprintf(os.Stderr, "skip %s (require-grant; use exec)\n", name)
					continue
				}
				if err := gate(s.Secrets[name], name, ""); err != nil {
					return err
				}
				plain, err := crypto.Decrypt(s.Secrets[name].Value, ids)
				if err != nil {
					return fmt.Errorf("decrypt %s: %w", name, err)
				}
				if err := logAudit("env", name, ""); err != nil {
					return err
				}
				if noExport {
					fmt.Printf("%s=%s\n", name, shellQuote(string(plain)))
				} else {
					fmt.Printf("export %s=%s\n", name, shellQuote(string(plain)))
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&noExport, "no-export", false, "omit the leading 'export '")
	return c
}

// newLog prints the access history, including the attributed AI agent and session.
func newLog() *cobra.Command {
	var limit int
	var jsonOut, verify, requireSigned, remoteCheck bool
	var anchor string
	c := &cobra.Command{
		Use:   "log [NAME]",
		Short: "Show access history (--verify checks the log's integrity)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := ""
			if len(args) > 0 {
				name = args[0]
			}
			a, err := audit.Open(auditPath())
			if err != nil {
				return err
			}
			defer a.Close()
			if verify {
				return verifyLog(a, requireSigned, anchor, remoteCheck)
			}
			if requireSigned {
				return fmt.Errorf("--require-signed is only valid with --verify")
			}
			if anchor != "" {
				return fmt.Errorf("--anchor is only valid with --verify")
			}
			if remoteCheck {
				return fmt.Errorf("--remote is only valid with --verify")
			}
			evs, err := a.Recent(name, limit)
			if err != nil {
				return err
			}
			if jsonOut {
				views := []eventView{}
				for _, e := range evs {
					views = append(views, eventView{
						Time: e.TS, Op: e.Op, Name: e.Name, Agent: e.Agent,
						Version: e.Version, Session: e.Session, Actor: e.Actor, Caller: e.Caller,
					})
				}
				return emitJSON(views)
			}
			rows := make([][]string, 0, len(evs))
			for _, e := range evs {
				agent := e.Agent
				if e.Version != "" {
					agent += "/" + e.Version
				}
				// Sanitize the untrusted columns (name, and the agent/session/actor/caller strings,
				// which for a detected agent come from its own environment); colorOp(op) is a trusted
				// enum. See SEC-07.
				rows = append(rows, []string{
					e.TS.Local().Format("2006-01-02 15:04:05"), colorOp(e.Op), sanitize(e.Name),
					sanitize(agent), sanitize(shortID(e.Session)), sanitize(e.Actor), sanitize(e.Caller),
				})
			}
			renderTable([]string{"TIME", "OP", "NAME", "AGENT", "SESSION", "ACTOR", "CALLER"}, rows)
			return nil
		},
	}
	c.Flags().IntVar(&limit, "limit", 50, "max events")
	c.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	c.Flags().BoolVar(&verify, "verify", false, "verify the audit log's hash chain and signatures instead of printing it")
	c.Flags().BoolVar(&requireSigned, "require-signed", false, "with --verify, also fail if any chained event is unsigned")
	c.Flags().StringVar(&anchor, "anchor", "", "with --verify, also require the log to extend this previously-emitted anchor token")
	c.Flags().BoolVar(&remoteCheck, "remote", false, "with --verify, also require the log to extend its escrowed off-machine history (needs sync configured)")
	return c
}

// verifyLog runs an integrity check of the audit log and prints the result. It returns a non-zero
// error when the chain or a signature is broken, so it can gate a cron/CI check. With requireSigned
// it also fails when any chained event lacks a signature (a stripped or never-applied signature),
// which a default verify only reports as a count. With a previously-emitted anchor token, it also
// fails unless the chain still extends that head — the defense against the store and the audit DB
// being rolled back *together* to a consistent older state, which every in-DB check necessarily
// misses (SEC-14).
func verifyLog(a *audit.Log, requireSigned bool, anchor string, remoteCheck bool) error {
	r, err := a.Verify()
	if err != nil {
		return err
	}
	if !r.OK {
		if r.BrokenID != 0 {
			return fmt.Errorf("audit log integrity FAILED at event %d: %s", r.BrokenID, r.Reason)
		}
		return fmt.Errorf("audit log integrity FAILED: %s", r.Reason)
	}
	if requireSigned && r.Unsigned > 0 {
		return fmt.Errorf("audit log integrity FAILED: %d of %d chained event(s) are unsigned (--require-signed)", r.Unsigned, r.Checked)
	}
	// Store-generation cross-checks (SEC-14). The chain is intact, so the generations recorded in
	// it are trustworthy; a regression within the log, or a store older than the log's view, is
	// rollback evidence (a resurrected rotated/deleted secret) and fails the verify.
	if r.GenRegressedID != 0 {
		return fmt.Errorf("store ROLLBACK detected: event %d observed an older store generation than an earlier event — an older store copy was restored while auditing continued (check the store's git history; rotate any resurrected secrets)", r.GenRegressedID)
	}
	if r.MaxStoreGen > 0 {
		if s, err := openStore(); err == nil && s.Generation < r.MaxStoreGen {
			return fmt.Errorf("store ROLLBACK detected: the store is at generation %d but the audit log has verified events up to generation %d — the store file is older than the last audited operation (check the store's git history; rotate any resurrected secrets)", s.Generation, r.MaxStoreGen)
		}
	}
	// The anchor check runs only on an already-verified chain: the stored hashes are trustworthy
	// once the chain has been recomputed from genesis, so extending the anchored head proves the
	// history the anchor was minted over is still present and unmodified.
	if anchor != "" {
		n, h, err := audit.ParseAnchor(anchor)
		if err != nil {
			return err
		}
		if err := a.CheckAnchor(n, h); err != nil {
			return fmt.Errorf("audit log integrity FAILED: %w — the store and audit DB may have been rolled back together; treat every secret readable at the anchor time as potentially resurrected", err)
		}
	}
	// The escrowed history is the same check with an off-machine witness: segments this
	// machine pushed on past syncs are append-only on the backend, so a local log that
	// no longer extends them was rewritten or truncated here (SEC-14, Option B).
	if remoteCheck {
		b, err := openBackend()
		if err != nil {
			return err
		}
		if err := verifyAgainstEscrow(context.Background(), a, b); err != nil {
			return fmt.Errorf("audit log integrity FAILED: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "audit log OK: %d event(s) chained, %d signed", r.Checked, r.Signed)
	if r.Unsigned > 0 {
		fmt.Fprintf(os.Stderr, ", %d UNSIGNED", r.Unsigned)
	}
	if r.Legacy > 0 {
		fmt.Fprintf(os.Stderr, ", %d legacy (pre-chain, unverifiable)", r.Legacy)
	}
	if anchor != "" {
		fmt.Fprintf(os.Stderr, ", anchor extended")
	}
	fmt.Fprintln(os.Stderr)
	// Emit the fresh anchor on stdout so it can be captured and stored OFF this machine (a
	// password manager, a git note, another host). Passing it back via --anchor on a later
	// verify detects a joint store+audit rollback — the one rewrite the in-DB chain can't see.
	if r.Checked > 0 && r.LastHash != nil {
		fmt.Println(audit.FormatAnchor(r.Checked, r.LastHash))
	}
	return nil
}

// newRotate replaces an existing secret's value while preserving CreatedAt, and logs the
// change as a distinct "rotate" event (vs the initial "set"). Optionally advances the next
// rotation date.
func newRotate() *cobra.Command {
	var rotate, ttl, expiresAt string
	c := &cobra.Command{
		Use:   "rotate NAME",
		Short: "Replace an existing secret's value (keeps created_at; logs a rotation)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			unlock, err := lockStore()
			if err != nil {
				return err
			}
			defer unlock()
			s, err := openStore()
			if err != nil {
				return err
			}
			sec := s.Secrets[name]
			if sec == nil {
				return fmt.Errorf("no such secret: %s (use `set` to create)", name)
			}
			recips, err := crypto.ParseRecipients(s.Recipients)
			if err != nil {
				return err
			}
			val, err := readValue("New value: ")
			if err != nil {
				return err
			}
			armored, err := crypto.Encrypt(val, recips)
			if err != nil {
				return err
			}
			sec.Value = armored
			sec.UpdatedAt = time.Now().UTC()
			if rotate != "" {
				t, err := time.Parse("2006-01-02", rotate)
				if err != nil {
					return fmt.Errorf("rotate-after: %w", err)
				}
				sec.RotateAfter = &t
			}
			if err := applyExpiry(sec, ttl, expiresAt); err != nil {
				return err
			}
			if err := s.Save(); err != nil {
				return err
			}
			if err := logAudit("rotate", name, ""); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "rotated %s\n", name)
			return nil
		},
	}
	c.Flags().StringVar(&rotate, "rotate-after", "", "set the next rotation date (YYYY-MM-DD)")
	c.Flags().StringVar(&ttl, "ttl", "", "refresh expiry to a relative duration (e.g. 30m, 12h, 7d, 2w)")
	c.Flags().StringVar(&expiresAt, "expires-at", "", "refresh expiry to an absolute time (RFC3339 or YYYY-MM-DD)")
	return c
}

// newStale lists secrets due for rotation: those whose rotate_after is in the past (or within
// --within days). With --missing it instead lists secrets that have no rotation policy at all.
func newStale() *cobra.Command {
	var within int
	var missing, jsonOut bool
	c := &cobra.Command{
		Use:   "stale",
		Short: "List secrets due for rotation (rotate_after past, or within --within days)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			s, err := openStore()
			if err != nil {
				return err
			}
			now := time.Now()

			if missing {
				views := []secretView{}
				rows := [][]string{}
				for _, name := range s.Names() {
					sec := s.Secrets[name]
					if sec.RotateAfter != nil {
						continue
					}
					if jsonOut {
						views = append(views, viewOf(name, sec, time.Time{}, 0))
					} else {
						rows = append(rows, sanitizeAll([]string{name, strings.Join(sec.Tags, ","), sec.UpdatedAt.Local().Format("2006-01-02")}))
					}
				}
				if jsonOut {
					return emitJSON(views)
				}
				renderTable([]string{"NAME", "TAGS", "UPDATED"}, rows)
				return nil
			}

			// cutoff = now (+within days): surface anything whose rotation is due or whose hard
			// expiry falls on or before it. With the default --within 0 that means overdue
			// rotations and already-expired secrets; a larger window looks ahead.
			cutoff := now.AddDate(0, 0, within)
			views := []staleView{}
			rows := [][]string{}
			for _, name := range s.Names() {
				sec := s.Secrets[name]
				rotDue := sec.RotateAfter != nil && !sec.RotateAfter.After(cutoff)
				expSoon := sec.ExpiresAt != nil && !sec.ExpiresAt.After(cutoff)
				if !rotDue && !expSoon {
					continue
				}
				ra, ex := "-", "-"
				var status []string
				if rotDue {
					ra = sec.RotateAfter.Format("2006-01-02")
					days := int(now.Sub(*sec.RotateAfter).Hours() / 24)
					if days < 0 { // due in the future but within the window
						status = append(status, fmt.Sprintf("rotate in %dd", -days))
					} else {
						status = append(status, fmt.Sprintf("%dd overdue", days))
					}
				}
				if expSoon {
					ex = sec.ExpiresAt.Local().Format("2006-01-02 15:04")
					if now.After(*sec.ExpiresAt) {
						status = append(status, "EXPIRED")
					} else {
						status = append(status, "expiring")
					}
				}
				if jsonOut {
					views = append(views, staleView{Name: name, RotateAfter: sec.RotateAfter, ExpiresAt: sec.ExpiresAt, Status: status})
				} else {
					rows = append(rows, sanitizeAll([]string{name, ra, ex, strings.Join(status, ", ")}))
				}
			}
			if jsonOut {
				return emitJSON(views)
			}
			renderTable([]string{"NAME", "ROTATE AFTER", "EXPIRES", "STATUS"}, rows)
			return nil
		},
	}
	c.Flags().IntVar(&within, "within", 0, "also include secrets due within N days")
	c.Flags().BoolVar(&missing, "missing", false, "instead, list secrets with no rotation policy")
	c.Flags().BoolVar(&jsonOut, "json", false, "output JSON")
	return c
}
