# Contributing to arca

Thanks for your interest in arca. This covers how to build, test, and submit changes.

## Repositories

The project spans three repositories:

- **[arenzana/arca](https://github.com/arenzana/arca)** — this repository: the source code, tests,
  documentation, and the website (`docs/`). This is the only one developed directly.
- **[arenzana/homebrew-tap](https://github.com/arenzana/homebrew-tap)** — the Homebrew cask,
  **published automatically** by the release pipeline; not hand-edited.
- **[arenzana/scoop-bucket](https://github.com/arenzana/scoop-bucket)** — the Scoop manifest,
  likewise auto-published on each release.

## Development setup

arca is a single Go module with no build-time code generation.

```sh
git clone https://github.com/arenzana/arca
cd arca
make build      # or: go build .
make test       # go test -race ./...
```

You need a recent Go toolchain (see the `go` directive in `go.mod`) and `git`.

## Branching and review

- `main` is protected — changes land via a pull request with green CI.
- Work on a feature branch (or `develop`) and open a PR against `main`.
- CI runs on Linux, macOS, and Windows; the statement-coverage threshold is 90%.

## Tests

Unit and integration tests live next to the code. The end-to-end suite builds the real binary
and drives it as a black box; it sits under `e2e/` behind the `e2e` build tag.

```sh
go test -race ./...            # unit + integration
go test -tags e2e ./e2e/...    # end-to-end (also exercised on macOS and Windows in CI)
```

New behavior needs a test, and error paths matter — much of arca is about failing closed.

## Linting

CI runs `go vet`, `staticcheck`, and `gosec` (medium severity and up):

```sh
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go run github.com/securego/gosec/v2/cmd/gosec@latest -severity medium ./...
```

`exec` calls and config-derived file paths trip gosec G204/G304. Annotate them with a justified
`//#nosec` only when the input is genuinely operator-controlled, never to silence untrusted input.

## Style

- Match the surrounding code: standard library first, small focused functions, comments that
  explain *why*.
- Keep the dependency set small (see Dependencies below).

## Dependencies

arca prefers the Go standard library and adds a third-party dependency only when it would
otherwise mean reimplementing something security-sensitive. The whole runtime set is:

- **`filippo.io/age`** — the X25519 encryption that protects secrets at rest.
- **`github.com/spf13/cobra`** — the command tree.
- **`modernc.org/sqlite`** — a pure-Go SQLite driver for the audit log (no cgo, keeping
  builds reproducible and cross-compilation trivial).
- **`github.com/mark3labs/mcp-go`** — the MCP server SDK.
- **`golang.org/x/term`** — no-echo TTY reads.
- **`github.com/charmbracelet/lipgloss`** — styled, bordered tables for `log`/`ls`/`grants`/etc.
  (styling only, no TUI/event loop; output falls back to plain columns when piped).

**Selecting** one: a new direct dependency needs a clear reason in the PR, a compatible
license, and a healthy upstream; prefer the standard library or a small, well-scoped module
over a large framework. **Obtaining** them: dependencies are fetched and pinned through Go
modules (`go.mod` / `go.sum`), and module integrity is checked with `go mod verify` in CI and
before every release. **Tracking** them: Dependabot (`.github/dependabot.yml`) proposes weekly
updates for Go modules and GitHub Actions, `govulncheck` runs in CI to flag known
vulnerabilities, and a CycloneDX SBOM is generated so the full dependency set is auditable.

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not open public issues for
security problems, and never paste secret values or private keys into an issue or PR.

## Sign your commits (DCO)

arca uses the [Developer Certificate of Origin](https://developercertificate.org/). By signing
off a commit you certify that you wrote the change, or otherwise have the right to submit it
under the project's license. Every commit in a pull request must carry a `Signed-off-by:`
trailer — CI checks this and a PR with an unsigned commit will not pass.

Add the trailer automatically when you commit:

```sh
git commit -s
```

It appends a line matching your `git` identity:

```
Signed-off-by: Your Name <you@example.com>
```

If you forgot it on commits already made, add it across the branch with:

```sh
git rebase --signoff main
```

## Submitting

- Write a commit message that explains the change and its motivation, and sign it off (`-s`).
- Update `CHANGELOG.md` (the `Unreleased` section) and any docs the change affects.
