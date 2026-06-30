# Contributing to arca

Thanks for your interest in arca. This covers how to build, test, and submit changes.

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
- Keep the dependency set small. The only third-party runtime dependencies are age, cobra, the
  pure-Go SQLite driver, the MCP SDK, and `golang.org/x/term`. Adding one needs a good reason.

## Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not open public issues for
security problems, and never paste secret values or private keys into an issue or PR.

## Submitting

- Write a commit message that explains the change and its motivation.
- Update `CHANGELOG.md` (the `Unreleased` section) and any docs the change affects.
