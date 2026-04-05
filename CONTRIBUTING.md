# Contributing to Vens

Thank you for your interest in contributing to Vens! This guide tells you exactly what to expect from the review process, the coding standards we enforce, and how to get a first PR landed.

---

## Ways to contribute

- **Good first issues** — look for the [`good first issue`](https://github.com/venslabs/vens/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label on the issue tracker. If the label list is empty or you have something else in mind, open a `Question` issue first and we'll help you scope it.
- **Bug reports** — use the issue tracker with clear reproduction steps, the command line you ran, your `vens --version`, and (if possible) redacted `--debug-dir` output.
- **Documentation** — doc-only PRs are welcome and land fast. Start with `docs/` and `mkdocs.yml`.
- **New features / scanners / LLM providers** — please open an issue first so we can agree on scope before you write the code.
- **Security reports** — please follow [SECURITY.md](SECURITY.md); do not open public issues for vulnerabilities.

---

## Development setup

Prerequisites:

- Go (see `go.mod` for the minimum version; Vens pins via `go.mod`'s `go` directive)
- `make`
- `golangci-lint` (for linting — installed by the lint target on first run)
- Trivy or Grype for generating local test inputs

```bash
git clone https://github.com/YOUR_USERNAME/vens.git
cd vens

# Download deps
go mod download

# Build the binary (outputs to ./bin/)
make binaries

# Run the full test suite
make test

# Run the linter
make lint
```

---

## Code style

- **Go formatting** — everything must pass `gofmt -s` and `goimports`. The Makefile target `make fmt` does both. CI will fail if the working tree is not formatted.
- **Linting** — `make lint` runs `golangci-lint` with the project configuration in `.golangci.yml`. Fix or justify every finding before asking for review.
- **Package layout** — follow the structure already in `pkg/` and `cmd/vens/commands/`. New LLM providers live under `pkg/llm/`, new scanners under `pkg/scanner/`, new output formats under `pkg/outputhandler/`.
- **Error wrapping** — wrap with `fmt.Errorf("context: %w", err)` so error chains stay inspectable. Do not discard errors silently.
- **Logging** — use `log/slog` with the keyed form (`slog.InfoContext(ctx, "message", "key", value)`), never `log.Printf`.
- **Context propagation** — plumb `context.Context` through any function that does I/O or calls the LLM.
- **No breaking config changes without an issue first** — `config.yaml` is a user-facing contract.

---

## Tests

- Unit tests live next to the code they test, in `_test.go` files.
- End-to-end tests for the `vens` CLI live under `cmd/vens/testdata/script/` as [`rsc.io/script`](https://pkg.go.dev/rsc.io/script) scenarios. They use a mock LLM (`internal/testutil/mockllm`) so they run offline and deterministically. Add one scenario per CLI-visible behaviour change.
- Run the whole suite with `make test` before you open a PR. CI runs the same command.
- Integration tests against real LLM providers are **not** required (and not recommended) for contributions — the mock LLM is the test contract.

---

## Commit and PR style

- One logical change per commit. Squash noise before opening a PR (rebase interactively if needed).
- Commit messages use conventional-commits style when possible (`feat(...)`, `fix(...)`, `docs(...)`, `build(deps): ...`). The `git log` of the project is a good reference for tone.
- PR titles under 72 characters. Use the body to describe intent, trade-offs and testing.
- Link the issue the PR addresses with `Fixes #NNN` or `Refs #NNN`.
- Mark the PR as draft until CI is green and you're ready for review.

---

## Review process

- PRs are reviewed by the `venslabs/vens` maintainers. Expect a first response within a few working days.
- We may ask you to split a PR if it bundles unrelated changes, or to open a design issue before we merge a larger change.
- Dependabot PRs are rebased and merged automatically once CI passes; human PRs always get at least one manual review.
- After approval, maintainers merge. We prefer squash-merge so `main` stays linear.

---

## What's inspired this project

Vens' prompt structure and output-handler pattern are adapted from [AkihiroSuda/vexllm](https://github.com/AkihiroSuda/vexllm). Credit is also preserved in the code comments of the relevant files. If you work on the prompt or the output pipeline, please keep those references up to date.

---

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
