# Testing Strategy

## Unit tests (pkg/*)
- Focus on isolated functions (helpers, etc.).
- Fast, with no external dependencies (do not mock).
- Goal: catch logical regressions early and ensure flag/output interfaces remain stable.

## Integration / CLI tests (cmd/*)
- Run the `vens` binary against real inputs and a real LLM.
- Target key commands: `generate`, etc.
- Goal: validate `vens` integration with real `dependencies`.

## End-to-end tests (scenarios)
- Multi-step scenarios (e.g., `index` → `generate` → `output`).
- Goal: ensure cross-cutting features work together and remain stable.

## Regression / issue-driven tests
- Added after fixing specific bugs; reproduce the before/after case.
- Goal: prevent the bug from being reintroduced.

## Static checks (CI)
- `go vet`, linters, formatting, sometimes “golden tests” for CLI output.
- Goal: code quality and a stable user interface (stable outputs).

## Nightly real-provider smoke test (CI)
- Workflow: `.github/workflows/nightly-llm-smoke.yml`, on a `0 6 * * *` cron (plus manual `workflow_dispatch`).
- Runs `vens generate` against each real provider (OpenAI, Anthropic, Google, Ollama) on the tiny fixture in `.github/llm-smoke/` and asserts a valid *scored* VEX via `.github/llm-smoke/check-vex.py`.
- Goal: catch provider-side response-format changes that the mock-based tests cannot see (issue #175).
- Keys come from repo secrets (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`); model overrides via the usual `*_MODEL` env vars also work. A provider without its key is skipped gracefully with a notice, so the workflow stays green on forks and before secrets are configured. It never runs on pull requests.
- Ollama runs against a local server: the workflow installs Ollama and pulls `qwen2.5:0.5b` (server-side constrained decoding keeps the schema valid on any model).

To run the same check locally (costs real API calls):

```sh
go build -o vens ./cmd/vens
export OPENAI_API_KEY=<redacted>  # or ANTHROPIC_API_KEY / GOOGLE_API_KEY
./vens generate --llm=openai \
  --config-file=.github/llm-smoke/config.yaml \
  --sbom-serial-number=urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79 \
  .github/llm-smoke/report.json vex.cdx.json
python3 .github/llm-smoke/check-vex.py vex.cdx.json
```
