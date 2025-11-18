# Testing Strategy

## Unit tests (pkg/*)
- Focus on isolated functions (helpers, etc.).
- Fast, with no external dependencies (do not mock).
- Goal: catch logical regressions early and ensure flag/output interfaces remain stable.

## Integration / CLI tests (cmd/*)
- Run the `vens` binary against real inputs and a real LLM.
- Target key commands: `prioritize`, etc.
- Goal: validate `vens` integration with real `dependencies`.

## End-to-end tests (scenarios)
- Multi-step scenarios (e.g., `read` → `parse` → `prioritize` → `output`).
- Goal: ensure cross-cutting features work together and remain stable.

## Regression / issue-driven tests
- Added after fixing specific bugs; reproduce the before/after case.
- Goal: prevent the bug from being reintroduced.

## Static checks (CI)
- `go vet`, linters, formatting, sometimes “golden tests” for CLI output.
- Goal: code quality and a stable user interface (stable outputs).
