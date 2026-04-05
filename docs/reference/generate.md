# `vens generate`

**Who this is for:** anyone looking up a flag or an exit code.
**By the end of this page:** you know every flag of the `generate` command.

For a walkthrough, see **[Quickstart](../getting-started/quickstart.md)**.

---

## Synopsis

```
vens generate --config-file CONFIG INPUT OUTPUT [flags]
```

Generate a CycloneDX VEX document from a Trivy or Grype vulnerability report, with contextual OWASP risk scores computed by an LLM.

---

## Arguments

| Argument | Description |
|---|---|
| `INPUT` | Path to a Trivy or Grype JSON report. Format is auto-detected. |
| `OUTPUT` | Path where the generated CycloneDX VEX document will be written. Parent directory must exist. |

---

## Required flags

### `--config-file <path>`

Path to your [`config.yaml`](config-schema.md) file.

```bash
vens generate --config-file ./vens.yaml report.json vex.json
```

---

## Optional flags

### `--llm <provider>`

Force a specific LLM provider. Default: `auto` (detected from exported environment variables).

| Value | Provider | Env var used |
|---|---|---|
| `auto` | First detected | — |
| `openai` | OpenAI | `OPENAI_API_KEY`, `OPENAI_MODEL` |
| `anthropic` | Anthropic Claude | `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` |
| `googleai` | Google AI (Gemini) | `GOOGLE_API_KEY`, `GOOGLE_MODEL` |
| `ollama` | Ollama (local) | `OLLAMA_MODEL` |

```bash
vens generate --llm openai --config-file c.yaml in.json out.json
```

### `--llm-batch-size <int>`

Number of CVEs sent to the LLM per request. Default: `10`.

- Lower values (e.g. `5`) — fewer CVEs per call, more calls, safer for small context windows.
- Higher values (e.g. `20`) — fewer calls, faster, uses more tokens per call.

```bash
vens generate --llm-batch-size 15 ...
```

### `--llm-temperature <float>`

LLM sampling temperature. Default: `0.0` (deterministic). Values > 0 introduce randomness; not recommended for production scoring.

### `--llm-seed <int>`

Seed for LLM sampling (providers that support it). Default: `0` (no explicit seed). Use a fixed non-zero value together with `--llm-temperature 0.0` for the most reproducible runs.

### `--input-format <auto|trivy|grype>`

Force the input parser. Default: `auto`.

```bash
vens generate --input-format grype --config-file c.yaml report.json out.json
```

### `--output-format <auto|cyclonedxvex>`

Output format. Default: `auto`. Currently only `cyclonedxvex` is supported.

### `--debug-dir <path>`

Directory where Vens writes every prompt sent to the LLM and every response received. Useful for auditing scores or debugging unexpected results.

```bash
vens generate --debug-dir ./vens-debug --config-file c.yaml report.json out.json
ls vens-debug/
# prompt-batch-1.txt  response-batch-1.json
# prompt-batch-2.txt  response-batch-2.json
# ...
```

!!! warning
    The debug directory may contain CVE identifiers and your context file contents. Do not commit it to a public repository.

### `--sbom-serial-number <urn:uuid:...>`

Set the BOM-Link `serialNumber` field in the generated VEX. Use when linking the VEX back to a specific SBOM.

### `--sbom-version <int>`

Set the BOM-Link `version` field in the generated VEX. Default: `1`.

---

## Environment variables

| Variable | Purpose |
|---|---|
| `OPENAI_API_KEY` | OpenAI credentials |
| `OPENAI_MODEL` | OpenAI model name (e.g. `gpt-4o`) |
| `ANTHROPIC_API_KEY` | Anthropic credentials |
| `ANTHROPIC_MODEL` | Anthropic model name (e.g. `claude-sonnet-4-5`) |
| `GOOGLE_API_KEY` | Google AI credentials |
| `GOOGLE_MODEL` | Google AI model name (e.g. `gemini-2.0-flash`) |
| `OLLAMA_MODEL` | Ollama model name (e.g. `llama3.1`) |

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success — VEX written to `OUTPUT` |
| `1` | Generic failure (I/O, config validation, LLM call) |
| `2` | Invalid CLI usage (bad flags or arguments) |

!!! note
    `vens generate` does not fail based on CVE severity. To fail a CI pipeline on high contextual risk, filter the output VEX yourself — see [Prioritize a CVE backlog](../guides/prioritize-cves.md#put-it-in-ci).

---

## Examples

### Basic

```bash
export OPENAI_API_KEY=sk-...
export OPENAI_MODEL=gpt-4o

trivy image python:3.11-slim --format json --output report.json
vens generate --config-file vens.yaml report.json vex.json
```

### With Grype

```bash
grype python:3.11-slim -o json > report.json
vens generate --config-file vens.yaml report.json vex.json
```

### With debug output

```bash
vens generate \
  --config-file vens.yaml \
  --debug-dir ./debug \
  --llm-batch-size 5 \
  report.json vex.json
```

### Forcing Anthropic

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export ANTHROPIC_MODEL=claude-sonnet-4-5
vens generate --llm anthropic --config-file vens.yaml report.json vex.json
```

### Air-gapped with Ollama

```bash
# Ollama running on localhost:11434
export OLLAMA_MODEL=llama3.1
vens generate --llm ollama --config-file vens.yaml report.json vex.json
```

### As a Trivy plugin

Every example above also works as `trivy vens` — same flags, same behaviour:

```bash
trivy vens generate --config-file vens.yaml report.json vex.json
```

---

## See also

- **[config.yaml reference](config-schema.md)** — every field of the context file
- **[Quickstart](../getting-started/quickstart.md)** — end-to-end walkthrough
- **[Prioritize a CVE backlog](../guides/prioritize-cves.md)** — the common use case
