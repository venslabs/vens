# `vens generate`

**Who this is for:** anyone looking up a flag or an exit code.
**By the end of this page:** you know every flag of the `generate` command.

For a walkthrough, see **[Quickstart](../getting-started/quickstart.md)**.

---

## Synopsis

```
vens generate --config-file CONFIG --sbom-serial-number urn:uuid:<uuid> INPUT OUTPUT [flags]
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

### `--sbom-serial-number <urn:uuid:...>`

UUID used to build the BOM-Link `urn:cdx:<uuid>/<version>#<bom-ref>` references in the generated VEX. **Must** be provided and **must** start with `urn:uuid:`. Reuse the same UUID across runs when you want stable BOM-Links (for example when linking the VEX back to a specific SBOM in CI).

```bash
vens generate \
  --config-file ./vens.yaml \
  --sbom-serial-number urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79 \
  report.json vex.json
```

Generating an ad-hoc UUID on Linux/macOS:

```bash
SBOM_UUID="urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')"
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
vens generate --llm openai --config-file c.yaml --sbom-serial-number "$SBOM_UUID" in.json out.json
```

### `--llm-batch-size <int>`

Number of CVEs sent to the LLM per request. Default: `10`.

- Lower values (e.g. `5`) — fewer CVEs per call, more calls, safer for small context windows.
- Higher values (e.g. `20`) — fewer calls, faster, uses more tokens per call.

```bash
vens generate --llm-batch-size 15 ...
```

### `--llm-temperature <float>`

LLM sampling temperature. Default: `0.0` — keeps sampling as close to greedy as each provider supports. Values > 0 introduce randomness and are not recommended for production scoring.

### `--llm-seed <int>`

Seed forwarded to the LLM when the provider supports it. Default: `0` (no explicit seed sent). Today, OpenAI exposes a `seed` parameter; Anthropic and Google AI do not. On providers without seed support, this flag is silently ignored.

!!! warning "Reproducibility is best-effort, not a guarantee"
    Even at `--llm-temperature 0.0` with a fixed `--llm-seed`, **byte-identical scores across runs are not guaranteed**. Cloud LLM providers periodically update server-side models without changing the API model name, and most of them do not expose true deterministic decoding. What Vens does do is:

    - Compute the final OWASP score in Go from the LLM's four 0-9 component scores (`pkg/generator/generator.go`). Small drifts in the component scores are absorbed by the arithmetic.
    - Keep the same prompt, schema and ordering across runs.

    In practice, expect **score drift of ±1–3 points on a minority of CVEs** between runs with the same config and model. If you need strict reproducibility (for audit evidence at a fixed point in time), pin a local Ollama model version **and** archive the `--debug-dir` output — those two together give you a byte-exact record of what was sent and returned.

### `--input-format <auto|trivy|grype>`

Force the input parser. Default: `auto`.

```bash
vens generate --input-format grype --config-file c.yaml --sbom-serial-number "$SBOM_UUID" report.json out.json
```

### `--output-format <auto|cyclonedxvex>`

Output format. Default: `auto`. Currently only `cyclonedxvex` is supported.

### `--debug-dir <path>`

Directory where Vens writes the prompts it sends to the LLM. Useful for auditing scores, debugging unexpected results, and producing evidence for compliance reviews.

```bash
vens generate \
  --debug-dir ./vens-debug \
  --config-file c.yaml \
  --sbom-serial-number "$SBOM_UUID" \
  report.json out.json
ls vens-debug/
# system.prompt  human.prompt
```

**What you get:**

- `system.prompt` — the full system prompt sent to the LLM, including your `config.yaml` context formatted as text, the OWASP scoring instructions, and the JSON schema the LLM must return. Shape (truncated):

    ```
    You are a talented security expert scoring vulnerabilities using OWASP Risk Rating Methodology.

    SYSTEM CONTEXT:
    Project: my-python-api
    Description: Customer-facing Python API handling user data
    Exposure: internet
    Data Sensitivity: high
    Business Criticality: high
    Compliance Requirements: GDPR
    Security Controls: WAF
    ...

    TASK: For EACH vulnerability, analyze its specific characteristics and score 4 factors (0-9):
    1. THREAT_AGENT ...
    ...
    #### Output format: JSON Schema
    {...}
    ```

- `human.prompt` — the JSON array of CVEs sent to the LLM in the last batch (vuln id, pkg, title, description, severity). One file per run; the last batch overwrites earlier ones, so capture these per-batch by running with `--llm-batch-size 1` if you need a full trace.

Per-CVE component scores and the LLM's reasoning are logged to stderr at `INFO`/`DEBUG` level (run with `DEBUG=1` to see them).

!!! warning "Treat `--debug-dir` output as sensitive"
    These files contain the **full text** of what was sent to the LLM provider:

    - Your `config.yaml` context, including the `notes` field verbatim.
    - Every CVE identifier from the scanned image, plus titles and descriptions.

    Do **not** commit them to a public repository. In CI, either delete the directory after inspection or upload it to an access-controlled artifact store.

!!! note "Retention for compliance workloads"
    If you need the debug output as audit evidence (HIPAA-style 6-year retention, SOC 2 change log, PCI-DSS risk decisions), store it in the same encrypted, access-controlled system you use for other security audit logs. Treat each `--debug-dir` directory as one entry in your vulnerability-triage evidence chain, indexed by scan date and by the Git SHA of the `config.yaml` that produced it. Reasoning can only be reconstructed later if **both** the `config.yaml` version and the debug files are preserved — a copy of the VEX alone is not enough.

### `--sbom-version <int>`

BOM-Link `version` number used alongside `--sbom-serial-number`. Default: `1`.

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

All examples assume `$SBOM_UUID` is set, e.g.:

```bash
SBOM_UUID="urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')"
```

### Basic

```bash
export OPENAI_API_KEY=sk-...
export OPENAI_MODEL=gpt-4o

trivy image python:3.11-slim --format json --output report.json
vens generate --config-file vens.yaml --sbom-serial-number "$SBOM_UUID" report.json vex.json
```

### With Grype

```bash
grype python:3.11-slim -o json > report.json
vens generate --config-file vens.yaml --sbom-serial-number "$SBOM_UUID" report.json vex.json
```

### With debug output

```bash
vens generate \
  --config-file vens.yaml \
  --sbom-serial-number "$SBOM_UUID" \
  --debug-dir ./debug \
  --llm-batch-size 5 \
  report.json vex.json
```

### Forcing Anthropic

```bash
export ANTHROPIC_API_KEY=sk-ant-...
export ANTHROPIC_MODEL=claude-sonnet-4-5
vens generate --llm anthropic --config-file vens.yaml --sbom-serial-number "$SBOM_UUID" report.json vex.json
```

### Air-gapped with Ollama

```bash
# Ollama running on localhost:11434
export OLLAMA_MODEL=llama3.1
vens generate --llm ollama --config-file vens.yaml --sbom-serial-number "$SBOM_UUID" report.json vex.json
```

### As a Trivy plugin

Every example above also works as `trivy vens` — same flags, same behaviour:

```bash
trivy vens generate --config-file vens.yaml --sbom-serial-number "$SBOM_UUID" report.json vex.json
```

---

## See also

- **[config.yaml reference](config-schema.md)** — every field of the context file
- **[Quickstart](../getting-started/quickstart.md)** — end-to-end walkthrough
- **[Prioritize a CVE backlog](../guides/prioritize-cves.md)** — the common use case
