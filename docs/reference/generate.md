# `vens generate`

**Who this is for:** anyone looking up a flag or an exit code.
**By the end of this page:** you know every flag of the `generate` command.

For a walkthrough, see **[Quickstart](../getting-started/quickstart.md)**.

---

## Synopsis

```
vens generate --config-file CONFIG --sbom-serial-number urn:uuid:<uuid> INPUT OUTPUT [flags]
```

Generate a CycloneDX VEX document from a Trivy or Grype vulnerability report, with an OWASP risk rating for each CVE in your deployment. The LLM answers closed questions about each CVE; vens computes every level, the severity and the score. See **[How vens rates a CVE](../concepts/cvss-vs-owasp.md#how-vens-rates-a-cve)**.

---

## Arguments

| Argument | Description |
|---|---|
| `INPUT` | Path to a Trivy or Grype JSON report. Format is auto-detected. |
| `OUTPUT` | Path where the generated CycloneDX VEX document will be written. Parent directory must exist. |

---

## Required flags

### `--config-file <path>`

Path to your [`config.yaml`](config-schema.md) file, in schema 2 (`schema_version: 2`). A file written for vens v0.6 or earlier is refused at load, before any LLM call: see **[Migrating from vens v0.6](config-schema.md#migrating)**. Warnings about fields left out are logged at load, before any LLM call.

### `--sbom-serial-number <urn:uuid:...>`

The `serialNumber` of the CycloneDX SBOM paired with this scan. Vens uses it to build the BOM-Link `urn:cdx:<uuid>/<version>#<bom-ref>` references in the generated VEX so each `affects` entry resolves back to that SBOM. **Required** and **must** start with `urn:uuid:`.

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

Pick the LLM provider. Default: `auto`, which resolves to `openai`. There is no detection: `auto` never looks at your environment to choose the provider, so an Anthropic or Gemini key on its own still sends the run to OpenAI, which then stops with `openai: OPENAI_API_KEY is not set`. Only the choice of provider ignores the environment; once it lands on OpenAI the run reads `OPENAI_MODEL`, `OPENAI_API_KEY` and, if you set it, `OPENAI_BASE_URL`.

| Value | Provider | Env vars |
|---|---|---|
| `auto` | OpenAI, same as `openai` | `OPENAI_API_KEY`, `OPENAI_MODEL` |
| `openai` | OpenAI | `OPENAI_API_KEY`, `OPENAI_MODEL` |
| `anthropic` | Anthropic Claude | `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` |
| `googleai` | Google AI (Gemini) | `GOOGLE_API_KEY` (or `GEMINI_API_KEY`), `GOOGLE_MODEL` |
| `ollama` | Ollama (local) | `OLLAMA_MODEL` (required), `OLLAMA_HOST` |

Any provider other than OpenAI needs an explicit `--llm`.

The `*_MODEL` variables are optional for the three cloud providers and fall back to `gpt-5.4-mini`, `claude-sonnet-4-6` and `gemini-2.5-flash`, logged as a warning at startup. Ollama has no default: without `OLLAMA_MODEL` the run stops with `ollama: set the OLLAMA_MODEL environment variable`.

```bash
vens generate --llm openai --config-file c.yaml --sbom-serial-number "$SBOM_UUID" in.json out.json
```

### `--llm-batch-size <int>`

Number of distinct CVEs in a batch. Default: `10`. A CVE found in several packages counts once.

Each batch gets one call per question, in a fixed order, about the batch's CVEs that get that question: up to 12 calls per batch. Each flagged CVE then gets one more call of its own, the adjustment. So a CVE is sent once per question asked about it, and the batch size sets how many CVEs share each call, not how many calls a CVE gets.

- Lower values (e.g. `5`) — fewer CVEs per call, more calls, safer for small context windows.
- Higher values (e.g. `20`) — fewer calls, more tokens per call.

The run summary at the end of each run gives the calls made, per question (see **[The run summary](#the-run-summary)**).

```bash
vens generate --llm-batch-size 15 ...
```

### `--llm-temperature <float>`

LLM sampling temperature. Only sent to the provider when the flag is explicitly passed — by default no temperature is sent at all (the `0.0` default is never forwarded on its own), so each provider applies its own default instead: `0.8` for Ollama, `1.0` for OpenAI, Gemini and Anthropic. Values above `0` — including those provider defaults — introduce randomness and are not recommended for production scoring. Passing `--llm-temperature 0` together with `--llm-seed` reduces drift between runs, but it doesn't make runs deterministic. Note: some models don't take an explicit temperature. Current Anthropic generations reject it, so passing the flag with one of them fails fast with a clear error; OpenAI reasoning models (o-series and `gpt-5*`, which includes the default `gpt-5.4-mini`) ignore it.

### `--llm-seed <int>`

Seed forwarded to the LLM when the provider supports it. Default: `0` (no explicit seed sent). OpenAI, Google AI and Ollama accept a `seed` parameter; Anthropic has none, so on Anthropic this flag is silently ignored.

!!! warning "Reproducibility is best-effort, not a guarantee"
    Even at `--llm-temperature 0.0` with a fixed `--llm-seed`, **byte-identical scores across runs are not guaranteed**. Cloud LLM providers periodically update server-side models without changing the API model name, and most of them do not expose true deterministic decoding. What Vens does do is:

    - Ask closed questions: the model picks a named answer from a fixed list, never a number, and vens computes every level, the severity and the score in Go. Given the same answers, the rating is the same.
    - Keep the same prompts, schemas and question order across runs.

    An answer that changes between runs moves its factor's level, and with it the score, and the severity when the likelihood or the impact crosses a band boundary. How often that happens depends on the model; vens does not promise a figure. If you need strict reproducibility (for audit evidence at a fixed point in time), pin a local Ollama model version, pass `--llm-temperature 0 --llm-seed <n>`, **and** archive the `--debug-dir` output — together they give you a byte-exact record of what was sent and returned, and `answers.json` gives each answer and the level vens read from it.

### `--input-format <auto|trivy|grype>`

Force the input parser. Default: `auto`.

```bash
vens generate --input-format grype --config-file c.yaml --sbom-serial-number "$SBOM_UUID" report.json out.json
```

### `--output-format <auto|cyclonedxvex>`

Output format. Default: `auto`. Currently only `cyclonedxvex` is supported.

### `--cyclonedx-spec-version <1.6|1.7>`

CycloneDX spec version for the VEX output. Default: `1.6`.

The default is `1.6` because no released Dependency-Track version can ingest a 1.7 BOM yet (it is rejected as an unrecognized specVersion) — 1.6 lands out of the box. Opt up to `1.7` if your consumer understands it. The `--attest` sidecar is emitted at the same spec version as the VEX. Any value other than `1.6` or `1.7` is rejected with an error.

```bash
vens generate --cyclonedx-spec-version 1.7 \
  --config-file c.yaml \
  --sbom-serial-number "$SBOM_UUID" \
  report.json out.json
```

### `--debug-dir <path>`

Directory where Vens writes, for every LLM call, the prompts it sends and the raw reply it gets back. Useful for auditing scores, debugging unexpected results, and producing evidence for compliance reviews.

Each run writes into a `run-*` subdirectory of its own, logged when the run starts, so runs that share a `--debug-dir`, even in parallel, never overwrite each other:

```bash
vens generate \
  --debug-dir ./vens-debug \
  --config-file c.yaml \
  --sbom-serial-number "$SBOM_UUID" \
  report.json out.json
# ... level=INFO msg="Writing debug files" dir=./vens-debug/run-3787846641
ls vens-debug/run-3787846641/
# batch-00001.human.prompt  batch-00001.response  batch-00001.system.prompt
# batch-00002.human.prompt  batch-00002.response  batch-00002.system.prompt
# ...
```

Each run adds a new `run-*` directory, and nothing deletes the old ones. Remove them when you are done, for example with `rm -rf vens-debug/run-*`.

**What you get**, for each LLM call, numbered from `00001` in call order:

- `batch-NNNNN.system.prompt` — the system prompt, the same for every call of a run: the role, your deployment (project name and description, exposure with its meaning and the attacker group, `listener` when `present` or `absent`, `notes`) and the rules for answering. Shape (truncated):

    ```
    You are a security expert. You answer questions of the OWASP Risk Rating Methodology about vulnerabilities found in one deployment, described below. ...

    DEPLOYMENT
    Project: python-backend-api
    Description: Python 3.11 backend API service handling customer data
    Exposure: internet (Publicly accessible). The attacker group to consider is anonymous Internet users.
    Notes: Customer-facing REST API built with FastAPI/Flask ...

    Judge each vulnerability from its own entry and this deployment. Choose cannot_tell only when the facts given do not decide between the other answers. ...
    ```

- `batch-NNNNN.human.prompt` — the request: the CVE entries of that call as JSON (vuln id, title, description, severity, packages), then one question, the config fields that question shows, and its closed list of answers. An adjustment call holds one flagged CVE with the evidence of its flag. Shape (truncated):

    ```
    VULNERABILITIES
    [{"vulnId":"CVE-2011-3374","title":"...","description":"...","severity":"LOW","packages":[...]}, ...]

    QUESTION
    How motivated are anonymous Internet users to find and exploit this vulnerability in this service? ...

    FOR THIS QUESTION
    Business criticality: high (Customer-facing, important operations)
    Data sensitivity: high (PII, financial data, customer info)

    ANSWERS
    - low_or_no_reward: Low or no reward: ...
    - possible_reward: Possible reward: ...
    - high_reward: High reward: ...
    - cannot_tell: The facts given do not say.
    ...
    ```

- `batch-NNNNN.response` — the model's raw reply to that call: for each CVE, its answer and one sentence of reasoning. It is written before Vens parses it, so a reply that fails to parse is on disk too. A call that failed, such as one the provider truncated, has no `.response`.

The JSON Schema of each reply is sent to the provider with the call, not written to these files.

Numbers count LLM calls, not `--llm-batch-size` batches: each batch makes one call per question, a call the provider truncates is retried in two halves, and the CVEs a reply leaves out are asked again in one more call, each with its own number.

Each run also writes **`answers.json`**: for each CVE, each of the 16 factors in the vector's order with the answer as the reply wrote it (when the question was asked), how vens read it (`answered`, `cannot_tell`, `invalid` for an answer off its list, `no_description`), the level, and where the level came from (`answer`, `constant`, `config`, `floor`, `adjustment`); whether the adjustment was made and how it read; the CVE's counters; and the run's counters summed. A run that fails also lists, marked `unrated` and without levels, the CVEs of the batch it failed in that already had answers. It holds no reasoning and no CVE text, but keeps each answer verbatim.

```json
{
  "vulnerabilities": [
    {
      "vulnId": "CVE-2011-3374",
      "adjustment": "not_asked",
      "factors": [
        { "factor": "SL", "level": 9, "source": "constant" },
        { "factor": "M", "answer": "possible_reward", "reading": "answered", "level": 4, "source": "answer" },
        ...
      ],
      "counters": ["detection_undeclared", "traceability_missing"]
    },
    ...
  ],
  "counters": { "applicability_missing": 5, "data_subjects_missing": 25, "detection_undeclared": 45, "traceability_missing": 45, ... }
}
```

!!! note "Matching the files to the `--attest` evidence"
    Match a call's files to its `evidence-batch-N` entry by `prompt_hash`, not by number: the attestation records only the calls that succeeded, so after a truncated call, `batch-00002` can be `evidence-batch-1`. `prompt_hash` is the SHA-256 of the system prompt, two newlines, then the human prompt:

    ```bash
    cd vens-debug/run-3787846641
    { cat batch-00002.system.prompt; printf '\n\n'; cat batch-00002.human.prompt; } | sha256sum
    jq -r '.declarations.evidence[] | .["bom-ref"] + " " + (.data[] | select(.name == "prompt_hash") | .contents.attachment.content)' ../../out.attestation.cdx.json
    ```

    An ask-again that holds every CVE of the call it repeats sends the same prompt word for word, so two entries can share a hash. They come in the same order as the files, and each entry's `raw_response` is its call's `.response`, base64-encoded.

Each CVE's score, severity and vector are also logged to stderr at `INFO`, once per affected package (`Scored vulnerability`), and the questions planned for each CVE at `DEBUG` (run with `DEBUG=1` to see them).

!!! warning "Treat `--debug-dir` output as sensitive"
    These files contain the **full text** of what was sent to the LLM provider and of what it sent back:

    - The parts of your `config.yaml` the questions show, including the `notes` field verbatim. `data_subjects`, `detection`, `traceability`, `audit_requirement` and the `ids`, `siem` and `edr` controls are never sent, so they are not in these files.
    - Every CVE identifier from the scanned image, plus titles and descriptions.
    - The model's answers and reasoning for each CVE in your context, and in `answers.json` each answer as the model wrote it.

    On Linux and macOS, Vens creates each run directory and its files readable by your user only (`0700` and `0600`). Do **not** commit them to a public repository. In CI, either delete the directory after inspection or upload it to an access-controlled artifact store.

!!! note "Retention for compliance workloads"
    If you need the debug output as audit evidence (HIPAA-style 6-year retention, SOC 2 change log, PCI-DSS risk decisions), store it in the same encrypted, access-controlled system you use for other security audit logs. Treat each `run-*` directory as one entry in your vulnerability-triage evidence chain, indexed by scan date and by the Git SHA of the `config.yaml` that produced it. Reasoning can only be reconstructed later if **both** the `config.yaml` version and the debug files are preserved — a copy of the VEX alone is not enough.

### `--attest`

Opt-in. Emits a [CycloneDX Attestations (CDXA)](https://cyclonedx.org/specification/overview/) sibling file next to the VEX, capturing what the LLM saw and produced so the run can be audited and reproduced later. Off by default.

```bash
vens generate --attest \
  --config-file c.yaml \
  --sbom-serial-number "$SBOM_UUID" \
  report.json out.cdx.json
# writes out.cdx.json AND out.attestation.cdx.json
```

**What it contains** (CDX BOM at the same spec version as the VEX — `1.6` by default, or whatever `--cyclonedx-spec-version` selects — everything under `declarations`):

- `claims[]` — one per scored CVE/affected component, linked to its target component and to the evidence of every call that answered for the CVE. The `predicate` gives the score and the severity; the `reasoning` holds one line per question answered, `factor (answer): sentence`, and one for the adjustment when the CVE was flagged.
- `targets.components[]` — the affected components the claims point at
- `evidence[]` — one per LLM call that returned a reply, recording how the scoring was produced:
    - `generation_method` — `llm`
    - `provider` / `model` — backend and model used (e.g. `openai` / `gpt-5.4-mini`); when the provider's `*_MODEL` env var is unset, vens falls back to that provider's default and logs it
    - `seed` — the LLM seed (`0` if unset)
    - `temperature` — the sampling temperature (only present when `--llm-temperature` was explicitly passed)
    - `prompt_hash` — SHA-256 of `system_prompt + "\n\n" + human_prompt`
    - `input_hash` — SHA-256 of the scanner report bytes
    - `config_hash` — SHA-256 of the `config.yaml` used
    - `raw_response` — base64-encoded raw LLM JSON reply (flagged `sensitiveData`)
- `assessors[]` + `attestations[]` — tie the claims to vens as the producer; a human reviewer can later add their own assessor/attestation over the same claims without touching the LLM evidence

The producing `vens` version is recorded in `metadata.tools`. The attestation is a `file` component that links to the VEX it describes through a `bom` external reference (`urn:cdx:<vex-serial>/<version>`).

!!! note "Reproducibility scope"
    The attestation records the inputs and outputs of each LLM call. Recreating a score also requires the `config.yaml` used at the time — keep it under version control alongside the attestation.

!!! warning "The attestation is sensitive — store it like audit evidence"
    The claims spell out, in clear text, which CVEs you scored, their scores and the model's reasoning, and `raw_response` holds the full model reply **base64-encoded, not encrypted** (anyone with the file can decode it). The prompt, scanner report and config are kept only as SHA-256 hashes, so the raw vulnerability list is not embedded, but the assessment itself is fully readable. In CI, write the attestation to the same access-controlled store as your other security evidence, not to a public build artifact.

### `--strict`

New in v0.7.0. Fails a run that would use a worst-case fallback, and writes no VEX and no attestation; a VEX or an attestation an earlier run left at the output path stays as it was. Off by default: without it, vens uses each fallback and counts it in the [run summary](#the-run-summary).

A strict run fails at the first of three checks that finds one, with exit code 1:

1. **At load**, before the LLM provider is set up: `data_subjects`, `detection` or `traceability` left out.

    ```text
    strict: context.data_subjects, context.detection, context.traceability not declared, so each would fall back to its worst case
    ```

2. **Before any LLM call**: a CVE whose CVSS vectors leave an axis undecided (no CVSS vector in the scanner's report, a vector that does not parse, one that lacks an axis metric or gives one a value off its scale), or a CVE with no description. One error lists every such CVE with its causes:

    ```text
    failed to generate risk scores: strict: 2 vulnerabilities would fall back to a worst case, so no LLM call is made:
      CVE-2026-2673: applicability_missing: no CVSS vector in the scanner's report
      CVE-2026-3184: applicability_missing: no CVSS vector in the scanner's report; no description in the scanner's report, so Motive, Opportunity and Ease of exploit read cannot_tell
    ```

    Here the cause is the scan, not your config. A scan holding a CVE with no CVSS vector in the scanner's report cannot pass `--strict`, and nothing in vens fixes it: the vector has to come from the scanner. Without `--strict`, such a CVE has its losses asked instead of floored, and counts in `applicability_missing`.

3. **During the run**: the first answer to a question that reads as `cannot_tell`, an answer off its list included. The run stops after that call:

    ```text
    failed to generate risk scores: strict: the answer to Privacy violation (PV) for CVE-2024-2222 reads as cannot_tell, counted as privacy_cannot_tell; stopping the run
    ```

The adjustment's `cannot_tell` keeps the answer the CVE already had: it is not counted and does not fail a strict run. To pass the first check, declare `data_subjects`, `detection` and `traceability`, as the **[fully declared file](config-schema.md#fully-declared-file)** does.

```bash
vens generate --strict --config-file c.yaml --sbom-serial-number "$SBOM_UUID" report.json out.json
```

### `--sbom-version <int>`

BOM-Link `version` number used alongside `--sbom-serial-number`. Default: `1`.

---

## The run summary

A run that reaches scoring ends with one `INFO` line, `Scoring run finished`, also when it fails during scoring:

```text
level=INFO msg="Scoring run finished" rows=107 cves=45 llm_calls=61 asked_again=0 splits=0 calls.M=5 calls.O=5 ... calls.adjustment=6 counters.applicability_missing=5 counters.data_subjects_missing=25 counters.detection_undeclared=45 counters.traceability_missing=45 failed=false
```

- `rows` and `cves` — the scanner's findings, and the distinct CVEs among them.
- `llm_calls`, `asked_again`, `splits` — every call made, the calls that asked again for CVEs a reply left out, and the calls split in half after the provider truncated them.
- `calls.<factor>` — the calls of each question (`M`, `O`, `EE`, `ID`, `LC`, `LI`, `LAV`, `LAC`, `FD`, `RD`, `NC`, `PV`), and `calls.adjustment`. A question no CVE needs makes no call.
- `counters.*` — one per CVE that used a fallback, shown when not zero:
    - `<factor>_cannot_tell` (`motive_cannot_tell`, `opportunity_cannot_tell`, `ease_of_exploit_cannot_tell`, `intrusion_detection_cannot_tell`, `confidentiality_cannot_tell`, `integrity_cannot_tell`, `availability_cannot_tell`, `accountability_cannot_tell`, `financial_damage_cannot_tell`, `reputation_cannot_tell`, `non_compliance_cannot_tell`, `privacy_cannot_tell`) — the answer read as `cannot_tell`, or an answer off its list, so the question's worst answer applied. That is the factor's worst level, except where a rule still limits it: Intrusion detection takes the worst channel `detection` declares, `data_subjects` caps Privacy violation, and a flagged CVE's adjustment can lower Opportunity, a loss or Privacy violation. A CVE with no description counts in `motive_cannot_tell`, `opportunity_cannot_tell` and `ease_of_exploit_cannot_tell`, whatever the model answered.
    - `detection_undeclared`, `traceability_missing`, `data_subjects_missing` — the fallback of a field left out of `config.yaml`.
    - `applicability_missing` — the CVE's CVSS vectors left an axis undecided, so its loss was asked instead of floored.
    - `severity_contested_unavailable` — no record in the report to check the CVE's severity against NVD's, so a contested severity could not be flagged.
    - `reasoning_missing` — a reply gave no reasoning for one of the CVE's answers; the answer is kept.
- `defects.*` — replies that break the schema or the instructions, counted by kind: `answer_off_list`, `answer_key_written_twice`, `answer_without_reasoning`, `answer_cve_not_asked`, `answer_cve_repeated`, and for the adjustment `adjustment_unreadable`, `adjustment_key_written_twice`, `adjustment_off_list`, `adjustment_field_not_asked`, `adjustment_without_reasoning`. A provider that honours the schema and the prompt writes none.
- `failed` — whether the run failed.

A run that stops before scoring starts logs no summary, such as one whose config fails to load or fails `--strict`'s config check; a report with no vulnerabilities logs none either.

`--debug-dir` writes the same counters, per CVE, to `answers.json`.

---

## Environment variables

| Variable | Purpose |
|---|---|
| `OPENAI_API_KEY` | OpenAI credentials |
| `OPENAI_MODEL` | OpenAI model name (e.g. `gpt-5.4-mini`) |
| `ANTHROPIC_API_KEY` | Anthropic credentials |
| `ANTHROPIC_MODEL` | Anthropic model name (e.g. `claude-sonnet-4-6`) |
| `GOOGLE_API_KEY` | Google AI credentials |
| `GEMINI_API_KEY` | Google AI credentials (fallback used when `GOOGLE_API_KEY` is unset) |
| `GOOGLE_MODEL` | Google AI model name (e.g. `gemini-2.5-flash`) |
| `OLLAMA_MODEL` | Ollama model name (e.g. `llama3.1`) |

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success — VEX written to `OUTPUT` |
| `1` | Failure: I/O, a config that does not load, an LLM call, or a `--strict` check |
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
export OPENAI_MODEL=gpt-5.4-mini

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
export ANTHROPIC_MODEL=claude-sonnet-4-6
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
