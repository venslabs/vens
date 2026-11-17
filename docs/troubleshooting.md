# Troubleshooting

**Who this is for:** anyone whose `vens generate` run didn't go the way the quickstart promised.
**By the end of this page:** you know how to diagnose the failure modes below.

When in doubt, rerun with debug output:

```bash
DEBUG=1 vens generate \
  --debug-dir ./vens-debug \
  --config-file config.yaml \
  --sbom-serial-number "urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')" \
  report.json vex.json
```

`--debug-dir` writes the prompts and the raw LLM response of every LLM call to disk, with `answers.json` for the run, in a `run-*` subdirectory of its own for each run. `DEBUG=1` raises the log level to `debug` and shows the questions planned for each CVE and the CVEs of each batch.

---

## `--config-file is required`

You omitted `--config-file`. Vens refuses to run without a [`config.yaml`](reference/config-schema.md) — the whole point is contextual scoring.

```bash
vens generate --config-file config.yaml --sbom-serial-number "$SBOM_UUID" report.json vex.json
```

---

## `sbom-serial-number is required`

`vens generate` needs `--sbom-serial-number` — it must be the `serialNumber` of the CycloneDX SBOM paired with this scan, in `urn:uuid:<uuid>` form. Extract it from the SBOM (`jq -r .serialNumber sbom.cdx.json`), or for ad-hoc runs generate one:

```bash
SBOM_UUID="urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')"
vens generate \
  --config-file config.yaml \
  --sbom-serial-number "$SBOM_UUID" \
  report.json vex.json
```

Pin the UUID as a repository variable when you need stable BOM-Links across CI builds.

---

## `context.exposure must be one of [internal private internet]`

Your `config.yaml` has a typo, an extra word, or a missing required field. Check [`config.yaml` reference](reference/config-schema.md) — the three required fields are `exposure`, `data_sensitivity`, `business_criticality`.

---

## `config.yaml has no schema_version`

The file was written for vens v0.6 or earlier. vens v0.7.0 reads schema 2 only and refuses the file before any LLM call. Add `schema_version: 2` at the top, then declare the new fields: see **[Migrating from vens v0.6](reference/config-schema.md#migrating)**.

The same applies to `schema_version 1 is not supported`. `schema_version must be the integer 2, got ...` means the marker is there but written as something else, such as `"2"` (a string) or `2.0`: write `schema_version: 2`. `schema_version 3 is not supported` means the file was written for a newer vens.

---

## `unknown key` in `config.yaml`

```text
config.yaml line 10: unknown key `tracability` under context
```

A key schema 2 does not have, usually a typo. vens v0.6 and earlier ignored it, so a misspelled `compliance_requirement:` silently dropped your frameworks; schema 2 refuses the file and names the line. This one fails:

<!-- docs-check: E3 -->
```yaml
schema_version: 2

project:
  name: "my-service"

context:
  exposure: "private"
  data_sensitivity: "medium"
  business_criticality: "medium"
  tracability: "per_request"
```

Fix the key's spelling (`traceability`). Every key is in the **[config.yaml reference](reference/config-schema.md)**.

---

## `context.detection ...` or `context.traceability ...` is refused

The new fields have strict shapes:

- `context.detection has no channels` or `is required once context.detection is present`: once `detection` is written, declare all three channels, `network`, `host` and `application`. To leave detection undeclared, remove the key.
- `context.detection.network: active_in_application applies to application only`: only the `application` channel takes `active_in_application`.
- `must be a single value`: `listener`, `data_subjects`, `traceability` and each channel take one value, not a list.
- `has no value`: the key is written with nothing after it. Write a value or remove the key.

<!-- docs-check: E5 -->
```yaml
schema_version: 2

project:
  name: "my-service"

context:
  exposure: "private"
  data_sensitivity: "medium"
  business_criticality: "medium"
  detection:
    network: "logged"
```

Every message is in **[Load errors and warnings](reference/config-schema.md#load-errors)**.

---

## Warnings at load: `... is not declared`

```text
level=WARN msg="context.detection is not declared: every channel counts as not logged, so Intrusion detection is 9 on every finding."
```

The run goes on: vens uses the fallback the warning states and counts each use in the run summary. Declare `detection`, `traceability` and `data_subjects` for what is in place to remove the warning. `audit_requirement` and the `ids`, `siem` and `edr` controls do not stand in for them; the warning says so when they are set. Each warning is in **[Load errors and warnings](reference/config-schema.md#warnings)**.

---

## `strict: ...`

A `--strict` run refused to use a worst-case fallback. It writes no VEX and no attestation, and leaves the files an earlier run wrote as they were. Three causes:

- **`strict: context.data_subjects, context.detection, context.traceability not declared`** — at load, before any LLM call. Declare the fields it names.
- **`strict: N vulnerabilities would fall back to a worst case, so no LLM call is made`** — the scan holds CVEs with no CVSS vector in the scanner's report, a vector that does not parse or lacks an axis metric, or no description. The error lists each CVE and its cause. This comes from the scanner's report, not from your config, and vens cannot fix it: such a scan cannot pass `--strict`. Run without `--strict` and watch the `applicability_missing` counter, or use a scanner database that carries the vectors.
- **`strict: the answer to ... reads as cannot_tell ... stopping the run`** — the model could not decide one question for one CVE, or answered off its list. Read that call's `.response` in `--debug-dir`: the model's reasoning says what was missing, often something `notes` can state.

See **[`--strict`](reference/generate.md#-strict)**.

---

## What the counters in the run summary mean

A run that reaches scoring ends with a `Scoring run finished` line, also when it fails during scoring. Its `counters.*` count, per CVE, each fallback the run used:

- `<factor>_cannot_tell` (such as `privacy_cannot_tell`) — the model answered `cannot_tell`, or off its list, so the question's worst answer applied: the factor's worst level, unless `detection` or `data_subjects` limits it or a flagged CVE's adjustment lowers it. A CVE with no description counts in `motive_cannot_tell`, `opportunity_cannot_tell` and `ease_of_exploit_cannot_tell`.
- `detection_undeclared`, `traceability_missing`, `data_subjects_missing` — a field left out of `config.yaml`. Declare it.
- `applicability_missing` — the CVE's CVSS vectors could not rule out a loss, so the loss was asked instead of floored.

A counter that is high for one question across most CVEs points at missing context: read a few of that question's replies in `--debug-dir`. The full list, with `calls.*` and `defects.*`, is in **[The run summary](reference/generate.md#the-run-summary)**; `answers.json` gives the counters per CVE.

---

## `no LLM backend detected`

No LLM provider environment variable is set. Export one of:

```bash
export OPENAI_API_KEY=sk-...    OPENAI_MODEL=gpt-5.4-mini
export ANTHROPIC_API_KEY=...    ANTHROPIC_MODEL=claude-sonnet-4-6
export GOOGLE_API_KEY=...       GOOGLE_MODEL=gemini-2.5-flash
export OLLAMA_MODEL=llama3.1    # with a local Ollama running
```

Or force a provider explicitly: `--llm ollama`.

---

## `unable to parse LLM output`

A reply to a question was not the JSON its schema asks for: text that is not JSON, JSON cut short, or JSON of another shape. Vens reads such a reply as no answer for the CVEs it should have carried, and skips an answer of it that is not a JSON object, keeping the others. It logs a `WARN` quoting the start of the reply, counts the reply in the run summary under `defects.reply_unreadable`, and asks again for the CVEs left without an answer, once, as for CVEs a reply leaves out. A CVE still without an answer stops the run, no VEX is written, and the error ends with what Vens could not read:

```text
failed to generate risk scores: model returned no answer to Motive (M) for CVE-2024-1234 after asking again; stopping the run: unable to parse LLM output: the reply is not JSON: unexpected end of JSON input: "{\"answers\":[{\"vulnId\":\"CVE-2024-1234\",\"reasoning\":\"The parser"
```

Possible causes:

- **Small / local model with weak JSON compliance.** Vens asks for structured JSON: for each question, one named answer and one sentence of reasoning per CVE. On the scoring of earlier versions, which asked for four component scores per CVE, models under 7B parameters routinely failed on batches of 10. These recommendations for Ollama come from then and have not been rechecked on the v0.7.0 questions:
    - `llama3.1:70b` / `llama3.3:70b` — robust on the default batch size of 10.
    - `llama3.1:8b`, `mistral:7b` — work with `--llm-batch-size 3` to `5`.
    - Anything smaller (`phi3:mini`, `gemma:2b`, …) — expect frequent failures; use only for smoke tests.
- **Prompt truncation on small context windows.** Reduce `--llm-batch-size`.
- **Provider-side safety filter** trimmed the response. Each reply Vens could not read is whole in its `batch-NNNNN.response`, in the run's `vens-debug/run-*/` directory, next to the two prompts that produced it: inspect them and re-run.

---

## My OWASP scores change between two runs with the same config

This can happen. See the ["Reproducibility is best-effort"](reference/generate.md#-llm-seed-int) note in the `vens generate` reference: cloud LLM providers do not guarantee byte-deterministic decoding even at `temperature=0`. The model picks named answers and vens computes the rating in Go, so the same answers always give the same rating; a rating moves only when an answer changes.

What to do:

- If you need strict reproducibility for audit evidence at a fixed point in time, pin a local Ollama model version (model tags are immutable), pass `--llm-temperature 0 --llm-seed <n>`, **and** archive `--debug-dir` output. Together they give you a byte-exact record of what was sent and returned.
- If a specific CVE is jumping across severities between runs, compare the two runs' `answers.json`: it shows which answer changed. That usually means the LLM is genuinely uncertain about that question for that CVE in your context — read the reasoning in that question's `.response`, and state the missing fact in `notes` if you can.

---

## Rate limit errors (OpenAI / Anthropic / Google AI)

Vens already retries up to 10 times with a 10 s sleep on rate-limit errors. If you still hit the ceiling:

- Lower `--llm-batch-size` (default `10`) — more calls, smaller bursts.
- Use a different model tier with higher quotas.
- Run locally with Ollama for bulk scans.

---

## `failed to detect input format`

The input file is neither a Trivy JSON report nor a Grype JSON report. Force the parser explicitly:

```bash
vens generate --input-format trivy ...
# or
vens generate --input-format grype ...
```

If you use a different scanner, export its output to Trivy or Grype JSON first — Vens only supports those two today.

Note: `--input-format` examples in this page omit `--sbom-serial-number` for brevity, but the flag is still required on every `vens generate` call.

---

## `cannot generate VEX: ... (empty BOMRef)`

A row in the scanner report gives Vens nothing to point the VEX at: no usable PURL and no package ID (Trivy also falls back to the package name). Vens stops right after reading the report, before any LLM call, and writes no VEX. The error names CVEs, not rows: in the report, find each CVE's row with no PURL and no package ID, fix or remove it, and run again.

---

## What happens if the LLM fails on one batch?

Vens processes CVEs in batches (default 10, tunable via `--llm-batch-size`), one call per question per batch. Provider errors fail the whole run; a CVE the model leaves out or answers badly is handled CVE by CVE:

- **Rate limit on a call** → Vens retries that call up to 10 times with a 10 s backoff (`pkg/llm`). If all retries fail, the whole `vens generate` run exits with a non-zero status and the output VEX file is not written. This is intentional — a partial VEX would be misleading.
- **Network error / provider outage mid-run** → same behaviour: exit non-zero, no partial VEX.
- **The provider truncates a call** → Vens asks each half of its CVEs on its own, down to a single CVE.
- **The LLM leaves CVEs out of its answer** → Vens asks for them again, together, in one more call. If one is still missing, the run stops there, names the question and the missing CVEs and writes no VEX.
- **The LLM returns a reply that cannot be read** (not JSON, cut short without the provider flagging it, or JSON of another shape) → Vens reads it as no answer for the CVEs it should have carried, keeping any answer of it that is a JSON object, logs a `WARN` quoting the start of the reply and counts it under `defects.reply_unreadable`. Those CVEs are asked again with the ones left out; one still without an answer stops the run as above, and the error ends with `unable to parse LLM output: ...`, quoting the start of the reply. `--debug-dir` keeps each reply whole, beside its prompts, so you can reproduce it or lower the batch size.
- **The LLM answers `cannot_tell`, or off the list** → Vens uses the question's worst answer and counts it in the run summary; under `--strict` the run stops instead.
- **An adjustment reply cannot be read** → the CVE keeps the levels its questions gave; the run summary counts it under `defects`.

For CI pipelines, this means you should either:

- Let the step fail the build on any LLM error (cleanest), or
- Wrap the `vens generate` step in `continue-on-error: true` and gate the downstream step on VEX file existence + non-empty.

---

## "No vulnerabilities found in the report"

Either the scanner returned nothing (great!), or the filter was too strict. Re-scan with a broader severity range:

```bash
trivy image IMAGE --format json --severity LOW,MEDIUM,HIGH,CRITICAL --output report.json
```

---

## All my CVEs cluster in the same score range

Vens **does** score every CVE — that part is not broken. Some sameness is built in: Skill level, Ease of discovery and Awareness are 9 for every finding, and Size follows your `exposure`, so the likelihood never falls below MEDIUM. But if virtually every CVE gets the same severity and close scores, look for what the CVEs share:

1. Check the run summary's counters. A field left out (`detection_undeclared`, `traceability_missing`) gives every finding the same worst case, and a high `*_cannot_tell` counter means the model could not tell that question apart from CVE to CVE.
2. Are the three required fields in `config.yaml` actually representative of the production deployment? (Don't leave `exposure: internal` when it's public-facing.)
3. Did you enable the **real** controls in `context.controls`? Not wishful ones.
4. Did you fill `context.notes` with 2–3 sentences of architecture? Every question shows it.
5. For local models: is your Ollama model large enough? On the scoring of earlier versions, small models sometimes gave flat, uniform scores even when they emitted valid JSON (see [Ollama JSON compliance](#unable-to-parse-llm-output) above). Their answers to the v0.7.0 questions have not been measured, so read them in `--debug-dir`.

See [Describe your system context](guides/configuration.md) for the checklist.

---

## `sbom-serial-number must start with 'urn:uuid:'`

You passed `--sbom-serial-number` but forgot the prefix. The value must look like `urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79`. This flag is **required** — see [`--sbom-serial-number`](reference/generate.md#-sbom-serial-number-urnuuid).

---

## Output VEX has no `analysis.detail` / no reasoning

By design — Vens does not embed the LLM reasoning in the VEX to keep the document strictly CycloneDX-compliant and stable. Pass `--attest` for a sidecar whose claims give, per CVE, one line per question answered, or capture the reasoning separately with `--debug-dir`:

```bash
vens generate \
  --debug-dir ./debug \
  --config-file config.yaml \
  --sbom-serial-number "$SBOM_UUID" \
  report.json vex.json
ls debug/run-*/
# batch-00001.human.prompt  batch-00001.response  batch-00001.system.prompt
# ...
```

Each `batch-NNNNN.response` is the model's raw reply to one question, answers and reasoning included, for the CVEs in the `batch-NNNNN.human.prompt` beside it. `answers.json` gives each CVE's answers and levels without the reasoning. Each CVE's score, severity and vector are also logged to stderr at `INFO`.

---

## Still stuck?

Open an issue with:

- The exact command line
- The redacted `config.yaml`
- The contents of `--debug-dir`
- Your Vens version (`vens --version`)

at [github.com/venslabs/vens/issues](https://github.com/venslabs/vens/issues).
