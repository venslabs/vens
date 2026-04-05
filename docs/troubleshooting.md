# Troubleshooting

**Who this is for:** anyone whose `vens generate` run didn't go the way the quickstart promised.
**By the end of this page:** you know how to diagnose the most common failure modes.

When in doubt, rerun with debug output:

```bash
DEBUG=1 vens generate \
  --debug-dir ./vens-debug \
  --config-file config.yaml \
  --sbom-serial-number "urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')" \
  report.json vex.json
```

`--debug-dir` writes the system prompt and the raw LLM response for every batch to disk. `DEBUG=1` raises the log level to `debug` and shows per-CVE component scores.

---

## `--config-file is required`

You omitted `--config-file`. Vens refuses to run without a [`config.yaml`](reference/config-schema.md) — the whole point is contextual scoring.

```bash
vens generate --config-file config.yaml --sbom-serial-number "$SBOM_UUID" report.json vex.json
```

---

## `sbom-serial-number is required`

`vens generate` needs `--sbom-serial-number` in `urn:uuid:<uuid>` form — it feeds the BOM-Link references in the VEX. Generate one once:

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

## `no LLM backend detected`

No LLM provider environment variable is set. Export one of:

```bash
export OPENAI_API_KEY=sk-...    OPENAI_MODEL=gpt-4o
export ANTHROPIC_API_KEY=...    ANTHROPIC_MODEL=claude-sonnet-4-5
export GOOGLE_API_KEY=...       GOOGLE_MODEL=gemini-2.0-flash
export OLLAMA_MODEL=llama3.1    # with a local Ollama running
```

Or force a provider explicitly: `--llm ollama`.

---

## `unable to parse LLM output`

The LLM returned text that is not valid JSON matching the expected schema. Most common causes:

- **Small / local model with weak JSON compliance.** Vens asks for structured JSON with four component scores per CVE. Models under 7B parameters routinely fail this on batches of 10. Concrete recommendations for Ollama:
    - `llama3.1:70b` / `llama3.3:70b` — robust on the default batch size of 10.
    - `llama3.1:8b`, `mistral:7b` — work with `--llm-batch-size 3` to `5`.
    - Anything smaller (`phi3:mini`, `gemma:2b`, …) — expect frequent failures; use only for smoke tests.
- **Prompt truncation on small context windows.** Reduce `--llm-batch-size`.
- **Provider-side safety filter** trimmed the response. Inspect `vens-debug/system.prompt` and `vens-debug/human.prompt` and re-run the batch that failed.

---

## My OWASP scores change between two runs with the same config

This is expected within a small band. See the ["Reproducibility is best-effort"](reference/generate.md#--llm-seed-int) note in the `vens generate` reference: cloud LLM providers do not guarantee byte-deterministic decoding even at `temperature=0`. Vens mitigates drift by computing the final OWASP score in Go from the LLM's four 0-9 component scores — small component drift is averaged out — but you should expect **±1–3 points of variation on a minority of CVEs** between runs.

What to do:

- If you need strict reproducibility for audit evidence at a fixed point in time, pin a local Ollama model version (model tags are immutable) **and** archive `--debug-dir` output. Together they give you a byte-exact record of what was sent and returned.
- If a specific CVE is jumping across severity buckets between runs, it usually means the LLM is genuinely uncertain about that CVE in your context — check the `--debug-dir` reasoning for that batch.

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

## What happens if the LLM fails on one batch?

Vens processes CVEs in batches (default 10, tunable via `--llm-batch-size`). The failure behaviour is batch-level, not CVE-level:

- **Rate limit on a batch** → Vens retries that batch up to 10 times with a 10 s backoff (`pkg/llm`). If all retries fail, the whole `vens generate` run exits with a non-zero status and the output VEX file is not written. This is intentional — a partial VEX would be misleading.
- **LLM returns malformed JSON that cannot be parsed** → Vens exits with `unable to parse LLM output: ...`. The failing batch is included in the error message; use `--debug-dir` to capture the exact prompt so you can reproduce or downgrade the batch size.
- **Network error / provider outage mid-batch** → same behaviour: exit non-zero, no partial VEX.
- **A single CVE that the LLM cannot score** → the LLM still returns a JSON entry with some component scores; Vens clamps them to `[0, 9]` and proceeds. There is no "skipped" state in the output today. If you see a CVE with four identical component scores that match the default severity bucket of its CVSS, treat it as low-confidence and audit it via `--debug-dir`.

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

Vens **does** score every CVE — that part is not broken. But if virtually every CVE lands in the same narrow band (typically 30–40), it usually means the LLM had nothing specific to differentiate them with and regressed to a generic interpretation of the CVSS severity. A healthy Vens run on a production context produces a wide spread: some CVEs lose 20+ points because a control neutralizes them, others gain 20+ because they hit your data or compliance boundary directly.

Re-check:

1. Are the three required fields in `config.yaml` actually representative of the production deployment? (Don't leave `exposure: internal` when it's public-facing.)
2. Did you enable the **real** controls in `context.controls`? Not wishful ones.
3. Did you fill `context.notes` with 2–3 sentences of architecture? The LLM leans on it for tie-breaks.
4. For local models: is your Ollama model large enough? (See [Ollama JSON compliance](#unable-to-parse-llm-output) above — small models sometimes produce flat, uniform scores even when they emit valid JSON.)

See [Describe your system context](guides/configuration.md) for the checklist.

---

## `sbom-serial-number must start with 'urn:uuid:'`

You passed `--sbom-serial-number` but forgot the prefix. The value must look like `urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79`. Omit the flag entirely if you don't need a stable BOM-Link — Vens will generate a random UUID.

---

## Output VEX has no `analysis.detail` / no reasoning

By design — Vens does not embed the LLM reasoning in the VEX to keep the document strictly CycloneDX-compliant and stable. Capture the reasoning separately with `--debug-dir`:

```bash
vens generate \
  --debug-dir ./debug \
  --config-file config.yaml \
  --sbom-serial-number "$SBOM_UUID" \
  report.json vex.json
ls debug/
# system.prompt  human.prompt
```

Per-CVE component scores and reasoning are also logged to stderr at `INFO` / `DEBUG` level.

---

## Still stuck?

Open an issue with:

- The exact command line
- The redacted `config.yaml`
- The contents of `--debug-dir`
- Your Vens version (`vens --version`)

at [github.com/venslabs/vens/issues](https://github.com/venslabs/vens/issues).
