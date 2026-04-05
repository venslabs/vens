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

- **Small / local model with weak JSON compliance** (e.g. some Ollama models). Try a larger model, or lower `--llm-batch-size` to `3` so the LLM has less to produce per call.
- **Prompt truncation on small context windows.** Reduce `--llm-batch-size`.
- **Provider-side safety filter** trimmed the response. Inspect `vens-debug/system.prompt` and re-run with the batch that failed.

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

## "No vulnerabilities found in the report"

Either the scanner returned nothing (great!), or the filter was too strict. Re-scan with a broader severity range:

```bash
trivy image IMAGE --format json --severity LOW,MEDIUM,HIGH,CRITICAL --output report.json
```

---

## OWASP score looks too generic

If every CVE lands in the same 30–40 range, the LLM didn't have enough context. Re-check:

1. Are the three required fields in `config.yaml` actually representative of the production deployment? (Don't leave `exposure: internal` when it's public-facing.)
2. Did you enable the **real** controls in `context.controls`? Not wishful ones.
3. Did you fill `context.notes` with 2–3 sentences of architecture? The LLM leans on it for tie-breaks.

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
