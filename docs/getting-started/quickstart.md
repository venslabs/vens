# Quickstart — your first VEX in 5 minutes

**Who this is for:** anyone who just installed Vens and wants to see it work.
**By the end of this page:** you have a real CycloneDX VEX file scored with OWASP risk ratings.

We will scan `python:3.11-slim`, generate a VEX, and read the result.

---

## Prerequisites

- `vens` installed — see [Installation](installation.md)
- `trivy` (or `grype`) installed — [trivy.dev](https://trivy.dev) / [grype](https://github.com/anchore/grype)
- An LLM provider configured — **one** of:
    - `OPENAI_API_KEY` + `OPENAI_MODEL` (cloud, recommended for getting started)
    - `ANTHROPIC_API_KEY` + `ANTHROPIC_MODEL`
    - `GOOGLE_API_KEY` + `GOOGLE_MODEL`
    - `OLLAMA_MODEL` (local, no cloud credentials, zero cost — see the Ollama tab on the install page)

---

## Step 1 — Scan an image with Trivy

```bash
trivy image python:3.11-slim \
  --format json \
  --severity HIGH,CRITICAL \
  --output report.json
```

You now have a `report.json` with ~30–80 CVEs.

!!! note
    Vens also accepts Grype reports:
    ```bash
    grype python:3.11-slim -o json > report.json
    ```
    Vens auto-detects the format.

---

## Step 2 — Describe your system

Create `config.yaml`:

```yaml
schema_version: 2

project:
  name: "my-python-api"
  description: "Customer-facing Python API handling user data"

context:
  exposure: "internet"          # internal | private | internet
  data_sensitivity: "high"      # low | medium | high | critical
  business_criticality: "high"  # low | medium | high | critical
  compliance_requirements:
    - "GDPR"
  listener: "present"           # present | absent | unknown
  data_subjects: "thousands"    # none | one_individual | hundreds | thousands | millions
  detection:                    # not_logged | logged | logged_and_reviewed
    network: "logged"
    host: "not_logged"
    application: "logged"
  traceability: "per_request"   # none | per_request | per_individual
  controls:
    waf: true
```

This is the step the ratings depend on. A dev/test environment would use different values and get _different_ scores. Replace the values with what is true for your service today: `listener` says whether it accepts connections, `data_subjects` how many people's personal data it can read, `detection` what records an attack attempt, and `traceability` whether requests are recorded, and by whom. Leave out one of the last three and vens warns at load and uses its fallback, which the warning states. See [Describe your context](../guides/configuration.md) for the full field reference.

Don't want to write this by hand? `vens init` asks a few questions and writes the file for you — see [`vens init`](../reference/init.md).

---

## Step 3 — Generate the VEX

`--sbom-serial-number` is the `serialNumber` of the CycloneDX SBOM paired with this scan — Vens uses it to build BOM-Link references back to that SBOM. Extract it from the SBOM (`jq -r .serialNumber sbom.cdx.json`), or for this quickstart generate an ad-hoc one:

```bash
# Linux / macOS
SBOM_UUID="urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')"
```

Then run:

```bash
vens generate \
  --config-file config.yaml \
  --sbom-serial-number "$SBOM_UUID" \
  report.json \
  output.vex.json
```

You will see progress logs as Vens asks the LLM its questions, batch by batch. With this config and the Trivy report in `examples/quickstart/reports/`:

```
INFO Config loaded schema_version=2 project=my-python-api exposure=internet ... undeclared=""
INFO Processing vulnerabilities count=107
INFO Scored vulnerability vuln=CVE-... score=43.3125 severity=high vector=SL:9/M:4/O:9/S:9/...
...
INFO Scoring run finished rows=107 cves=45 llm_calls=67 asked_again=0 splits=0 calls.R=5 calls.M=5 ... calls.adjustment=2 ... failed=false
```

Your own scan gives other counts, and your model's answers set the scores. Each batch of up to 10 CVEs makes one call per question, so runtime grows with the number of distinct CVEs and depends on the LLM provider. The last line counts the calls and any fallback the run used: see [The run summary](../reference/generate.md#the-run-summary).

!!! tip "Pin the UUID per service, not per run"
    For ad-hoc exploration it is fine to generate a fresh UUID on every run. In CI or for any service you will rescan regularly, **pin a single UUID per service** (as a repo/environment variable) and reuse it forever. BOM-Link references stay stable across scans, which is what downstream tools (Trivy, Dependency-Track, custom dashboards) expect when correlating VEX documents back to the same service over time.

---

## Step 4 — Read the result

Open `output.vex.json`. It is a CycloneDX 1.6 BOM (1.6 is the default; pass `--cyclonedx-spec-version 1.7` if your consumer supports it). Each vulnerability carries an OWASP rating:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "vulnerabilities": [
    {
      "id": "CVE-XXXX-YYYY",
      "source": { "name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-XXXX-YYYY" },
      "ratings": [
        {
          "method": "OWASP",
          "score": 43.3125,
          "severity": "high",
          "vector": "SL:9/M:4/O:9/S:9/ED:9/EE:9/A:9/ID:8/LC:2/LI:9/LAV:1/LAC:9/FD:3/RD:5/NC:7/PV:3"
        }
      ],
      "affects": [{ "ref": "urn:cdx:.../1#pkg:..." }]
    }
  ]
}
```

**The three things to look at:**

1. `ratings[0].severity` — `low` / `medium` / `high` / `critical`, from OWASP's matrix of the likelihood and the impact (never `info`: the likelihood is never LOW)
2. `ratings[0].score` — likelihood × impact on a 0–81 scale, a vens number to sort CVEs within a severity
3. `ratings[0].vector` — the 16 OWASP factor levels the severity and the score are computed from; see [How vens rates a CVE](../concepts/cvss-vs-owasp.md#how-vens-rates-a-cve)

!!! note "Reasoning"
    The model's answers and reasoning are not written into the VEX file — the VEX stays strictly CycloneDX-compliant. Pass `--attest` for a sidecar whose claims hold one line per question answered, or `--debug-dir` to capture every prompt and response, with `answers.json`; see [`vens generate --debug-dir`](../reference/generate.md#-debug-dir-path).

---

## Step 5 — Sort by severity, then score

Get your top 10 most critical CVEs with `jq`, by severity first, then by score:

```bash
jq '[.vulnerabilities[] | {id, score: .ratings[0].score, severity: .ratings[0].severity}]
    | sort_by({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[.severity], -.score)
    | .[0:10]' output.vex.json
```

You now have CVEs ranked by vens's computed rating, ready for review.

---

## What just happened

1. Trivy found every known CVE in the image.
2. You described _your_ system in 19 lines of YAML.
3. Vens asked an LLM closed questions about each CVE in your context, one question per call, and computed the 16 OWASP levels, the severity and the score from the answers.
4. You got a VEX file where a generic CVSS 7.5 may become a contextual `low` — or a generic CVSS 5.3 may become a `critical`.

---

## Next steps

- **[Prioritize a CVE backlog](../guides/prioritize-cves.md)** — the main use case, end to end.
- **[Describe your context](../guides/configuration.md)** — what each field changes in the rating.
- **[CVSS vs OWASP contextual](../concepts/cvss-vs-owasp.md)** — understand why the scores move.
- **[Troubleshooting](../troubleshooting.md)** — when things don't go as expected.
