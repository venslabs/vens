# Quickstart — your first VEX in 5 minutes

**Who this is for:** anyone who just installed Vens and wants to see it work.
**By the end of this page:** you have a real CycloneDX VEX file scored with OWASP risk ratings.

We will scan `python:3.11-slim`, generate a VEX, and read the result.

---

## Prerequisites

- `vens` installed — see [Installation](installation.md)
- `trivy` installed — [trivy.dev](https://trivy.dev)
- An LLM provider configured (e.g. `OPENAI_API_KEY` exported)

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
project:
  name: "my-python-api"
  description: "Customer-facing Python API handling user data"

context:
  exposure: "internet"          # internal | private | internet
  data_sensitivity: "high"      # low | medium | high | critical
  business_criticality: "high"  # low | medium | high | critical
  compliance_requirements:
    - "GDPR"
  controls:
    waf: true
```

This is the step that makes scores meaningful. A dev/test environment would use different values and get _different_ scores. See [Describe your context](../guides/configuration.md) for the full field reference.

---

## Step 3 — Generate the VEX

```bash
vens generate \
  --config-file config.yaml \
  report.json \
  output.vex.json
```

You will see progress logs as Vens batches CVEs to the LLM:

```
INFO Config loaded project=my-python-api exposure=internet ...
INFO Processing vulnerabilities count=47
INFO Scored vulnerability vuln=CVE-... score=52.0 severity=high ...
```

Typical runtime: **30 seconds to 2 minutes** depending on CVE count and LLM provider.

!!! tip "Reproducibility"
    Pass `--sbom-serial-number urn:uuid:<your-uuid>` if you need a stable BOM-Link across runs (for example when linking the VEX back to a specific SBOM in CI). Without it, Vens generates a fresh UUID each run.

---

## Step 4 — Read the result

Open `output.vex.json`. It is a CycloneDX 1.6 BOM. Each vulnerability carries an OWASP rating:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "vulnerabilities": [
    {
      "id": "CVE-2026-0915",
      "source": { "name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0915" },
      "ratings": [
        {
          "method": "OWASP",
          "score": 52.0,
          "severity": "high",
          "vector": "SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:3/LC:7/LI:7/LAV:7/LAC:7/FD:7/RD:7/NC:7/PV:7"
        }
      ],
      "affects": [{ "ref": "urn:cdx:.../1#pkg:..." }]
    }
  ]
}
```

**The three things to look at:**

1. `ratings[0].score` — the OWASP score (0–81)
2. `ratings[0].severity` — bucket: `info` / `low` / `medium` / `high` / `critical`
3. `ratings[0].vector` — the full 16-factor OWASP Risk Rating vector

!!! note "Reasoning"
    Vens logs the LLM's per-CVE reasoning to stderr as it scores (and to `--debug-dir` if you set it). The reasoning is not written into the VEX file itself — the VEX stays strictly CycloneDX-compliant. See [`vens generate --debug-dir`](../reference/generate.md#--debug-dir-path) to capture every prompt and response for auditing.

---

## Step 5 — Sort by real risk

Get your top 10 most critical CVEs with `jq`:

```bash
jq '[.vulnerabilities[] | {id, score: .ratings[0].score, severity: .ratings[0].severity}] | sort_by(-.score) | .[0:10]' output.vex.json
```

You now have a prioritized backlog where the top items are the ones that _actually_ threaten your system.

---

## What just happened

1. Trivy found every known CVE in the image.
2. You described _your_ system in 15 lines of YAML.
3. Vens sent each CVE to an LLM along with your context and asked for an OWASP Risk Rating.
4. You got a VEX file where a generic CVSS 8.8 may become a contextual OWASP 10 (low) — or a generic CVSS 5.3 may become an OWASP 52 (high).

---

## Next steps

- **[Prioritize a CVE backlog](../guides/prioritize-cves.md)** — the common use case, end to end.
- **[Describe your context](../guides/configuration.md)** — make scores more accurate.
- **[CVSS vs OWASP contextual](../concepts/cvss-vs-owasp.md)** — understand why the scores move.
- **[Troubleshooting](../troubleshooting.md)** — when things don't go as expected.
