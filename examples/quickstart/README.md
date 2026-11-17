# Quickstart Example

This example demonstrates how **vens** transforms generic CVSS scores into contextual OWASP risk scores for a **Python 3.11 backend API** (107 Trivy findings over 45 vulnerability ids).

## Why vens?

**CVSS asks**: "How severe is this vulnerability technically?"
**OWASP asks**: "What's the risk **for MY system**?"

## Quick Start

```bash
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-5.4-mini"

# Pin one serial per service; a fresh UUID is fine for this example
SBOM_UUID="urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')"

# Using Trivy report (auto-detected)
vens generate \
  --config-file config.yaml \
  --llm openai \
  --sbom-serial-number "$SBOM_UUID" \
  reports/python-slim.trivy.json \
  output_vex.cdx.json

# Or using Grype report (auto-detected)
vens generate \
  --config-file config.yaml \
  --llm openai \
  --sbom-serial-number "$SBOM_UUID" \
  reports/python-slim.grype.json \
  output_vex.cdx.json
```

**Context**: See `config.yaml` for the risk profile (exposure, data sensitivity, business criticality, whether it accepts connections, how many people's personal data it can read, what records an attack attempt and who did what, compliance, security controls)

**Audit trail**: add `--attest` to the command to also write `output_vex.attestation.cdx.json`, a [CycloneDX attestation](../../docs/reference/generate.md#--attest) recording how each CVE was scored (model, seed, prompt/input/config hashes, raw response) so a run can be audited and reproduced.

## How It Works

```
Trivy/Grype Scan → CVEs with CVSS scores
     ↓
vens + LLM → The LLM answers closed questions about each CVE in your context
     ↓
OWASP rating → vens computes the 16 factor levels, the severity (OWASP's
               likelihood × impact matrix) and a 0-81 score
     ↓
Prioritized List → Sort by severity, then score: the order to review them in
```

**Supported Scanners:**
- ✅ Trivy (auto-detected)
- ✅ Grype (auto-detected)

## Before and after

### Before (CVSS only)
```
107 findings → Sort by CVSS score → Review in that order
CVE-2019-1010023: CVSS 8.8, the same wherever the package runs
CVE-2026-0915: CVSS 5.3, whatever data this service holds
```

### After (OWASP contextual)
```
107 findings → Sort by OWASP severity, then score → Review in that order
CVE-2019-1010023: its likelihood and impact are computed from model answers, CVSS vectors and your declared context
CVE-2026-0915: GDPR and the people whose data it can expose weigh on its impact
```

## Output Example

`output_vex.cdx.json` contains CycloneDX VEX with one OWASP rating per vulnerability. The committed file was generated with vens v0.6.0, whose vectors repeat four numbers over the 16 factors; a run of vens v0.7.0 or later writes vectors of 16 levels, as below (levels illustrative):

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-XXXX-YYYY",
      "ratings": [{
        "score": 43.3125,
        "severity": "high",
        "method": "OWASP",
        "vector": "SL:9/M:4/O:9/S:9/ED:9/EE:9/A:9/ID:8/LC:2/LI:9/LAV:1/LAC:9/FD:3/RD:5/NC:7/PV:3"
      }]
    }
  ]
}
```
