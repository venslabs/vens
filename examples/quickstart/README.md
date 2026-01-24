# Quickstart Example

This directory contains a **real-world example** demonstrating how **vens** prioritizes vulnerabilities based on business context using OWASP Risk Rating Methodology.

## Overview

In this example, we scan a **production NGINX container image** and use LLM to evaluate each vulnerability's contribution to OWASP risk factors.

| Image | Role | Description |
|-------|------|-------------|
| `nginx:1.25` | Public-facing web server | Internet-exposed, high attack surface |

**The key insight**: vens uses LLM to analyze each CVE and evaluate how much it contributes to your project's risk profile based on the OWASP factors you define.

## Directory Structure

```
quickstart/
├── config.yaml          # OWASP risk factors for your project
├── reports/             # Trivy vulnerability reports
│   └── nginx.trivy.json
└── output_vex.cdx.json  # Generated VEX with risk scores
```

## How It Works

1. **Vulnerability Report** (`reports/`): Trivy scan identifies CVEs in the image
2. **Risk Configuration** (`config.yaml`): You define base OWASP risk factors for your project context
3. **LLM Analysis**: vens uses LLM to evaluate each vulnerability's contribution (0-100%) to each OWASP factor
4. **Risk Score**: Final weighted score computed using OWASP Risk Rating formula

## Configuration (`config.yaml`)

```yaml
project:
  name: "nginx-production"
  description: "Production NGINX web server exposed to internet"

owasp:
  threat_agent: 7      # 0-9: Who might attack?
  vulnerability: 6     # 0-9: How easy to exploit?
  technical_impact: 7  # 0-9: Damage to systems?
  business_impact: 8   # 0-9: Business consequences?
```

## Running the Example

### Option 1: OpenAI

```bash
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-4o-mini"

vens generate \
  --config-file config.yaml \
  --llm openai \
  reports/nginx.trivy.json \
  output_vex.cdx.json
```

### Option 2: Ollama (Local LLM)

```bash
export OLLAMA_MODEL="llama3"

vens generate \
  --config-file config.yaml \
  --llm ollama \
  reports/nginx.trivy.json \
  output_vex.cdx.json
```

## LLM Reasoning Example

For each vulnerability, the LLM evaluates its contribution to OWASP factors:

```
CVE-2024-1234 in OpenSSL (RCE):
├── Threat Agent:      90%  → Widely known, public exploits available
├── Vulnerability:     85%  → POC available, easy to exploit
├── Technical Impact:  95%  → RCE = full system compromise
└── Business Impact:  100%  → Frontend server, critical for business

Final Score Calculation:
  Likelihood = (7 × 0.90 + 6 × 0.85) / 2 = 5.70
  Impact = (7 × 0.95 + 8 × 1.00) / 2 = 7.33
  Risk = 5.70 × 7.33 = 41.78 (CRITICAL)
```

## Example Output

After running vens, `output_vex.cdx.json` contains a CycloneDX VEX document with OWASP risk scores:

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "vulnerabilities": [
    {
      "id": "CVE-2024-1234",
      "ratings": [
        {
          "score": 41.78,
          "severity": "critical",
          "method": "OWASP"
        }
      ]
    },
    {
      "id": "CVE-2024-5678",
      "ratings": [
        {
          "score": 12.5,
          "severity": "low",
          "method": "OWASP"
        }
      ]
    }
  ]
}
```

### Understanding the Output

Each vulnerability receives a contextual OWASP risk score based on:
- The base risk factors you defined in `config.yaml`
- The LLM's evaluation of how much each CVE contributes to those factors

| Severity | Score Range | Action |
|----------|-------------|--------|
| CRITICAL | ≥ 60 | Immediate remediation required |
| HIGH | 40-59 | Prioritize for next sprint |
| MEDIUM | 20-39 | Plan remediation |
| LOW | 5-19 | Monitor |
| NOTE | < 5 | Informational |

## Regenerating the Example

To regenerate the vulnerability report with a newer image version:

```bash
# Generate vulnerability report
trivy image nginx:1.25 --format json --output reports/nginx.trivy.json
```

## Key Takeaways

1. **Context matters**: LLM evaluates each CVE based on your project's specific context
2. **OWASP methodology**: Industry-standard risk rating for consistent prioritization
3. **Actionable output**: CycloneDX VEX format integrates with security platforms
4. **Customizable**: Adjust base OWASP factors to match your risk tolerance
