# Quickstart Example

This directory contains a **real-world example** demonstrating how **vens** prioritizes vulnerabilities based on business context using OWASP Risk Rating Methodology.

## Overview

In this example, we scan a **production NGINX container image** and use LLM to calculate OWASP risk scores for each vulnerability based on your project context.

| Image | Role | Description |
|-------|------|-------------|
| `nginx:1.25` | Public-facing web server | Internet-exposed, high attack surface |

**The key insight**: vens uses LLM to analyze each CVE and calculate its OWASP risk score based on the context hints you provide (exposure, data sensitivity, business criticality).

## Directory Structure

```
quickstart/
├── config.yaml          # Context hints for OWASP risk calculation
├── reports/             # Trivy vulnerability reports
│   └── nginx.trivy.json
└── output_vex.cdx.json  # Generated VEX with risk scores
```

## How It Works

1. **Vulnerability Report** (`reports/`): Trivy scan identifies CVEs in the image
2. **Context Configuration** (`config.yaml`): You define simple context hints for your project
3. **LLM Analysis**: vens uses LLM to calculate OWASP risk scores based on your context
4. **Risk Score**: Final score computed using OWASP Risk Rating formula (0-81)

## Configuration (`config.yaml`)

```yaml
project:
  name: "nginx-production"
  description: "Production NGINX web server exposed to internet"

context:
  exposure: "internet"              # internal | private | internet
  data_sensitivity: "high"          # low | medium | high | critical
  business_criticality: "critical"  # low | medium | high | critical
  notes: "Handles customer PII, PCI-DSS compliance required"
```

### Context Values

| Field | Value | Description |
|-------|-------|-------------|
| **exposure** | `internal` | Corporate network only |
| | `private` | Requires VPN/authentication |
| | `internet` | Publicly accessible |
| **data_sensitivity** | `low` | Public data |
| | `medium` | Internal data |
| | `high` | PII, financial data |
| | `critical` | Secrets, credentials, PHI |
| **business_criticality** | `low` | Dev/test environments |
| | `medium` | Internal tools |
| | `high` | Customer-facing services |
| | `critical` | Revenue-critical, compliance |

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

For each vulnerability, the LLM calculates the OWASP risk score based on your context:

```
CVE-2024-1234 in OpenSSL (RCE):
├── Context: internet-exposed, high data sensitivity, critical business
├── Threat Agent: 8/9 (public exploits, APT target)
├── Vulnerability: 7/9 (easy to exploit, POC available)
├── Technical Impact: 8/9 (RCE, data compromise)
├── Business Impact: 9/9 (revenue-critical, compliance)
└── OWASP Score: 63.75/81 → CRITICAL

Score Calculation:
  Likelihood = (8 + 7) / 2 = 7.5
  Impact = (8 + 9) / 2 = 8.5
  Risk = 7.5 × 8.5 = 63.75
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
          "score": 63.75,
          "severity": "critical",
          "method": "OWASP"
        }
      ]
    },
    {
      "id": "CVE-2024-5678",
      "ratings": [
        {
          "score": 12.25,
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
- Your project context (exposure, data sensitivity, business criticality)
- The LLM's analysis of the vulnerability type and affected package

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

1. **Simple configuration**: Just 3 required fields (exposure, data_sensitivity, business_criticality)
2. **Context matters**: LLM evaluates each CVE based on your project's specific context
3. **OWASP methodology**: Industry-standard risk rating for consistent prioritization
4. **Actionable output**: CycloneDX VEX format integrates with security platforms
