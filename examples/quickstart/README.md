# Quickstart Example

This example demonstrates how **vens** transforms generic CVSS scores into contextual OWASP risk scores for a **Python 3.11 backend API** (107 CVEs).

## Why vens?

**CVSS asks**: "How severe is this vulnerability technically?"
**OWASP asks**: "What's the real risk **for MY system**?"

## Quick Start

```bash
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-4o"

vens generate \
  --config-file config.yaml \
  --llm openai \
  reports/python-slim.trivy.json \
  output_vex.cdx.json
```

**Context**: See `config.yaml` for the risk profile (exposure, data sensitivity, compliance, security controls)

## How It Works

```
Trivy Scan → 107 CVEs with CVSS scores
     ↓
vens + LLM → Analyzes each CVE with your context
     ↓
OWASP Scores → Risk = Likelihood × Impact
     ↓
Prioritized List → Fix what matters for YOU
```

## Value Comparison: Before vs After

### Before (CVSS only)
```
107 CVEs → Sort by CVSS score → Patch top 20
❌ Waste time on CVE-2019-1010023 (CVSS 8.8, not exploitable)
❌ Miss CVE-2026-0915 (CVSS 5.3, but leaks PII under GDPR)
```

### After (OWASP contextual)
```
107 CVEs → Sort by OWASP score → Patch real risks
✅ Skip CVE-2019-1010023 (OWASP 10/81 - not applicable)
✅ Prioritize CVE-2026-0915 (OWASP 52/81 - GDPR risk)
```

## Output Example

`output_vex.cdx.json` contains CycloneDX VEX with OWASP scores:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2026-0915",
      "ratings": [{
        "score": 52.0,
        "severity": "high",
        "method": "OWASP"
      }]
    }
  ]
}
```
