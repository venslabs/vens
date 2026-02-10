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
        "score": 45.5,
        "severity": "high",
        "method": "OWASP",
        "vector": "SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:3/LC:7/LI:7/LAV:7/LAC:7/FD:7/RD:7/NC:7/PV:7"
      }]
    },
    {
      "id": "CVE-2019-1010023",
      "ratings": [{
        "score": 10.0,
        "severity": "low",
        "method": "OWASP",
        "vector": "SL:3/M:3/O:3/S:3/ED:2/EE:2/A:2/ID:7/LC:4/LI:4/LAV:4/LAC:4/FD:4/RD:4/NC:4/PV:4"
      }]
    }
  ]
}
```

## Understanding OWASP Risk Rating Vectors

Each vulnerability includes a 16-factor risk vector following the [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology):

### Vector Format
`SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:3/LC:7/LI:7/LAV:7/LAC:7/FD:7/RD:7/NC:7/PV:7`

### Factor Categories (all scored 0-9)

**1. Threat Agent Factors** (Likelihood)
- **SL** (Skill Level): Attacker's technical expertise
- **M** (Motive): Incentive to exploit
- **O** (Opportunity): Resources/access required
- **S** (Size): Number of potential attackers

**2. Vulnerability Factors** (Likelihood)
- **ED** (Ease of Discovery): How easy to find
- **EE** (Ease of Exploit): How easy to exploit
- **A** (Awareness): Public knowledge level
- **ID** (Intrusion Detection): Detection likelihood (inverse: 9=undetected)

**3. Technical Impact Factors** (Impact)
- **LC** (Loss of Confidentiality): Data disclosure
- **LI** (Loss of Integrity): Data corruption
- **LAV** (Loss of Availability): Service disruption
- **LAC** (Loss of Accountability): Action traceability

**4. Business Impact Factors** (Impact)
- **FD** (Financial Damage): Monetary loss
- **RD** (Reputation Damage): Brand impact
- **NC** (Non-Compliance): Regulatory violation
- **PV** (Privacy Violation): PII exposure

### Score Calculation
```
Likelihood = avg(Threat Agent + Vulnerability factors)
Impact = avg(Technical + Business Impact factors)
Risk Score = Likelihood × Impact  (0-81 scale)
```

### Real Example: CVE-2026-0915
```
Vector: SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:3/LC:7/LI:7/LAV:7/LAC:7/FD:7/RD:7/NC:7/PV:7

Interpretation:
• Threat Agent: HIGH (7) - Skilled attackers with strong motive
• Vulnerability: HIGH (5.25) - Moderately easy to discover/exploit, detectable
• Technical Impact: HIGH (7) - Full CIA compromise
• Business Impact: HIGH (7) - GDPR violations, PII leakage
• Final Risk: 45.5/81 = HIGH severity
```
