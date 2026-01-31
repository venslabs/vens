# Vens as a Trivy Plugin

Use vens as a [Trivy plugin](https://trivy.dev/docs/latest/plugin/) to transform generic CVSS scores into contextual OWASP risk scores.

## Installation

```bash
trivy plugin install github.com/venslabs/vens
```

## Quick Start

```bash
# 1. Set up LLM
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-4o-mini"

# 2. Scan with Trivy
trivy image nginx:1.25 --format json --severity HIGH,CRITICAL > report.json

# 3. Generate VEX with contextual OWASP scores
trivy vens generate --config-file config.yaml report.json output.vex.json
```

**Output example:**

```json
{
  "vulnerabilities": [{
    "id": "CVE-2019-1010023",
    "ratings": [{
      "method": "OWASP",
      "score": 10.0,
      "severity": "low"
    }],
    "analysis": {
      "detail": "Low risk: Not applicable to runtime environment"
    }
  }]
}
```

## Enrich Reports

Add OWASP scores to your Trivy reports:

```bash
# Generate VEX
trivy vens generate --config-file config.yaml report.json vex.json

# Enrich report
trivy vens enrich --vex vex.json report.json > enriched-report.json
```

## Configuration

Create `config.yaml`:

```yaml
project:
  name: "my-api"
  description: "Production web application"

context:
  exposure: "internet"              # internal | private | internet
  data_sensitivity: "high"          # low | medium | high | critical
  business_criticality: "critical"  # low | medium | high | critical
  compliance_requirements: ["PCI-DSS", "SOC2"]
  controls:
    waf: true
    ids: true
```

## LLM Providers

| Provider | Environment Variable | Example |
|----------|---------------------|---------|
| OpenAI (recommended) | `OPENAI_API_KEY` | `export OPENAI_MODEL="gpt-4o-mini"` |
| Anthropic | `ANTHROPIC_API_KEY` | `export ANTHROPIC_MODEL="claude-3-5-sonnet-20241022"` |
| Ollama (local) | `OLLAMA_MODEL` | `export OLLAMA_MODEL="llama3"` |
| Google AI | `GOOGLE_API_KEY` | `export GOOGLE_MODEL="gemini-pro"` |

**Using Ollama:**

```bash
export OLLAMA_MODEL="llama3"
trivy vens generate --config-file config.yaml --llm ollama report.json output.json
```

## Commands

### `trivy vens generate`

Generate VEX with OWASP scores:

```bash
trivy vens generate --config-file config.yaml INPUT OUTPUT
```

**Key flags:**
- `--config-file` (required) - Path to config.yaml
- `--llm` - LLM provider: `openai` | `anthropic` | `ollama` | `googleai`
- `--llm-batch-size` - CVEs per request (default: `10`)

### `trivy vens enrich`

Enrich Trivy report with OWASP scores:

```bash
trivy vens enrich --vex VEX_FILE REPORT_FILE
```

---

**See [Main Documentation](../README.md) for more details.**
