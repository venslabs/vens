# Vens as a Trivy Plugin

Vens can be used as a Trivy plugin to prioritize CVEs based on risk using OWASP Risk Rating Methodology.

## Installation

Install vens as a Trivy plugin:

```bash
trivy plugin install github.com/venslabs/vens
```

## Usage

Once installed, you can use vens commands directly through Trivy:

### 1. Generate VEX with LLM

Generate a VEX document from a Trivy scan report using LLM to calculate OWASP risk scores:

```bash
# Set up your LLM API key
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-4o-mini"

# Scan an image with Trivy
trivy image nginx:1.25 --format=json --severity HIGH,CRITICAL > report.json

# Generate VEX with OWASP risk scores using vens as a Trivy plugin
trivy vens generate --config-file config.yaml --llm openai report.json output.cdx.json
```

### 2. Enrich Reports with VEX

Enrich a Trivy vulnerability report with ratings and scores from a VEX document:

```bash
# Scan an image with Trivy
trivy image nginx:1.25 --format=json --severity HIGH,CRITICAL > report.json

# Generate VEX with OWASP risk scores
trivy vens generate --config-file config.yaml --llm openai report.json vex.cdx.json

# Enrich the report with VEX ratings
trivy vens enrich --vex vex.cdx.json report.json

# Or save to a file
trivy vens enrich --vex vex.cdx.json --output enriched-report.json report.json
```

## Configuration

Create a `config.yaml` file with your project's context hints:

```yaml
project:
  name: "my-project"
  description: "Production web application"

context:
  # How is the system exposed?
  # Values: internal | private | internet
  exposure: "internet"

  # What type of data is handled?
  # Values: low | medium | high | critical
  data_sensitivity: "high"

  # How critical is the system?
  # Values: low | medium | high | critical
  business_criticality: "critical"

  # Additional context (optional)
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

## LLM Backends

Vens supports multiple LLM providers:

| Backend | Environment Variables |
|---------|-----------------------|
| OpenAI | `OPENAI_API_KEY`, `OPENAI_MODEL` |
| Ollama | `OLLAMA_MODEL`, `OLLAMA_BASE_URL` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Google AI | `GOOGLE_API_KEY`, `GOOGLE_MODEL` |

Example with Ollama:

```bash
export OLLAMA_MODEL="llama3"
trivy vens generate --config-file config.yaml --llm ollama report.json output.cdx.json
```
