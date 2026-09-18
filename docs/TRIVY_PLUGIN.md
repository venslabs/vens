# Vens as a Trivy Plugin

Use vens as a [Trivy plugin](https://trivy.dev/docs/latest/plugin/) to prioritize vulnerabilities by real risk, not just CVSS.

## Installation

```bash
trivy plugin install github.com/venslabs/vens
```

## Quick Start

```bash
# 1. Set up LLM
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-5.4-mini"

# 2. Scan with Trivy
trivy image nginx:1.25 --format json --severity HIGH,CRITICAL > report.json

# 3. Generate VEX with contextual OWASP scores
SBOM_UUID="urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')"
trivy vens generate --config-file config.yaml --sbom-serial-number "$SBOM_UUID" report.json output.vex.json
```

**Each vulnerability carries an OWASP rating:**

```json
{
  "vulnerabilities": [{
    "id": "CVE-XXXX-YYYY",
    "ratings": [{
      "method": "OWASP",
      "score": 10.0,
      "severity": "low",
      "vector": "SL:3/M:3/O:3/S:3/ED:2/EE:2/A:2/ID:7/LC:4/LI:4/LAV:4/LAC:4/FD:4/RD:4/NC:4/PV:4"
    }]
  }]
}
```

*Score and vector are illustrative; actual values depend on your `config.yaml` and the model.*

## Enrich Reports

Add OWASP scores to your Trivy reports:

```bash
# Generate VEX
trivy vens generate --config-file config.yaml --sbom-serial-number "$SBOM_UUID" report.json vex.json

# Enrich report
trivy vens enrich --vex vex.json --output enriched-report.json report.json
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

`--llm` defaults to `auto`, and `auto` means OpenAI. Nothing is detected from your environment, so pass the flag for any other provider.

| Provider | Flag | Credentials | Model variable |
|----------|------|-------------|----------------|
| OpenAI | `--llm openai` (default) | `OPENAI_API_KEY` | `OPENAI_MODEL`, default `gpt-5.4-mini` |
| Anthropic | `--llm anthropic` | `ANTHROPIC_API_KEY` | `ANTHROPIC_MODEL`, default `claude-sonnet-4-6` |
| Google AI | `--llm googleai` | `GOOGLE_API_KEY` or `GEMINI_API_KEY` | `GOOGLE_MODEL`, default `gemini-2.5-flash` |
| Ollama (local) | `--llm ollama` | none | `OLLAMA_MODEL`, required, no default |

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
trivy vens generate --llm anthropic --config-file config.yaml --sbom-serial-number "$SBOM_UUID" report.json output.json
```

Drop the flag and the Anthropic key above is ignored: vens calls OpenAI with the key from the Quick Start, and you pay for that run. If no `OPENAI_API_KEY` is exported, it stops instead with `openai: OPENAI_API_KEY is not set`.

## Commands

### `trivy vens generate`

Generate VEX with OWASP scores:

```bash
trivy vens generate --config-file CONFIG --sbom-serial-number urn:uuid:<uuid> INPUT OUTPUT
```

**Key flags:**
- `--config-file` (required) - Path to config.yaml
- `--sbom-serial-number` (required) - serialNumber of the CycloneDX SBOM paired with this scan, in `urn:uuid:<uuid>` form. Get it with `jq -r .serialNumber sbom.cdx.json`.
- `--llm` - LLM provider: `openai` | `anthropic` | `ollama` | `googleai`
- `--llm-batch-size` - CVEs per request (default: `10`)

### `trivy vens enrich`

Enrich Trivy report with OWASP scores:

```bash
trivy vens enrich --vex VEX_FILE REPORT_FILE
```

---

**See [Main Documentation](../README.md) for more details.**
