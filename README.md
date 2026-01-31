# vens - Context-Aware Vulnerability Risk Scoring

**Stop treating all vulnerabilities equally.** Vens transforms generic CVSS scores into **contextual OWASP risk scores** tailored to YOUR system using LLM intelligence.

## Why vens?

Traditional scanners treat all vulnerabilities the same. Vens analyzes each CVE in **your specific context** to calculate real risk:

```
Risk = Likelihood × Impact (0-81 scale)
```

**Real example:**

| CVE | CVSS (Generic) | OWASP (Contextual) | Why? |
|-----|----------------|-------------------|------|
| CVE-2019-1010023 | 8.8 HIGH | **10.0 LOW** ⬇️ | Not exploitable in your runtime |
| CVE-2026-0915 | 5.3 MEDIUM | **52.0 HIGH** ⬆️ | PII leak + GDPR impact |

**Result**: Fix what actually matters in YOUR system.

## Installation

**Standalone:**
```bash
go install github.com/venslabs/vens/cmd/vens@latest
```

**[Trivy Plugin](https://trivy.dev/docs/latest/plugin/):**
```bash
trivy plugin install github.com/venslabs/vens
```

## Quick Example

```bash
# 1. Set up LLM
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-4o"

# 2. Scan with Trivy
trivy image python:3.11-slim --format json --output report.json

# 3. Generate contextual risk scores
vens generate --config-file config.yaml report.json output.vex.json
```

Output of [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/) with OWASP scores:

```json
{
  "vulnerabilities": [{
    "id": "CVE-2026-0915",
    "ratings": [{
      "method": "OWASP",
      "score": 52.0,
      "severity": "high"
    }],
    "analysis": {
      "detail": "High risk: Exposes PII in GDPR-regulated environment"
    }
  }]
}
```

## Configuration

Create `config.yaml`:

```yaml
project:
  name: "my-api"
  description: "Customer-facing REST API"

context:
  exposure: "internet"              # internal | private | internet
  data_sensitivity: "high"          # low | medium | high | critical
  business_criticality: "high"      # low | medium | high | critical
  compliance_requirements: ["GDPR", "SOC2"]
  controls:
    waf: true
```

**LLM Providers:**

| Provider | Environment Variable |
|----------|---------------------|
| OpenAI (recommended) | `OPENAI_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Ollama (local) | `OLLAMA_MODEL` |
| Google AI | `GOOGLE_API_KEY` |

## Command Reference

### `vens generate`

Generate VEX with contextual OWASP scores:

```bash
vens generate --config-file config.yaml INPUT OUTPUT
```

**Key flags:**
- `--config-file` (required) - Path to config.yaml
- `--llm` - LLM provider: `openai` | `anthropic` | `ollama` | `googleai` (default: `auto`)
- `--llm-batch-size` - CVEs per request (default: `10`)
- `--debug-dir` - Save prompts/responses for debugging

### `vens enrich`

Enrich Trivy report with OWASP scores:

```bash
vens enrich --vex output.vex.json report.json
```

---

## Learn More

- [Complete Example](examples/quickstart/) - 107 real CVEs comparison
- [Trivy Plugin Guide](docs/TRIVY_PLUGIN.md) - Plugin usage

## Contributing

Contributions welcome! Open an issue or submit a PR.

## License

Apache License 2.0 - See [LICENSE](LICENSE)

---

**Focus on what matters. Patch smarter, not harder.**
