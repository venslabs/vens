[![GitHub Release][release-img]][release]
[![CI][ci-img]][ci]
[![Go Report Card][go-report-img]][go-report]
[![License: Apache-2.0][license-img]][license]
[![GitHub Downloads][github-downloads-img]][release]
[![Documentation][docs-img]][docs]

# vens - Context-Aware Vulnerability Risk Scoring

**Stop treating all vulnerabilities equally.** Vens transforms generic CVSS scores into **contextual OWASP risk scores** tailored to YOUR system using LLM intelligence, and outputs standards-compliant **[CycloneDX VEX](https://www.ntia.gov/files/ntia/publications/vex_one-page_summary.pdf)**.

> 📖 **[Read the full documentation →](https://venslabs.github.io/vens/)**
>
> New to Vens? Start with the [5-minute quickstart](https://venslabs.github.io/vens/getting-started/quickstart/) or learn how to [prioritize a CVE backlog](https://venslabs.github.io/vens/guides/prioritize-cves/).

## Why vens?

Traditional scanners treat all vulnerabilities the same. Vens analyzes each CVE in **your specific context** to calculate real risk:

```
Risk = Likelihood × Impact (0-81 scale)
```

**Illustrative example:**

| Scenario | CVSS (Generic) | OWASP (Contextual) | Why? |
|-----|----------------|-------------------|------|
| Generic RCE in a library whose vulnerable path is not executed | 8.8 HIGH | **10.0 LOW** ⬇️ | Not reachable in your runtime |
| Info leak in a PII handler running under GDPR | 5.3 MEDIUM | **52.0 HIGH** ⬆️ | PII leak + compliance impact |

*Scores above are illustrative — actual scores depend on your `config.yaml` and the LLM model.*

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
# 1. Set up LLM (OpenAI shown — Anthropic, Google AI, or local Ollama also supported)
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-4o"

# 2. Scan with Trivy or Grype
trivy image python:3.11-slim --format json --output report.json
# or
grype python:3.11-slim --output json --file report.json

# 3. Pin a stable per-service UUID (reuse across runs, do not regenerate each time)
SBOM_UUID="urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')"

# 4. Generate contextual risk scores
vens generate --config-file config.yaml --sbom-serial-number "$SBOM_UUID" report.json output.vex.json

# 5. Optionally fold the OWASP ratings back into the Trivy report
vens enrich --vex output.vex.json report.json
```

Output is a [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/) document; each vulnerability carries an OWASP rating:

```json
{
  "vulnerabilities": [{
    "id": "CVE-XXXX-YYYY",
    "source": { "name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-XXXX-YYYY" },
    "ratings": [{
      "method": "OWASP",
      "score": 52.0,
      "severity": "high",
      "vector": "SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:3/LC:7/LI:7/LAV:7/LAC:7/FD:7/RD:7/NC:7/PV:7"
    }]
  }]
}
```

The per-CVE reasoning from the LLM is logged to stderr as the command runs, and is captured alongside prompts/responses when you pass `--debug-dir <path>`. It is intentionally not embedded in the VEX file to keep the document strictly CycloneDX-compliant.

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

**Supported scanners:**
- ✅ **Trivy** - Auto-detected from JSON report format
- ✅ **Grype** - Auto-detected from JSON report format

**Key flags:**
- `--config-file` (required) - Path to config.yaml
- `--input-format` - Scanner format: `auto` | `trivy` | `grype` (default: `auto`)
- `--llm` - LLM provider: `openai` | `anthropic` | `ollama` | `googleai` (default: `auto`)
- `--llm-batch-size` - CVEs per request (default: `10`)
- `--debug-dir` - Save prompts/responses for debugging

### `vens enrich`

Apply VEX scores to your Trivy report:

```bash
vens enrich --vex output.vex.json report.json
```

---

## Learn More

- **[📖 Full Documentation](https://venslabs.github.io/vens/)** — installation, guides, reference
- **[5-minute Quickstart](https://venslabs.github.io/vens/getting-started/quickstart/)** — your first VEX
- **[Prioritize a CVE backlog](https://venslabs.github.io/vens/guides/prioritize-cves/)** — the common use case
- **[CVSS vs OWASP contextual](https://venslabs.github.io/vens/concepts/cvss-vs-owasp/)** — why the scores move
- [Complete Example](examples/quickstart/) - 107 real CVEs comparison
- [Trivy Plugin Guide](docs/TRIVY_PLUGIN.md) - Plugin usage

## Contributing

Contributions are welcome. See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the full contributor guide: development setup, coding standards, testing with the mock LLM, commit conventions, and the review process.

Quick start for contributors:

- **Good first issue?** Look for the [`good first issue`](https://github.com/venslabs/vens/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label.
- **Bug report?** Open an issue with the exact command, your `vens --version`, and (if possible) redacted `--debug-dir` output.
- **Bigger change?** Open an issue first so we can agree on scope before you write the code.
- **Security report?** See [SECURITY.md](SECURITY.md) — please do not open public issues for vulnerabilities.

## License

Apache License 2.0 - See [LICENSE](LICENSE)

---

**Focus on what matters. Patch smarter, not harder.**

[docs-img]: https://img.shields.io/badge/docs-venslabs.github.io%2Fvens-blue?logo=readthedocs&logoColor=white
[docs]: https://venslabs.github.io/vens/
[release-img]: https://img.shields.io/github/release/venslabs/vens.svg?logo=github
[release]: https://github.com/venslabs/vens/releases
[ci-img]: https://github.com/venslabs/vens/actions/workflows/main.yml/badge.svg
[ci]: https://github.com/venslabs/vens/actions/workflows/main.yml
[go-report-img]: https://goreportcard.com/badge/github.com/venslabs/vens
[go-report]: https://goreportcard.com/report/github.com/venslabs/vens
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[license]: https://github.com/venslabs/vens/blob/main/LICENSE
[github-downloads-img]: https://img.shields.io/github/downloads/venslabs/vens/total?logo=github
