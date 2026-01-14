<p align="center">
  <img src="vens-logo.png" alt="vens logo">
</p>


**Vens** is an intelligent vulnerability prioritization tool. It leverages the power of LLMs to analyze your security reports and SBOMs, generating precise and actionable VEX ([Vulnerability Exploitability eXchange](https://www.ntia.gov/files/ntia/publications/vex_one-page_summary.pdf)) documents.

No more endless lists of CVEs without context. **vens** helps you focus on what truly matters.

## ✨ Key Features

- 🧠 **LLM-Powered Prioritization**: Intelligent contextual analysis of exploitability.
- 📦 **SBOM Support**: Integrates your CycloneDX files for enhanced accuracy.
- 🚀 **Trivy Integration**: Instantly transforms your Trivy scans into VEX reports.
- 🎯 **Custom Risk Scoring**: Configure your own impact and probability criteria.

## 🌐 Vision & Impact

**Vens** is at the forefront of vulnerability management innovation. 

- **First-of-its-kind Open Source**: We are pioneering the use of LLMs to generate prioritized VEX reports, filling a gap in the open-source ecosystem by providing actionable intelligence for platforms like [Dependency-Track](https://dependencytrack.org/).
- **Pushing the Standards**: We don't just use CycloneDX; we help shape it. We are actively advocating for the CycloneDX specification to better support risk-based prioritization, ensuring that ratings and risk scores are integrated into the heart of security platforms.
  - 🔗 Check out our contribution: [CycloneDX Specification PR #722](https://github.com/CycloneDX/specification/pull/722)

## 🚀 Quick Start

### Installation

Option 1: As a standalone program:
```bash
go install github.com/venslabs/vens/cmd/vens@latest
```

Option 2: As a Trivy [plugin](https://aquasecurity.github.io/trivy/latest/docs/plugin/) (see [TRIVY_PLUGIN.md](docs/TRIVY_PLUGIN.md) for details):
```bash
trivy plugin install github.com/venslabs/vens
alias vens="trivy vens"
```

### Usage

Run the following command to generate a VEX report using the quickstart files. For a detailed explanation and a complete working example, please refer to the [Quickstart Guide](examples/quickstart).

```bash
export OPENAI_API_KEY="your-key"

vens generate \
  --config-file examples/quickstart/config.yaml \
  --sboms examples/quickstart/sbom.cdx.json \
  --llm openai \
  examples/quickstart/trivy.json \
  output_vex.json
```

## ⚙️ Configuration

### Risk Context
**vens** uses a `config.yaml` file to define your custom risk context based on OWASP risk ratings.

> [!IMPORTANT]
> **vens** uses the component SBOM to match component-specific risk scores to vulnerabilities. Ensure that every component defined in your `config.yaml` has a corresponding SBOM. Refer to the [Quickstart example](examples/quickstart) for further clarification.

```yaml
owasp:
  # Use version-less PURLs as keys
  pkg:golang/github.com/acme/lib:
    likelihood: 7  # 0 to 9 (OWASP native scale)
    impact: 9      # 0 to 9 (OWASP native scale)
  
  pkg:npm/react:
    score: 45      # 0 to 81 (likelihood * impact)
```

- **likelihood**: Probability of the vulnerability being exploited in your specific environment.
- **impact**: Potential damage if the vulnerability is exploited.
- **score**: Direct OWASP risk score (calculated as `likelihood * impact` if not provided).

### LLM Backends
**vens** supports multiple LLM providers. Configure them using environment variables:

| Backend | Flag `--llm` | Environment Variables |
|---------|--------------|-----------------------|
| **OpenAI** (default) | `openai` | `OPENAI_API_KEY` |
| **Ollama** | `ollama` | `OLLAMA_MODEL` (e.g., `llama3`), `OLLAMA_BASE_URL` (optional) |
| **Anthropic** | `anthropic` | `ANTHROPIC_API_KEY` |
| **Google AI** | `googleai` | `GOOGLE_API_KEY`, `GOOGLE_MODEL` (optional) |

**Example for Ollama:**
```bash
export OLLAMA_MODEL="llama3"
vens generate --llm ollama ...
```

## 💻 Command Reference

### `vens generate`

Generate a VEX report by analyzing security scans and SBOMs.

**Usage:**
```bash
vens generate [flags] INPUT OUTPUT
```

**Flags:**
| Flag | Description | Default |
|------|-------------|---------|
| `--config-file` | **(Required)** Path to `config.yaml` | |
| `--sboms` | **(Required)** Comma-separated list of CycloneDX SBOMs (assets) | |
| `--llm` | LLM backend (`openai`, `ollama`) | `auto` |
| `--llm-temperature` | Sampling temperature | `0.0` |
| `--llm-batch-size` | Number of CVEs to process per request | `10` |
| `--llm-seed` | Seed for reproducible results | `0` |
| `--input-format` | Input format (`auto`, `trivy`) | `auto` |
| `--output-format` | Output format (`auto`, `cyclonedxvex`) | `auto` |
| `--debug` | Enable debug logging | `false` |

### `vens enrich`

Enrich a Trivy vulnerability report with OWASP scores from a VEX document.

**Usage:**
```bash
vens enrich --vex VEX_FILE [flags] REPORT_FILE
```

**Flags:**
| Flag | Description | Default |
|------|-------------|---------|
| `--vex` | **(Required)** Path to the VEX file (CycloneDX) | |
| `--output` | Output file path (if not specified, prints to stdout) | |
| `--debug` | Enable debug logging | `false` |

## 📖 Documentation

- [System Design](docs/system-design/system-design.md): Understand how vens works under the hood.
- [Input Processing](docs/inputs/input-processing.md): Supported formats and data flow.
- [Testing Strategy](docs/testing.md): How we ensure the tool's reliability.

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---
Made with ❤️ for smarter security.
