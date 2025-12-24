# 🛡️ vens

**Vens** is an intelligent vulnerability prioritization tool. It leverages the power of LLMs to analyze your security reports and SBOMs, generating precise and actionable VEX (Vulnerability Exploitability eXchange) documents.

No more endless lists of CVEs without context. **vens** helps you focus on what truly matters.

## ✨ Key Features

- 🧠 **LLM-Powered Prioritization**: Intelligent contextual analysis of exploitability.
- 📦 **SBOM Support**: Integrates your CycloneDX files for enhanced accuracy.
- 🚀 **Trivy Integration**: Instantly transforms your Trivy scans into VEX reports.
- 🎯 **Custom Risk Scoring**: Configure your own impact and probability criteria.

## 🚀 Quick Start

### Installation

```bash
go install github.com/fahedouch/vens/cmd/vens@latest
```

### Usage

Generate a VEX report with a single command:

```bash
export OPENAI_API_KEY="your-key"

vens generate \
  --config-file examples/mvp/config.yaml \
  --sboms examples/mvp/sbom.cdx.json \
  --llm openai \
  examples/mvp/trivy.json \
  output_vex.json
```

## 📖 Documentation

- [System Design](docs/system-design/system-design.md): Understand how vens works under the hood.
- [Input Processing](docs/inputs/input-processing.md): Supported formats and data flow.
- [Testing Strategy](docs/testing.md): How we ensure the tool's reliability.

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

---
Made with ❤️ for smarter security.
