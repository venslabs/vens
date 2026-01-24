<p align="center">
  <img src="vens-logo.png" alt="vens logo">
</p>


**Vens** is an AI-powered vulnerability risk scorer. It analyzes security reports and evaluates each vulnerability's contribution to **OWASP Risk Rating factors** using LLMs, generating precise **CycloneDX VEX** documents with contextual risk scores.

Stop wasting time on contextless CVE lists. Focus on the risks that actually matter.

## 🌐 Vision & Impact

**Vens** is at the forefront of vulnerability management innovation. 

- **First-of-its-kind Open Source**: We are pioneering the use of LLMs to generate risk-scored VEX reports based on OWASP methodology, filling a gap in the open-source ecosystem by providing actionable intelligence for platforms like [Dependency-Track](https://dependencytrack.org/).
- **Pushing the Standards**: We don't just use CycloneDX; we help shape it. We are actively advocating for the CycloneDX specification to better support risk-based prioritization, ensuring that ratings and risk scores are integrated into the heart of security platforms.
  - 🔗 Check out our contribution: [CycloneDX Specification PR #722](https://github.com/CycloneDX/specification/pull/722)

## 🎯 How It Works

Vens uses the **OWASP Risk Rating Methodology** to compute contextual risk scores:

1. **You define your project's base risk factors** in `config.yaml`:
   - **Threat Agent** (0-9): Who might attack? (skill, motivation, opportunity)
   - **Vulnerability** (0-9): How easy to discover and exploit?
   - **Technical Impact** (0-9): Damage to systems, data, infrastructure
   - **Business Impact** (0-9): Financial, reputation, compliance consequences

2. **The LLM analyzes each vulnerability** and evaluates its contribution (0-100%) to each factor:
   ```
   CVE-2024-1234 in OpenSSL (RCE):
   ├── Threat Agent:      90%  → Widely known, public exploits
   ├── Vulnerability:     85%  → POC available, easy to exploit
   ├── Technical Impact:  95%  → RCE = full system compromise
   └── Business Impact:  100%  → Frontend server, critical
   ```

3. **Final weighted risk score** is computed:
   ```
   Likelihood = (ThreatAgent × 0.90 + Vulnerability × 0.85) / 2
   Impact = (TechnicalImpact × 0.95 + BusinessImpact × 1.00) / 2
   Risk = Likelihood × Impact
   ```

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

```bash
export OPENAI_API_KEY="your-key"

# 1. Scan your image/project with Trivy
trivy image nginx:1.25 --format=json --severity HIGH,CRITICAL > report.json

# 2. Generate OWASP risk scores using LLM
vens generate --config-file config.yaml report.json output_vex.json
```

## ⚙️ Configuration

### Risk Context (`config.yaml`)

Define your project's context and base OWASP risk factors:

```yaml
# vens - Vulnerability Risk Scoring Configuration
project:
  name: "nginx-production"
  description: "Production NGINX web server exposed to internet"

# OWASP Risk Rating (0-9 scale for each factor)
# Reference: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
owasp:
  # === LIKELIHOOD (How probable is the attack?) ===
  
  threat_agent: 7
  # Who might attack? Their skill, motivation, and opportunity
  # 0-3: Script kiddies, opportunistic attacks
  # 4-6: Skilled attackers, moderate resources
  # 7-9: Organized crime, nation-states, APT groups
  
  vulnerability: 6
  # How easy is it to find and exploit vulnerabilities?
  # 0-3: Very difficult, requires insider knowledge
  # 4-6: Public CVEs, some tools available
  # 7-9: Trivial, automated scanners, known exploits

  # === IMPACT (What damage if successful?) ===
  
  technical_impact: 7
  # Damage to systems, data, and infrastructure
  # 0-3: Minor data disclosure, limited access
  # 4-6: Significant data loss, service disruption
  # 7-9: Complete system compromise, data destruction
  
  business_impact: 8
  # Consequences for the business
  # 0-3: Minimal financial/reputation loss
  # 4-6: Moderate losses, customer complaints
  # 7-9: Bankruptcy risk, regulatory fines, brand destruction
```

### LLM Backends

**vens** supports multiple LLM providers. Configure them using environment variables:

| Backend | Flag `--llm` | Environment Variables |
|---------|--------------|-----------------------|
| **OpenAI** (default) | `openai` | `OPENAI_API_KEY`, `OPENAI_MODEL` (optional) |
| **Ollama** | `ollama` | `OLLAMA_MODEL` (e.g., `llama3`), `OLLAMA_BASE_URL` (optional) |
| **Anthropic** | `anthropic` | `ANTHROPIC_API_KEY` |
| **Google AI** | `googleai` | `GOOGLE_API_KEY`, `GOOGLE_MODEL` (optional) |

**Example for Ollama:**
```bash
export OLLAMA_MODEL="llama3"
vens generate --llm ollama --config-file config.yaml report.json output.json
```

## 💻 Command Reference

### `vens generate`

Generate a VEX report with OWASP risk scores by analyzing vulnerabilities using LLM.

**Usage:**
```bash
vens generate [flags] INPUT OUTPUT
```

**Flags:**
| Flag | Description | Default |
|------|-------------|---------|
| `--config-file` | **(Required)** Path to `config.yaml` with OWASP factors | |
| `--llm` | LLM backend (`openai`, `ollama`, `anthropic`, `googleai`) | `auto` |
| `--llm-temperature` | Sampling temperature | `0.0` |
| `--llm-batch-size` | Number of CVEs to process per request | `10` |
| `--llm-seed` | Seed for reproducible results | `0` |
| `--input-format` | Input format (`auto`, `trivy`) | `auto` |
| `--output-format` | Output format (`auto`, `cyclonedxvex`) | `auto` |
| `--debug-dir` | Directory to save debug files (prompts, responses) | |

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

## 📖 Documentation

- [System Design](docs/system-design/system-design.md): Understand how vens works under the hood.
- [Input Processing](docs/inputs/input-processing.md): Supported formats and data flow.
- [Testing Strategy](docs/testing.md): How we ensure the tool's reliability.

## 🙏 Acknowledgments

- LLM prompt structure inspired by [vexllm](https://github.com/AkihiroSuda/vexllm)

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---
Made with ❤️ for smarter security.
