# Quickstart Example

This directory contains a sample project to demonstrate how **vens** prioritizes vulnerabilities.

## Files

- `config.yaml`: Defines the business risk context. In this example, we assign a specific risk score to our main application (`pkg:module/quickstart-sample-app`).
- `sbom.cdx.json`: A CycloneDX SBOM representing the assets (the application and its dependencies). Note that the main application is defined in the `metadata` section.
- `trivy.json`: A vulnerability scan report from Trivy containing several CVEs in various libraries.

## What happens when you run vens?

1. **Mapping**: vens uses an LLM to match each vulnerability from `trivy.json` to the most relevant component in `sbom.cdx.json`.
2. **Contextualization**: For each matched component, vens identifies its "parent" (the main application defined in the SBOM metadata).
3. **Scoring**: vens looks up the risk score for that parent in `config.yaml` and applies it to the vulnerability.
4. **Output**: A VEX (Vulnerability Exploitability eXchange) document is generated, containing the prioritized vulnerabilities with their OWASP risk scores.

## How to run

### Option 1: OpenAI
```bash
export OPENAI_API_KEY="sk-..."
vens generate \
  --config-file config.yaml \
  --sboms sbom.cdx.json \
  --llm openai \
  trivy.json \
  output_vex.json
```

### Option 2: Ollama (Local)
```bash
export OLLAMA_MODEL="llama3"
vens generate \
  --config-file config.yaml \
  --sboms sbom.cdx.json \
  --llm ollama \
  trivy.json \
  output_vex.json
```

Check the `output_vex.json` to see the results!
