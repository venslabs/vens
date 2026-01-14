# Vens as a Trivy Plugin

Vens can be used as a Trivy plugin to evaluate and prioritize vulnerabilities based on context.

## Installation

Install vens as a Trivy plugin:

```bash
trivy plugin install github.com/venslabs/vens
```

## Usage

Once installed, you can use vens commands directly through Trivy:

### 1. Generate VEX with LLM

Generate a VEX document from a Trivy scan report using LLM to prioritize vulnerabilities:

```bash
# Scan an image with Trivy
trivy image python:3.12.4 --format=json --severity HIGH,CRITICAL > report.json

# Generate VEX using vens as a Trivy plugin
trivy vens generate --config-file config.yaml --sboms sbom1.cdx.json,sbom2.cdx.json report.json output.cdx
```

### 2. Enrich Reports with VEX

Enrich a Trivy vulnerability report with ratings and scores from a VEX document:

```bash
# Scan an image with Trivy
trivy image python:3.12.4 --format=json --severity HIGH,CRITICAL > report.json

# Generate VEX using vens
trivy vens generate --config-file config.yaml report.json vex.cdx.json

# Enrich the report with VEX ratings
trivy vens enrich --vex vex.cdx.json report.json

# Or save to a file
trivy vens enrich --vex vex.cdx.json --output enriched-report.json report.json
```