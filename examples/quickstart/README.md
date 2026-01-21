# Quickstart Example

This directory contains a **real-world example** demonstrating how **vens** prioritizes vulnerabilities based on business context.

## Overview

In this example, we scan **2 popular container images** that you might find in a typical production environment:

| Image | Role | Vulnerabilities | OWASP Score |
|-------|------|-----------------|-------------|
| `nginx:1.21` | Public-facing web server | 540 | 36 (CRITICAL) |
| `redis:6` | Internal cache | 160 | 12 (LOW) |

**The key insight**: A vulnerability in `nginx` (your internet-exposed frontend) is more critical than the same vulnerability in `redis` (internal cache). **vens** helps you prioritize based on this business context.

## Directory Structure

```
quickstart/
├── config.yaml          # OWASP risk scores for each component
├── sboms/               # CycloneDX SBOMs for each image
│   ├── nginx.cdx.json
│   └── redis.cdx.json
└── reports/             # Trivy vulnerability reports
    ├── nginx.trivy.json
    └── redis.trivy.json
```

## How It Works

1. **SBOMs** (`sboms/`): Each CycloneDX SBOM lists the packages and dependencies in the container image
2. **Vulnerability Reports** (`reports/`): Trivy scans identify CVEs in each image
3. **Risk Configuration** (`config.yaml`): You define OWASP risk scores based on business context
4. **vens**: Combines all inputs to produce a prioritized VEX document

## Running the Example

### Option 1: OpenAI

```bash
export OPENAI_API_KEY="sk-..."
vens generate \
  --config-file config.yaml \
  --sboms sboms/nginx.cdx.json,sboms/redis.cdx.json \
  --llm openai \
  reports/nginx.trivy.json \
  output_vex.cdx.json
```

### Option 2: Ollama (Local LLM)

```bash
export OLLAMA_MODEL="llama3"
vens generate \
  --config-file config.yaml \
  --sboms sboms/nginx.cdx.json,sboms/redis.cdx.json \
  --llm ollama \
  reports/nginx.trivy.json \
  output_vex.cdx.json
```

## Example Output

After running vens, `output_vex.cdx.json` contains a CycloneDX VEX document with prioritized vulnerabilities:

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "vulnerabilities": [
    {
      "id": "CVE-2011-3374",
      "ratings": [
        {
          "score": 36,
          "method": "OWASP"
        }
      ],
      "affects": [
        {
          "ref": "urn:cdx:7d3fcbed-5788-4f1c-843c-991003351c90/1#pkg:deb/debian/apt@2.2.4?arch=amd64&distro=debian-11.3"
        }
      ]
    },
    {
      "id": "CVE-2017-18018",
      "ratings": [
        {
          "score": 36,
          "method": "OWASP"
        }
      ],
      "affects": [
        {
          "ref": "urn:cdx:7d3fcbed-5788-4f1c-843c-991003351c90/1#pkg:deb/debian/coreutils@8.32-4+b1?arch=amd64&distro=debian-11.3"
        }
      ]
    }
  ]
}
```

### Understanding the Output

Each vulnerability in the output includes an OWASP risk score (36) inherited from the parent component (`nginx`). This score reflects the business context: nginx is internet-exposed with a high attack surface.

If you process a report for `redis` instead, vulnerabilities would receive a lower score (12) because redis is an internal cache, not directly accessible.

| Component | Risk Level | Why? |
|-----------|------------|------|
| nginx | CRITICAL (36) | Internet-exposed, high attack surface |
| redis | LOW (12) | Internal cache, not directly accessible |

This is the power of **vens**: it helps you focus on what matters most to your business.

## Regenerating the Example

To regenerate the SBOMs and vulnerability reports with newer image versions:

```bash
# Generate SBOMs
trivy image nginx:1.21 --format cyclonedx --output sboms/nginx.cdx.json
trivy image redis:6 --format cyclonedx --output sboms/redis.cdx.json

# Generate vulnerability reports
trivy image nginx:1.21 --format json --output reports/nginx.trivy.json
trivy image redis:6 --format json --output reports/redis.trivy.json
```

## Key Takeaways

1. **Context matters**: Not all vulnerabilities are equally important
2. **Business impact**: vens uses OWASP risk scoring to reflect real-world priorities
3. **Actionable output**: The VEX document helps security teams focus remediation efforts
4. **Scalable**: Works with any number of components and vulnerability reports
