---
date: 2026-02-04
categories:
  - Introduction
slug: stop-patching-vulnerabilities-that-dont-matter
---

# Stop patching vulnerabilities that don't matter to you

![Stop patching CVEs that don't matter](../../assets/stop-patching-cover.svg)

Monday, 9 AM, coffee in hand. You open the Trivy report: **107 vulnerabilities**. You sort by CVSS, a **9.8 CRITICAL** sits at the top, and the emergency meeting starts.

<!-- more -->

Except that CVE targets a feature you don't even use. Two days gone for nothing. Meanwhile a **5.3 MEDIUM** sits quietly further down: it exposes customer data, and you are under GDPR. That was the real problem.

CVSS tells you the technical severity of the bug. Not the real risk for *your* system.

## What vens does

[vens](https://github.com/venslabs/vens) reads your scan output plus a short file describing your system (exposure, sensitive data, compliance, security controls) and computes an OWASP Risk Rating with an LLM. The result tells you what to patch first.

## How it works

### 1. Install

vens is an [official Trivy plugin](https://aquasecurity.github.io/trivy-plugin-index/):

```bash
go install github.com/venslabs/vens/cmd/vens@latest
# or as a Trivy plugin
trivy plugin install github.com/venslabs/vens
```

### 2. Scan as usual

```bash
trivy image python:3.11-slim --format json --output report.json
```

### 3. Describe your system in a [`config.yaml`](https://github.com/venslabs/vens/blob/main/examples/quickstart/config.yaml)

```yaml
project:
  name: "my-api"
  description: "Customer-facing REST API"

context:
  exposure: "internet"                    # internal | private | internet
  data_sensitivity: "high"                # customer PII
  business_criticality: "high"            # business-critical service
  compliance_requirements: ["GDPR", "SOC2"]
  controls:
    waf: true
    ids: true
```

### 4. Run the contextual analysis

```bash
export OPENAI_API_KEY="sk-..."
export OPENAI_MODEL="gpt-5.4-mini"

# serialNumber of the SBOM paired with this scan; any urn:uuid: works for a first run
SBOM_UUID="urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')"
trivy vens generate --config-file config.yaml --sbom-serial-number "$SBOM_UUID" report.json output.vex.json
```

## The output

Here is an extract of what vens generates:

```json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "vulnerabilities": [
    {
      "id": "CVE-2026-0915",
      "ratings": [
        {
          "score": 45.5,
          "severity": "high",
          "method": "OWASP",
          "vector": "SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:6/LC:7/LI:7/LAV:7/LAC:7/FD:7/RD:7/NC:7/PV:7"
        }
      ]
    },
    {
      "id": "CVE-2019-1010023",
      "ratings": [
        {
          "score": 10,
          "severity": "low",
          "method": "OWASP",
          "vector": "SL:3/M:3/O:3/S:3/ED:2/EE:2/A:2/ID:2/LC:4/LI:4/LAV:4/LAC:4/FD:4/RD:4/NC:4/PV:4"
        }
      ]
    }
  ]
}
```

Same two CVEs, ranked by what they mean for your deployment rather than by a context-free base score.

## Try it

- GitHub: [github.com/venslabs/vens](https://github.com/venslabs/vens)
- Full example: [examples/quickstart](https://github.com/venslabs/vens/tree/main/examples/quickstart)
- License: Apache 2.0, contributions welcome
- LLM support: OpenAI, Anthropic, Google, Ollama (local)

*Originally published on [Medium](https://medium.com/@fahed.dorgaa/vens-stop-patching-vulnerabilities-that-dont-matter-to-you-64337b9468a5).*
