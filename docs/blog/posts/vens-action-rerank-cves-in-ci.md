---
date: 2026-05-28
categories:
  - Guide
slug: vens-action-rerank-cves-in-ci
---

# vens-action: reranking Trivy/Grype CVEs by real risk in CI

![Rerank your CVEs in CI](../../assets/rerank-ci-cover.svg)

If you run Trivy or Grype in CI and triage the output by CVSS, this is the thing I wish I'd had two years ago.

<!-- more -->

## What it does

Trivy and Grype hand you a list of CVEs. CVSS is a score in a vacuum: it doesn't know whether a service runs in a private subnet behind mTLS, or sits on the open internet handling payment cards. [vens](https://github.com/venslabs/vens) reads your scan output plus a YAML describing the service (exposure, data sensitivity, business criticality, controls, compliance, ...), runs every CVE through an LLM with that context, and emits a CycloneDX VEX with OWASP Risk Rating scores. You gate the build on those instead.

[`vens-action`](https://github.com/venslabs/vens-action) is the GitHub Action wrapper: install, invocation, build gate, packaged as a composite. Here's the minimum to drop it in.

## What you need

- A Trivy or Grype JSON report (you're probably running one of these already).
- A `.vens/config.yaml`. Three context fields are the floor (see below).
- An LLM API key: OpenAI, Anthropic, Google, or a self-hosted Ollama.
- The `serialNumber` of your CycloneDX SBOM (or an ad-hoc one, see below).

## The config

The bare minimum:

*Updated for schema 2: since vens v0.7.0 the file starts with `schema_version: 2`, and `traceability`, `detection` and `data_subjects` take their worst case until declared; see [Migrating from vens v0.6](../../reference/config-schema.md#migrating).*

```yaml
schema_version: 2
project:
  name: "checkout-api"
context:
  exposure: "internet"
  data_sensitivity: "high"
  business_criticality: "critical"
```

For scoring that actually reflects your service, fill in the rest: what records an attack attempt (`detection`) and who did what (`traceability`), how many people's personal data it can read (`data_subjects`), security controls (WAF, segmentation, ...), compliance requirements, availability target, free-form notes. The annotated reference lives in [`examples/quickstart/config.yaml`](https://github.com/venslabs/vens/blob/main/examples/quickstart/config.yaml). Wrong values mean wrong scores, so this file deserves the same review process as the rest of your code (CODEOWNERS, PR review, the works).

## The SBOM serial number

vens writes a CycloneDX VEX whose `vulnerabilities[].affects[].ref` entries are [BOM-Link](https://cyclonedx.org/capabilities/bomlink/) references: they must point back to the `serialNumber` of the SBOM the scan was produced from.

If you already have a CycloneDX SBOM for the artifact, pull the serial from it:

```bash
SBOM_UUID=$(jq -r .serialNumber sbom.cdx.json)
```

If you don't have one yet, generate an ad-hoc serial and reuse it across rescans of the same service so the BOM-Link stays stable:

```bash
SBOM_UUID="urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')"
```

Store the value as a repo variable, say `vars.SBOM_SERIAL`. Flag reference: [`vens generate --sbom-serial-number`](https://venslabs.github.io/vens/reference/generate/#-sbom-serial-number-urnuuid).

## The workflow

`.github/workflows/scan.yml`:

```yaml
name: scan
on: [push]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Trivy scan
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          image-ref: python:3.11-slim
          format: json
          output: report.json

      - name: vens
        id: vens
        uses: venslabs/vens-action@v0.2.0
        with:
          version: v0.4.0
          config-file: .vens/config.yaml
          input-report: report.json
          sbom-serial-number: ${{ vars.SBOM_SERIAL }}
          llm-provider: openai
          llm-model: gpt-5.4-mini
          llm-api-key: ${{ secrets.OPENAI_API_KEY }}
          fail-on-severity: critical
          enrich: "true"

      - uses: actions/upload-artifact@v4
        with:
          name: vens
          path: |
            ${{ steps.vens.outputs.vex-file }}
            ${{ steps.vens.outputs.enriched-report }}
```

Each run gives you a CycloneDX VEX (`vex-file`), your original Trivy report annotated with `Custom.owasp_score` and `Custom.owasp_vector` (`enriched-report`, when `enrich: true`), and per-severity counts as step outputs (`count-critical`, `count-high`, ...). Pipe the counts into dashboards, PR comments, whatever you already do with scan metrics.

`fail-on-severity: critical` makes the step fail if any CVE comes out CRITICAL by OWASP (score >= 60; since vens v0.7.0, a HIGH likelihood and a HIGH impact on OWASP's matrix, whatever the score). Drop the line if you just want artifacts and a manual review.

## Things you'll probably want to tweak

- **Self-hosted models.** `llm-provider: ollama` + `llm-base-url: http://ollama.corp:11434`.
- **Air-gapped runners.** Build vens yourself and pass `bin-path` instead of `version`. Skips the download and checksum step entirely.
- **Pin by SHA.** `uses: venslabs/vens-action@<commit-sha>`. Renovate and Dependabot both follow SHA-pinned actions.

## Why I bothered building it

CVSS sorts vulnerabilities like a smoke detector that can't tell if you're cooking or your kitchen is on fire. A 9.8 on an internal service with no PII and no internet exposure is rarely your urgent problem. A 5.4 on the auth path with cleartext token logging probably is. Your team knows the difference, but a spreadsheet per service doesn't scale, and most tools that do contextual scoring are paid SaaS with their own opinions.

vens is OSS, Apache 2.0. The action is a thin composite around the CLI. Issues, feedback, PRs: I read them.

- Action: [github.com/venslabs/vens-action](https://github.com/venslabs/vens-action)
- CLI: [github.com/venslabs/vens](https://github.com/venslabs/vens)
- Docs: [venslabs.github.io/vens](https://venslabs.github.io/vens/)

*Originally published on [dev.to](https://dev.to/fahed-dorgaa/vens-action-reranking-trivygrype-cves-by-real-risk-in-ci-1eec).*
