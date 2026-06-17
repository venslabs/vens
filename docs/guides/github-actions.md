# GitHub Actions Integration

Drop [vens-action](https://github.com/marketplace/actions/vens-action) into your pipeline after a Trivy or Grype scan to re-score every CVE in your project's context and produce a CycloneDX VEX file.

## Quickstart

Add this to your workflow after a container or dependency scan:

```yaml
- name: Scan image with Trivy
  run: trivy image python:3.11-slim --format json --output report.json

- name: Prioritize with vens
  id: vens
  uses: venslabs/vens-action@v0.2.0
  with:
    version: v0.3.2
    config-file: .vens/config.yaml
    input-report: report.json
    sbom-serial-number: ${{ vars.SBOM_SERIAL }}
    llm-provider: openai
    llm-model: gpt-4o
    llm-api-key: ${{ secrets.OPENAI_API_KEY }}
    fail-on-severity: critical
    enrich: "true"

- uses: actions/upload-artifact@v4
  with:
    name: vens-output
    path: |
      ${{ steps.vens.outputs.vex-file }}
      ${{ steps.vens.outputs.enriched-report }}
```

For tighter supply-chain control, pin by commit SHA instead of the mutable tag: `uses: venslabs/vens-action@06d3eb97fb0c2040e95f3bea271d0aeb2fd00c76  # v0.2.0`. Dependabot and Renovate both track SHA-pinned actions.

## About vens-action

The action wraps the [vens CLI](../reference/generate.md). It expects a Trivy or Grype JSON report, your `config.yaml`, and an LLM provider API key. It outputs a VEX file and severity counts you can use to fail the build.

Key difference from running `vens generate` directly: the action handles binary installation (from a release tag or pre-installed path), extracts `sbom-serial-number` for BOM-Link anchoring, and exposes counts as workflow outputs for downstream steps.

The `llm-api-key` is passed as an environment variable (never a CLI argument) and masked in workflow logs via `::add-mask::` before any step runs.

## Attestation

Set `attest: "true"` to also emit a [CycloneDX attestation](https://cyclonedx.org/capabilities/attestations/) next to the VEX, recording how each CVE was scored (model, seed, prompt/input/config hashes, raw response) for audit and reproduction. Add the `attestation-file` output to your `upload-artifact` paths to keep it. It is evidence, not a cryptographic signature, and includes the model's reasoning in clear text, so keep it access-controlled. Requires vens-action v0.2.0.

## Using the mock provider in CI

For testing or cost savings, use the `mock` LLM provider — it returns fixed scores and costs nothing:

```yaml
- uses: venslabs/vens-action@v0.2.0
  with:
    version: v0.3.2
    config-file: .vens/config.yaml
    input-report: report.json
    sbom-serial-number: ${{ vars.SBOM_SERIAL }}
    llm-provider: mock
```

Good for gating builds on presence of a VEX file without calling external LLM services.

## Air-gapped runners

Pre-install the vens binary and pass `bin-path`:

```yaml
- uses: venslabs/vens-action@v0.2.0
  with:
    bin-path: /opt/bin/vens
    config-file: .vens/config.yaml
    input-report: report.json
    sbom-serial-number: ${{ vars.SBOM_SERIAL }}
    llm-provider: ollama
    llm-base-url: http://ollama.corp.example:11434
    llm-model: llama3.1
```

## For details

See the [vens-action README](https://github.com/venslabs/vens-action#readme) for the full input/output reference and platform support notes.
