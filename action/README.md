# vens GitHub Action

A composite GitHub Action that runs [vens](https://github.com/venslabs/vens) on a Trivy or Grype report and produces a CycloneDX VEX document with per-CVE **OWASP Risk Rating** scores contextualised to _your_ system — not just generic CVSS severity.

> **Why?** A scanner finds 300 CVEs. Most don't matter to you. vens uses an LLM plus a description of your system (exposure, data sensitivity, compliance, controls) to tell you which ones actually do.

## Quick start

```yaml
name: scan

on: [push]

permissions:
  contents: read

jobs:
  scan-and-prioritize:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan image with Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'python:3.11-slim'
          format: 'json'
          output: 'trivy.json'

      - name: Prioritize CVEs with vens
        uses: venslabs/vens/action@v0.3.1
        with:
          config-file: .github/vens-config.yaml
          scan-report: trivy.json
          output: vens.vex.json
          sbom-serial-number: urn:uuid:00000000-0000-0000-0000-00000000beef
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          OPENAI_MODEL: gpt-4o

      - uses: actions/upload-artifact@v4
        with:
          name: vens-vex
          path: vens.vex.json
```

## Inputs

| Name | Required | Default | Description |
|---|---|---|---|
| `config-file` | **yes** | — | Path to your `vens-config.yaml` describing the system context (exposure, data sensitivity, compliance, controls). |
| `scan-report` | **yes** | — | Path to the Trivy or Grype JSON vulnerability report. |
| `version` | no | `latest` | vens version to install (e.g. `v0.3.1`). Using `latest` resolves the most recent GitHub release. |
| `output` | no | `vens.vex.json` | Where to write the generated CycloneDX VEX document. |
| `input-format` | no | `auto` | Scanner format: `auto`, `trivy`, `grype`. |
| `output-format` | no | `auto` | Output format: `auto`, `cyclonedxvex`. |
| `llm-provider` | no | `auto` | LLM backend: `auto`, `openai`, `anthropic`, `googleai`, `ollama`. |
| `llm-batch-size` | no | `10` | CVEs per LLM request. |
| `llm-temperature` | no | `0.0` | LLM temperature (`0.0` keeps runs reproducible). |
| `llm-seed` | no | `0` | LLM seed (`0` means no explicit seed). |
| `sbom-serial-number` | no | _auto_ | Stable SBOM UUID (`urn:uuid:...`). **Strongly recommended** to pin a per-service UUID in production — see [Pinning a stable SBOM UUID](#pinning-a-stable-sbom-uuid) below. |
| `sbom-version` | no | `1` | SBOM version number for BOM-Link. |
| `debug-dir` | no | — | Directory to save LLM prompts/responses for debugging. |
| `enrich` | no | `false` | Also run `vens enrich` to fold VEX ratings back into the Trivy report. |
| `enrich-output` | no | `trivy-enriched.json` | Output path for the enriched Trivy report (only used when `enrich=true`). |
| `working-directory` | no | `.` | Working directory from which vens is invoked. |
| `install-dir` | no | _runner tool cache_ | Directory where the vens binary is installed and added to `PATH`. |
| `github-token` | no | `${{ github.token }}` | GitHub token used to resolve `latest` release without hitting API rate-limits. |

## Outputs

| Name | Description |
|---|---|
| `vex-file` | Absolute path to the generated CycloneDX VEX document. |
| `enriched-report` | Absolute path to the enriched Trivy report (only set when `enrich=true`). |
| `vens-version` | vens version actually installed (resolved from `latest` if needed). |
| `sbom-serial-number` | SBOM serial number actually used (provided input or auto-generated UUID). |

## LLM credentials

The action does **not** take API keys as inputs — you pass them to the step as environment variables so they are never logged. Set whichever applies:

| Provider | Required env vars |
|---|---|
| OpenAI (default) | `OPENAI_API_KEY`, optionally `OPENAI_MODEL` (e.g. `gpt-4o`) |
| Anthropic | `ANTHROPIC_API_KEY`, optionally `ANTHROPIC_MODEL` |
| Google AI | `GOOGLE_API_KEY`, optionally `GOOGLE_MODEL` |
| Ollama (local) | `OLLAMA_MODEL`, optionally `OLLAMA_HOST` |

Example with Anthropic:

```yaml
      - uses: venslabs/vens/action@v0.3.1
        with:
          config-file: .github/vens-config.yaml
          scan-report: trivy.json
          llm-provider: anthropic
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          ANTHROPIC_MODEL: claude-3-5-sonnet-latest
```

## Example `vens-config.yaml`

```yaml
project:
  name: "payments-api"
  description: "Customer-facing REST API handling PCI data"

context:
  exposure: "internet"              # internal | private | internet
  data_sensitivity: "critical"      # low | medium | high | critical
  business_criticality: "critical"  # low | medium | high | critical
  compliance_requirements: ["PCI-DSS", "SOC2"]
  controls:
    waf: true
    mtls: true
```

See [venslabs/vens/examples](https://github.com/venslabs/vens/tree/main/examples) for more templates.

## Recipes

### Upload VEX and enriched report as artifacts

```yaml
      - id: vens
        uses: venslabs/vens/action@v0.3.1
        with:
          config-file: .github/vens-config.yaml
          scan-report: trivy.json
          enrich: 'true'
          sbom-serial-number: urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

      - uses: actions/upload-artifact@v4
        with:
          name: vens-output
          path: |
            ${{ steps.vens.outputs.vex-file }}
            ${{ steps.vens.outputs.enriched-report }}
```

### Fail the build only on contextually-HIGH risks

```yaml
      - id: vens
        uses: venslabs/vens/action@v0.3.1
        with:
          config-file: .github/vens-config.yaml
          scan-report: trivy.json
          sbom-serial-number: urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

      - name: Gate on contextual HIGH/CRITICAL
        run: |
          high=$(jq '[.vulnerabilities[]?.ratings[]? | select(.method=="OWASP" and (.severity=="high" or .severity=="critical"))] | length' "${{ steps.vens.outputs.vex-file }}")
          echo "contextual HIGH+ count: ${high}"
          if [ "${high}" -gt 0 ]; then
            echo "::error::${high} vulnerabilities are HIGH or CRITICAL in your context"
            exit 1
          fi
```

### Use a local Ollama LLM (no data leaves the runner)

```yaml
      - name: Start Ollama
        run: |
          curl -fsSL https://ollama.com/install.sh | sh
          ollama serve &>/dev/null &
          sleep 3
          ollama pull llama3.1:8b

      - uses: venslabs/vens/action@v0.3.1
        with:
          config-file: .github/vens-config.yaml
          scan-report: trivy.json
          llm-provider: ollama
        env:
          OLLAMA_MODEL: llama3.1:8b
```

### Chain with Grype instead of Trivy

```yaml
      - uses: anchore/scan-action@v4
        id: grype
        with:
          image: 'python:3.11-slim'
          output-format: 'json'
          fail-build: false

      - uses: venslabs/vens/action@v0.3.1
        with:
          config-file: .github/vens-config.yaml
          scan-report: ${{ steps.grype.outputs.json }}
          input-format: grype
          sbom-serial-number: urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

### Upload the VEX to Dependency-Track

```yaml
      - id: vens
        uses: venslabs/vens/action@v0.3.1
        with:
          config-file: .github/vens-config.yaml
          scan-report: trivy.json
          sbom-serial-number: urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

      - name: Upload VEX to Dependency-Track
        run: |
          curl -X POST "${DT_URL}/api/v1/vex" \
            -H "X-Api-Key: ${DT_API_KEY}" \
            -F "project=${DT_PROJECT_UUID}" \
            -F "vex=@${{ steps.vens.outputs.vex-file }}"
        env:
          DT_URL: ${{ secrets.DT_URL }}
          DT_API_KEY: ${{ secrets.DT_API_KEY }}
          DT_PROJECT_UUID: ${{ secrets.DT_PROJECT_UUID }}
```

## Pinning a stable SBOM UUID

The SBOM serial number is the identifier that links successive VEX documents for the same component. If you regenerate it on every run, downstream tools (Dependency-Track, GUAC, your own dashboards) will treat each scan as an unrelated document and you lose history.

**Recommended**: generate one UUID per service, once, and store it in your repo or secrets.

```bash
# Generate once, then paste into your workflow or a repo variable
uuidgen | tr '[:upper:]' '[:lower:]'
# → f47ac10b-58cc-4372-a567-0e02b2c3d479
```

Then in the action:

```yaml
        with:
          sbom-serial-number: urn:uuid:f47ac10b-58cc-4372-a567-0e02b2c3d479
```

Or via a repo variable:

```yaml
        with:
          sbom-serial-number: urn:uuid:${{ vars.VENS_SBOM_UUID }}
```

If you omit the input entirely, the action auto-generates a random UUID per run and prints a warning.

## How the binary is installed

The action is a composite action that:

1. Resolves the requested version (`latest` hits the GitHub API; pinned versions skip the call).
2. Downloads `vens-<version>-<os>-<arch>.tar.gz` from the matching [GitHub Release](https://github.com/venslabs/vens/releases).
3. Downloads `SHA256SUMS` from the same release and **verifies the tarball checksum**.
4. Extracts into `${RUNNER_TOOL_CACHE}/vens/<version>/<arch>/bin/` and prepends it to `PATH`.
5. Caches across jobs on the same runner.

Supported platforms: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`.

## Permissions

The action itself only needs network egress to `github.com` (release download). If your job uses the default `GITHUB_TOKEN`, minimal scope is fine:

```yaml
permissions:
  contents: read
```

## Versioning

- Pin to an exact release (`venslabs/vens/action@v0.3.1`) for reproducible builds.
- Use a floating major tag (`venslabs/vens/action@v0`) once it's published, for auto-updates within a major version.
- Avoid `@main` in production — it will follow unreleased changes.

## License

Apache License 2.0 — see the [LICENSE](../LICENSE) at the repo root.
