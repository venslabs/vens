# Installation

**Who this is for:** anyone getting started with Vens.
**By the end of this page:** you have Vens running — either as a CI step or as a local CLI binary.

---

## GitHub Action

If you scan with Trivy or Grype in GitHub Actions, drop [`venslabs/vens-action`](https://github.com/marketplace/actions/vens-action) into the workflow after the scan step:

```yaml
- name: Scan image with Trivy
  run: trivy image python:3.11-slim --format json --output report.json

- name: Prioritize with vens
  uses: venslabs/vens-action@v0.2.0   # check the marketplace for the latest tag; pin by SHA in production
  with:
    version: v0.4.0                   # vens binary version
    config-file: .vens/config.yaml    # see ../guides/configuration.md to author this file
    input-report: report.json
    sbom-serial-number: ${{ vars.SBOM_SERIAL }}
    llm-provider: openai
    llm-model: gpt-4o
    llm-api-key: ${{ secrets.OPENAI_API_KEY }}
    fail-on-severity: critical        # break the build on critical OWASP risk
```

The action installs the binary, runs `vens generate`, and exposes severity counts as workflow outputs you can fail the build on. Full input/output reference, air-gapped runners, and the mock provider: see the **[GitHub Actions integration guide](../guides/github-actions.md)**.

---

## Run Vens locally

Vens ships as a single static binary. Pick the method that fits your workflow.

### Prerequisites

Vens is not a scanner — it consumes reports produced by one. Before you start, make sure you have **one** of the following installed:

- **Trivy** — [trivy.dev/latest/getting-started/installation/](https://trivy.dev/latest/getting-started/installation/)
- **Grype** — [github.com/anchore/grype#installation](https://github.com/anchore/grype#installation)

You will also need credentials for an LLM provider (OpenAI, Anthropic, Google AI or Ollama) — see [Configure an LLM provider](#configure-an-llm-provider) below.

---

### Option 1 — Go install (recommended for developers)

```bash
go install github.com/venslabs/vens/cmd/vens@latest
```

Verify:

```bash
vens --version
```

!!! tip
    Make sure `$(go env GOPATH)/bin` is in your `$PATH`.

!!! note
    Pinning a specific version: `go install github.com/venslabs/vens/cmd/vens@v0.3.0`.

---

### Option 2 — Trivy plugin (recommended for Trivy users)

If you already use Trivy, install Vens as a native plugin — no separate binary to manage.

```bash
trivy plugin install github.com/venslabs/vens
```

Verify:

```bash
trivy vens --version
```

From now on, anywhere in this documentation where you see `vens <command>`, you can use `trivy vens <command>` instead.

---

### Option 3 — Prebuilt binary

Download the latest release for your OS/architecture from the [releases page](https://github.com/venslabs/vens/releases), extract it, and put it in your `$PATH`.

=== "Linux (x86_64)"

    ```bash
    # Replace VERSION with the actual tag, e.g. v0.3.0
    curl -L https://github.com/venslabs/vens/releases/download/VERSION/vens_Linux_x86_64.tar.gz \
      | tar -xz
    sudo mv vens /usr/local/bin/
    vens --version
    ```

=== "macOS (Apple Silicon)"

    ```bash
    curl -L https://github.com/venslabs/vens/releases/download/VERSION/vens_Darwin_arm64.tar.gz \
      | tar -xz
    sudo mv vens /usr/local/bin/
    vens --version
    ```

=== "macOS (Intel)"

    ```bash
    curl -L https://github.com/venslabs/vens/releases/download/VERSION/vens_Darwin_x86_64.tar.gz \
      | tar -xz
    sudo mv vens /usr/local/bin/
    vens --version
    ```

=== "Windows"

    Download `vens_Windows_x86_64.zip` from the releases page, extract it, and add the folder containing `vens.exe` to your `PATH`. Then in PowerShell:

    ```powershell
    vens --version
    ```

!!! note
    Exact archive names follow the release assets. Check the [releases page](https://github.com/venslabs/vens/releases) for the file matching your platform if unsure.

---

### Verify the download

Release artifacts are signed with [cosign](https://github.com/sigstore/cosign) in keyless mode: the signing identity is the GitHub Actions release workflow itself, certified by Sigstore — no long-lived key. Each release publishes `SHA256SUMS` and its Sigstore bundle `SHA256SUMS.sigstore.json` (signature, certificate, and transparency-log proof in one file). Download both alongside your archive from the [releases page](https://github.com/venslabs/vens/releases), then:

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/venslabs/vens/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS

sha256sum --check --ignore-missing SHA256SUMS
```

!!! note
    Releases also carry a GitHub build-provenance attestation. Verify it with `gh attestation verify <archive> --repo venslabs/vens`.

---

### Configure an LLM provider

Vens calls an LLM to score each CVE. All four providers below are first-class — pick whichever matches your constraints. Export credentials for **one**:

Vens asks the LLM to return structured JSON with four 0–9 component scores per CVE. If a model emits malformed JSON, you'll see `unable to parse LLM output` — see [troubleshooting](../troubleshooting.md).

=== "Ollama (local, no cloud, zero cost)"

    Run Ollama on the host where Vens runs (or another host on the same network), then pull a model:

    ```bash
    ollama pull llama3.1:70b
    # Lighter alternatives:
    # ollama pull llama3.1:8b
    # ollama pull mistral:7b

    export OLLAMA_MODEL="llama3.1:70b"
    # Optional — only set if Ollama runs on a different host than Vens:
    export OLLAMA_HOST="http://ollama.internal:11434"
    ```

    Nothing leaves the machine running Ollama — see [Privacy and data flow](../concepts/privacy-and-data-flow.md).

=== "OpenAI"

    ```bash
    export OPENAI_API_KEY="sk-..."
    export OPENAI_MODEL="gpt-4o"
    ```

    Among the cloud providers, OpenAI and Google AI accept the `seed` parameter Vens forwards (`--llm-seed`); Anthropic has no seed parameter and silently ignores it. This does not guarantee byte-identical scores across runs — see [Reference: `--llm-seed`](../reference/generate.md#--llm-seed-int) and [Limitations](../concepts/limitations.md).

=== "Anthropic"

    ```bash
    export ANTHROPIC_API_KEY="sk-ant-..."
    export ANTHROPIC_MODEL="claude-sonnet-4-5"
    ```

=== "Google AI"

    ```bash
    export GOOGLE_API_KEY="..."
    export GOOGLE_MODEL="gemini-2.5-flash"
    ```

Auto-detection currently defaults to **OpenAI**. If you use a different provider, pass the `--llm` flag explicitly:

```bash
--llm openai      # default when auto
--llm anthropic
--llm googleai
--llm ollama
```

!!! warning "LLM cost"
    Cloud LLM pricing depends on model, prompt size, and CVE count. Vens does not estimate cost.

    For an exact number, run once against your provider and read the billing dashboard. For a pre-run estimate, run with `--debug-dir ./debug`, count the tokens in `debug/system.prompt`, and plug into your provider's pricing page (the `human.prompt` file is overwritten on every batch and output tokens are not captured, so this is approximate).

    For zero-cost or air-gapped runs, use Ollama.

---

## Next step

Generate your first VEX: **[Quickstart (5 minutes)](quickstart.md)**.
