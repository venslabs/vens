# Installation

**Who this is for:** anyone getting started with Vens.
**By the end of this page:** you have `vens` (or `trivy vens`) running on your machine, with an LLM provider configured and a scanner available.

Vens ships as a single static binary. Pick the method that fits your workflow.

---

## Prerequisites

Vens is not a scanner — it consumes reports produced by one. Before you start, make sure you have **one** of the following installed:

- **Trivy** — [trivy.dev/latest/getting-started/installation/](https://trivy.dev/latest/getting-started/installation/)
- **Grype** — [github.com/anchore/grype#installation](https://github.com/anchore/grype#installation)

You will also need credentials for an LLM provider (OpenAI, Anthropic, Google AI or Ollama) — see [Configure an LLM provider](#configure-an-llm-provider) below.

---

## Option 1 — Go install (recommended for developers)

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

## Option 2 — Trivy plugin (recommended for Trivy users)

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

## Option 3 — Prebuilt binary

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

## Configure an LLM provider

Vens calls an LLM to score each CVE. All four providers below are first-class — pick whichever matches your constraints. Export credentials for **one**:

=== "Ollama (local, no cloud, zero cost)"

    Run Ollama on the host where Vens runs (or another host on the same network), then pull a model:

    ```bash
    ollama pull llama3.1:70b    # recommended for OWASP scoring quality
    # Lighter options if you are hardware-constrained:
    # ollama pull llama3.1:8b
    # ollama pull mistral:7b

    export OLLAMA_MODEL="llama3.1:70b"
    # Optional — only set if Ollama runs on a different host than Vens:
    export OLLAMA_HOST="http://ollama.internal:11434"
    ```

    **Model size matters.** Vens asks the LLM to return structured JSON with four 0–9 component scores per CVE. Models under 7B parameters routinely emit malformed JSON on batches of 10 CVEs. If you see `unable to parse LLM output` errors in [troubleshooting](../troubleshooting.md), move up one model tier or lower `--llm-batch-size` to 3–5.

    **Hardware rule of thumb:** `llama3.1:70b` needs a GPU with ≥48 GB VRAM (or an Apple Silicon box with ≥64 GB unified memory); `llama3.1:8b` runs on a modern laptop with ≥16 GB RAM.

    Nothing leaves the machine(s) running Ollama and Vens — see [Privacy and data flow](../concepts/privacy-and-data-flow.md).

=== "OpenAI"

    ```bash
    export OPENAI_API_KEY="sk-..."
    export OPENAI_MODEL="gpt-4o"
    ```

    OpenAI currently honours the `seed` parameter Vens forwards, giving the lowest cross-run score drift among cloud providers.

=== "Anthropic"

    ```bash
    export ANTHROPIC_API_KEY="sk-ant-..."
    export ANTHROPIC_MODEL="claude-sonnet-4-5"
    ```

=== "Google AI"

    ```bash
    export GOOGLE_API_KEY="..."
    export GOOGLE_MODEL="gemini-2.0-flash"
    ```

Auto-detection currently defaults to **OpenAI**. If you use a different provider, pass the `--llm` flag explicitly:

```bash
--llm openai      # default when auto
--llm anthropic
--llm googleai
--llm ollama
```

!!! warning "LLM cost"
    Cloud LLM pricing changes frequently and depends on model tier, prompt size, and the number of CVEs in your report. Vens does **not** estimate cost for you. To get a real number for your own environment:

    - Run Vens once on a representative report with `--debug-dir ./debug`.
    - Count the tokens in `debug/system.prompt` and `debug/human.prompt` (multiply by the batch count).
    - Plug those numbers into your provider's pricing page.

    As a rough order of magnitude at the time of writing, a single-scan run of ~200 CVEs with `gpt-4o` falls in the "cents to low dollars" range. **Treat this as back-of-envelope only** and always validate against your actual provider invoice before scaling to production CI. For zero-cost or air-gapped deployments, use the Ollama tab above.

---

## Next step

Generate your first VEX: **[Quickstart (5 minutes)](quickstart.md)**.
