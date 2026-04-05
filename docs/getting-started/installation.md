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

Vens calls an LLM to score each CVE. Before running it, export credentials for **one** provider:

=== "OpenAI (recommended)"

    ```bash
    export OPENAI_API_KEY="sk-..."
    export OPENAI_MODEL="gpt-4o"
    ```

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

=== "Ollama (local, no API key)"

    ```bash
    # Run Ollama locally, then:
    export OLLAMA_MODEL="llama3.1"
    ```

Vens auto-detects which provider to use based on the environment variable that is set. You can override with `--llm openai|anthropic|googleai|ollama`.

!!! warning "Token cost"
    A scan of ~200 CVEs with `gpt-4o` typically costs in the order of a few cents to a dollar, depending on prompt size and the model you pick. Use Ollama for air-gapped or cost-sensitive environments, and always monitor your own provider billing for the authoritative number.

---

## Next step

Generate your first VEX: **[Quickstart (5 minutes)](quickstart.md)**.
