# Installation

**Who this is for:** anyone getting started with Vens.
**By the end of this page:** you have `vens` (or `trivy vens`) running on your machine.

Vens ships as a single static binary. Pick the method that fits your workflow.

---

## Option 1 — Go install (recommended for developers)

```bash
go install github.com/venslabs/vens/cmd/vens@latest
```

Verify:

```bash
vens version
```

!!! tip
    Make sure `$(go env GOPATH)/bin` is in your `$PATH`.

---

## Option 2 — Trivy plugin (recommended for Trivy users)

If you already use Trivy, install Vens as a native plugin — no separate binary to manage.

```bash
trivy plugin install github.com/venslabs/vens
```

Verify:

```bash
trivy vens version
```

From now on, anywhere in this documentation where you see `vens <command>`, you can use `trivy vens <command>` instead.

---

## Option 3 — Prebuilt binary

Download the latest release for your OS/architecture from the [releases page](https://github.com/venslabs/vens/releases), extract it, and put it in your `$PATH`.

```bash
# Example for Linux x86_64 — replace VERSION with the actual tag
curl -L https://github.com/venslabs/vens/releases/download/VERSION/vens_Linux_x86_64.tar.gz \
  | tar -xz
sudo mv vens /usr/local/bin/
vens version
```

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
    A scan of ~200 CVEs with `gpt-4o` costs roughly **$0.10–$0.50** depending on prompt size. Use Ollama for air-gapped or cost-sensitive environments.

---

## Next step

Generate your first VEX: **[Quickstart (5 minutes)](quickstart.md)**.
