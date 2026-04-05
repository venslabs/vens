# Privacy and data flow

**Who this is for:** anyone (security, GRC, compliance, platform) who needs to know exactly what leaves their network when they run `vens generate`.
**By the end of this page:** you can answer "what does Vens send to OpenAI/Anthropic/Google/Ollama?" without reading Go source.

---

## TL;DR

| Data | Sent to the LLM provider? | Sent anywhere else? |
|---|---|---|
| CVE identifier (e.g. `CVE-2024-1234`) | ✅ Yes | ❌ No |
| CVE description / title from your scanner report | ✅ Yes | ❌ No |
| Package name, version, fixed version | ✅ Yes | ❌ No |
| `config.yaml` fields (`exposure`, `data_sensitivity`, `business_criticality`, `compliance_requirements`, `controls`, `notes`) | ✅ Yes — **including the `notes` field verbatim** | ❌ No |
| Your scanner report file as a whole | ❌ No — only the fields above are extracted | ❌ No |
| SBOM contents beyond vulnerability metadata | ❌ No | ❌ No |
| Source code, credentials, filesystem contents | ❌ Never | ❌ Never |

When you use **Ollama**, nothing leaves the machine running Ollama.

---

## What Vens sends per batch

For each batch of CVEs (default: 10 per call, tunable via `--llm-batch-size`), Vens builds two messages:

**System prompt** — contains:

- A fixed instruction block describing the OWASP Risk Rating methodology.
- Your `config.yaml` context, formatted as plain text. **The `notes` field is copied verbatim.**
- The JSON schema the LLM must return.

**Human prompt** — contains a JSON array with, for each CVE in the batch:

- `vulnId` (e.g. `CVE-2024-1234`)
- `pkgId`, `pkgName`
- `installedVersion`, `fixedVersion`
- `title` (the CVE title as reported by your scanner)
- `description` (the CVE description as reported by your scanner)
- `severity` (the native scanner severity, as context)

That is the complete list. Nothing else from the scanner report is forwarded.

---

## What about the `notes` field?

The `notes` field in `config.yaml` is free-form text that you author. It is designed to let you describe architecture and deployment context in plain English so the LLM can make better scoring decisions. **It is sent verbatim** to the configured LLM provider.

**Do:**
- Describe architecture at a level you would share with a security vendor.
- Mention technologies, frameworks, deployment patterns.
- Note compensating controls and the services the system talks to.

**Do not:**
- Paste secrets, API keys, tokens, passwords, or any credential material.
- Name internal systems by sensitive codename if that would violate an NDA or classification policy.
- Include customer data, PHI, PII, or personal identifiers.
- Include confidential roadmap information you are not willing to share with the LLM provider.

If any of the above could reasonably appear in `notes` for your environment, [use Ollama locally](../getting-started/installation.md#configure-an-llm-provider) instead — nothing will leave your network.

---

## Provider-side data handling

Each LLM provider has its own data retention, training, and privacy terms. Vens does not negotiate these on your behalf. Before pointing Vens at a cloud provider in a regulated environment, review:

- **OpenAI** — API data usage and retention: <https://openai.com/policies/api-data-usage-policies/>
- **Anthropic** — Commercial Terms of Service and Privacy Policy: <https://www.anthropic.com/legal>
- **Google AI (Gemini API)** — Data use and abuse policies: <https://ai.google.dev/gemini-api/terms>

Relevant questions to ask your legal/compliance team:

- Does the provider retain prompts and responses? For how long?
- Are prompts used to train future models? Can this be disabled?
- Is a BAA (for HIPAA workloads) or equivalent available for your plan tier?
- Where are the prompts processed geographically (data residency)?

If any of those answers are unacceptable for your data, **use Ollama** — the entire Vens pipeline then runs on hardware you control.

---

## Local / air-gapped deployment

When you configure `OLLAMA_MODEL` and run Vens with `--llm ollama` (or let auto-detection pick Ollama), **no data leaves the machine running Ollama**. Vens makes HTTP requests to `http://localhost:11434` by default, or to `$OLLAMA_HOST` if you run Ollama on a different host inside your network.

For air-gapped networks: install Vens and Ollama on any box that can reach each other; no outbound internet connectivity is required after the initial model pull.

---

## Debug directory

When you pass `--debug-dir <path>`, Vens writes to disk:

- `system.prompt` — the full system prompt sent to the LLM, including your `config.yaml` context (and `notes`).
- `human.prompt` — the full JSON array of CVEs sent to the LLM.

These files contain exactly the same data the LLM receives. They are useful for audit and troubleshooting, but they inherit the same sensitivity as the prompts themselves. Treat `--debug-dir` output as containing:

- your full architectural context (`notes` field),
- every CVE identifier from the scanned image.

Store it accordingly. See [`--debug-dir`](../reference/generate.md#--debug-dir-path) for retention guidance.

---

## See also

- **[Configuration guide](../guides/configuration.md)** — what to put (and not put) in `config.yaml`
- **[Limitations](limitations.md)** — what Vens deliberately does not guarantee
- **[Troubleshooting](../troubleshooting.md)**
