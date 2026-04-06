# Limitations — what Vens deliberately does not guarantee

**Who this is for:** anyone who needs to defend an adoption decision to a CISO, an auditor, or a skeptical engineering team.
**By the end of this page:** you know the honest shape of what Vens cannot promise, so you can scope how you use it.

Vens is a pragmatic prioritization tool, not a certification or a deterministic scoring engine. The list below is the set of things we chose **not** to promise, and why.

---

## 1. Scores are not byte-reproducible across runs

Even at `--llm-temperature 0.0` and with `--llm-seed`, cloud LLM providers do not expose true deterministic decoding, and provider-side models get silently updated. Expect **±1–3 points of drift on a minority of CVEs** between runs with the same config and model.

Mitigations Vens applies:

- Final OWASP score is computed in Go from the LLM's four 0–9 component scores, so small drift averages out.
- Same prompt, same schema, same ordering on every run.

If you need strict reproducibility for audit evidence at a point in time, pin a local Ollama model tag (model tags are immutable on disk) and archive `--debug-dir` output alongside the VEX. Together they give you a byte-exact record.

---

## 2. No published benchmark or calibration study

We do not claim a measured accuracy number against a ground-truth dataset. There is no "Vens scores agreed with human experts N% of the time" study. Treat Vens scores as a **ranking aid over CVSS alone**, not as a certified risk assessment.

How to use it responsibly:

- Audit the top 10 scores of every major scan manually (`--debug-dir` makes this cheap).
- Pilot on a single service for 2–4 weeks before expanding.
- Compare Vens' top-N to what your team would have ranked manually. If the overlap is high, you have real signal; if not, tighten `config.yaml` and the `notes` field.

---

## 3. Score quality depends entirely on user-provided context

`config.yaml` is a trust input. If you:

- set `exposure: internal` on an internet-facing service,
- mark `waf: true` when you have no WAF,
- leave `notes` empty on a complex deployment,

— the LLM has no way of knowing, and the scores will silently reflect your bad data. There is no automated validation of your claims. This is by design (Vens cannot inspect your production), but it is a limitation you should mitigate with [governance](../guides/configuration.md#governing-your-context-file).

---

## 4. No `analysis` block in the output VEX

The CycloneDX VEX spec allows per-vulnerability `analysis.state`, `analysis.justification`, `analysis.detail`. **Vens does not emit any of these.** The output carries only the OWASP rating (score, severity, vector). Rationale:

- The LLM reasoning is not stable enough across runs to be embedded as a durable CycloneDX `justification` — that field is intended for human assertions.
- Keeping the VEX strictly to numeric scoring means downstream tools can ingest it without trust assumptions about free-text fields.

If you need a justification record (for audit), use `--debug-dir` and preserve the output alongside your evidence. See [`--debug-dir`](../reference/generate.md#--debug-dir-path).

---

## 5. Vens sends data to third-party LLM providers (unless you use Ollama)

When you pick OpenAI, Anthropic or Google AI, every batch of CVEs — with title, description, package metadata, and your full `config.yaml` context including the `notes` field — is transmitted to that provider. Vens does not filter, redact, or negotiate data handling terms on your behalf.

See [Privacy and data flow](privacy-and-data-flow.md) for the full list of what is sent, and use [Ollama locally](../getting-started/installation.md#configure-an-llm-provider) when this is not acceptable.

---

## 6. No HIPAA BAA or similar legal agreements

Vens itself is an MIT-ish Apache 2.0 Go binary — it holds no data and signs no agreements. If you need a BAA, DPA, or equivalent for a cloud LLM provider, negotiate it directly with the provider on your provider account. For regulated workloads, the safest path is to deploy with Ollama on infrastructure you already have compliance coverage for.

---

## 7. Score quality drops on models below ~7B parameters

Vens asks the LLM to return structured JSON with four component scores per CVE. Small local models (under 7B parameters) frequently emit malformed JSON or produce flat, uniform scores regardless of input. `llama3.1:70b` and larger cloud models (gpt-4o, claude-sonnet-4-5, gemini-2.0-flash) are the sweet spot; lighter models are usable with `--llm-batch-size 3–5` but with lower quality.

This is a fundamental constraint of today's open-weight model landscape — if you need air-gapped + high quality, plan for a beefy GPU box.

---

## 8. No built-in cost control or budget gate

Vens makes LLM calls and does not know how much they cost. There is no `--max-spend` flag, no per-run budget, no rate-limit other than the provider's. Monitor billing on your provider dashboard, and start with small batches in CI before scaling out.

---

## 9. No reachability analysis

Vens reasons from CVE metadata (id, title, description, package) plus your text-described context. It **does not** inspect your source code, build graph, call graph, or runtime. If a CVE lives in a code path your build never executes, Vens will only know about it if you mention it in `notes` or if the CVE description makes it obvious.

For true reachability signals, chain a dedicated tool (Semgrep Code, Snyk Reachability, Endor Labs…) in front of Vens and paste its conclusions into `config.yaml` `notes`. See [Alternatives](alternatives.md).

---

## 10. Pre-1.0 — API surface may change

Vens is under active development and has not reached a 1.0 release yet. The CLI flags and `config.yaml` schema may evolve between minor versions. Pin a specific version in CI (`go install github.com/venslabs/vens/cmd/vens@vX.Y.Z`) and read the release notes before upgrading.

---

## See also

- **[Privacy and data flow](privacy-and-data-flow.md)**
- **[CVSS vs OWASP contextual](cvss-vs-owasp.md)**
- **[Alternatives](alternatives.md)**
- **[Troubleshooting](../troubleshooting.md)**
