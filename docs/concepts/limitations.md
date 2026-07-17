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

You can also pass [`--attest`](../reference/generate.md#--attest) to write a CDXA sidecar that records, per CVE, the model, seed, temperature, and SHA-256 hashes of the prompt, scan report and `config.yaml`, plus the raw response. It captures the evidence to reproduce a run later. It is point-in-time evidence, not a cryptographic signature.

---

## 2. Benchmarked for model choice, not calibrated to your outcomes

There is now a public benchmark, [vens-benchmark](https://github.com/venslabs/vens-benchmark), measuring how 12 LLMs do the vens scoring task: predicting a CVE's severity and reacting when the context changes. It is what backs the model advice in [Choosing a model](choosing-a-model.md) and the [writeup](../blog/posts/which-llm-should-score-your-cves.md).

What it does **not** give you is a calibration study proving Vens' priorities match expert human judgment on your systems. It tells you which model to run, not "Vens agreed with a human N% of the time" on your backlog. Treat Vens scores as a **ranking aid over CVSS alone**, not a certified risk assessment.

How to use it responsibly:

- Audit the top 10 scores of every major scan manually (`--debug-dir` makes this cheap).
- Pilot on a single service for 2–4 weeks before expanding.
- Compare Vens' top-N to what your team would have ranked manually. If the overlap is high, you have real signal; if not, tighten `config.yaml` and the `notes` field.

---

## 3. Score quality depends on your context and your model

`config.yaml` is a trust input. If you:

- set `exposure: internal` on an internet-facing service,
- mark `waf: true` when you have no WAF,
- leave `notes` empty on a complex deployment,

then the LLM has no way of knowing, and the scores will silently reflect your bad data. There is no automated validation of your claims. This is by design (Vens cannot inspect your production), but it is a limitation you should mitigate with [governance](../guides/configuration.md#governing-your-context-file).

Quality also depends on the model you run. A weak model produces weak scores even with perfect context, and the [benchmark](https://github.com/venslabs/vens-benchmark) shows the spread between models is large. See [Choosing a model](choosing-a-model.md) for the ones that hold up.

---

## 4. No `analysis` block in the output VEX

The CycloneDX VEX spec allows per-vulnerability `analysis.state`, `analysis.justification`, `analysis.detail`. **Vens does not emit any of these.** The output carries only the OWASP rating (score, severity, vector). Rationale:

- The LLM reasoning is not stable enough across runs to be embedded as a durable CycloneDX `justification` — that field is intended for human assertions.
- Keeping the VEX strictly to numeric scoring means downstream tools can ingest it without trust assumptions about free-text fields.

If you need a justification record (for audit), use `--debug-dir`, or pass [`--attest`](../reference/generate.md#--attest) to capture the per-CVE reasoning as structured CDXA claims (predicate plus reasoning) in a sidecar file, kept out of the VEX so downstream tools still ingest a clean document. See [`--debug-dir`](../reference/generate.md#--debug-dir-path).

---

## 5. Vens sends data to third-party LLM providers (unless you use Ollama)

When you pick OpenAI, Anthropic or Google AI, every batch of CVEs — with title, description, package metadata, and your full `config.yaml` context including the `notes` field — is transmitted to that provider. Vens does not filter, redact, or negotiate data handling terms on your behalf.

See [Privacy and data flow](privacy-and-data-flow.md) for the full list of what is sent, and use [Ollama locally](../getting-started/installation.md#configure-an-llm-provider) when this is not acceptable.

---

## 6. No HIPAA BAA or similar legal agreements

Vens itself is an MIT-ish Apache 2.0 Go binary — it holds no data and signs no agreements. If you need a BAA, DPA, or equivalent for a cloud LLM provider, negotiate it directly with the provider on your provider account. For regulated workloads, the safest path is to deploy with Ollama on infrastructure you already have compliance coverage for, accepting the local-model quality tradeoff in limitation 7.

---

## 7. Local models underperform on this task today

Vens asks the LLM to return structured JSON with four component scores per CVE. Small local models (under ~7B parameters) frequently emit malformed JSON or produce flat, uniform scores regardless of input. Smaller batches (`--llm-batch-size 3–5`) cut down the malformed JSON, but they do not fix the quality gap.

Larger local models are not a safe fix either: in the [benchmark](https://github.com/venslabs/vens-benchmark), the local models tried through Ollama all scored at or below a constant-guess baseline on the context task. If you need air-gapped **and** high quality, that is a real gap right now.

On cloud, the benchmark-backed picks are `claude-sonnet-4-6` (most accurate and stable) and `gpt-5.4-mini` (best value, run it a few times); `gemini-2.5-flash-lite` is fine only for rough triage. See [Choosing a model](choosing-a-model.md).

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
