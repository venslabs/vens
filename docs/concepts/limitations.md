# Limitations — what Vens deliberately does not guarantee

**Who this is for:** anyone who needs to defend an adoption decision to a CISO, an auditor, or a skeptical engineering team.
**By the end of this page:** you know the honest shape of what Vens cannot promise, so you can scope how you use it.

Vens is a pragmatic prioritization tool, not a certification or a deterministic scoring engine. The list below is the set of things we chose **not** to promise, and why.

---

## 1. Scores are not byte-reproducible across runs

Even at `--llm-temperature 0.0` and with `--llm-seed`, cloud LLM providers do not expose true deterministic decoding, and provider-side models get silently updated. Between runs with the same config and model, an answer can change: its factor's level moves, the score with it, and the severity when the likelihood or the impact crosses a band boundary. vens does not promise a drift figure.

Mitigations Vens applies:

- The model never gives a number. It picks a named answer from a closed list for each question, and vens computes every level, the severity and the score in Go: the same answers always give the same rating.
- Same prompts, same schemas, same question order on every run.

If you need strict reproducibility for audit evidence at a point in time, pin a local Ollama model tag (model tags are immutable on disk), pass `--llm-temperature 0 --llm-seed <n>`, and archive `--debug-dir` output alongside the VEX. Together they give you a byte-exact record.

You can also pass [`--attest`](../reference/generate.md#-attest) to write a CDXA sidecar that records, per CVE, the model, seed, temperature (recorded only when the flag is passed), and SHA-256 hashes of the prompt, scan report and `config.yaml`, plus the raw response. It captures the evidence to reproduce a run later. Pass [`--attest-signing-key`](../reference/generate.md#-attest-signing-key-path) to JSF-sign that sidecar so a consumer who has your public key can detect edits to the sidecar; the VEX itself is not signed. Without a signing key it remains point-in-time evidence, not a cryptographic signature.

---

## 2. Benchmarked for model choice, not calibrated to your outcomes

There is now a public benchmark, [vens-benchmark](https://github.com/venslabs/vens-benchmark), measuring how 12 LLMs do the vens scoring task: predicting a CVE's severity and reacting when the context changes. It is what backs the model advice in [Choosing a model](choosing-a-model.md) and the [writeup](../blog/posts/which-llm-should-score-your-cves.md).

The benchmark ran the scoring of earlier versions, where the model returned four numbers per CVE. It has not been rerun on the closed questions of v0.7.0, so its figures describe the models, not the current rating.

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

`data_subjects`, `detection` and `traceability` go further: vens applies them exactly as declared, without showing them to the model, so nothing questions them. Declaring `detection` as `logged_and_reviewed` where nobody reviews the logs lowers Intrusion detection on every finding. The attestation records only a hash of `config.yaml`, and it is not signed.

Quality also depends on the model you run. A weak model produces weak scores even with perfect context, and the [benchmark](https://github.com/venslabs/vens-benchmark) shows the spread between models is large. See [Choosing a model](choosing-a-model.md) for the ones that hold up.

---

## 4. No `analysis` block in the output VEX

The CycloneDX VEX spec allows per-vulnerability `analysis.state`, `analysis.justification`, `analysis.detail`. **Vens does not emit any of these.** The output carries only the OWASP rating (score, severity, vector). Rationale:

- The LLM reasoning is not stable enough across runs to be embedded as a durable CycloneDX `justification` — that field is intended for human assertions.
- Keeping the VEX strictly to numeric scoring means downstream tools can ingest it without trust assumptions about free-text fields.

If you need a justification record (for audit), use `--debug-dir`, or pass [`--attest`](../reference/generate.md#-attest) to capture the per-CVE reasoning as structured CDXA claims (predicate plus reasoning) in a sidecar file, kept out of the VEX so downstream tools still ingest a clean document. See [`--debug-dir`](../reference/generate.md#-debug-dir-path).

---

## 5. Vens sends data to third-party LLM providers (unless you use Ollama)

When you pick OpenAI, Anthropic or Google AI, every call sends that provider a batch of CVEs — with title, description, package metadata — and the parts of your `config.yaml` the questions show, including the `notes` field. Vens does not filter, redact, or negotiate data handling terms on your behalf.

See [Privacy and data flow](privacy-and-data-flow.md) for the full list of what is sent, and use [Ollama locally](../getting-started/installation.md#configure-an-llm-provider) when this is not acceptable.

---

## 6. No HIPAA BAA or similar legal agreements

Vens itself is an MIT-ish Apache 2.0 Go binary — it holds no data and signs no agreements. If you need a BAA, DPA, or equivalent for a cloud LLM provider, negotiate it directly with the provider on your provider account. For regulated workloads, the safest path is to deploy with Ollama on infrastructure you already have compliance coverage for; read limitation 7 on local models first.

---

## 7. Local models did poorly on the earlier scoring

Up to v0.6, vens asked the LLM for four component scores per CVE in structured JSON. Small local models (under ~7B parameters) frequently emitted malformed JSON or flat, uniform scores regardless of input. Smaller batches (`--llm-batch-size 3–5`) cut down the malformed JSON, but did not fix the quality gap. Larger local models were not a safe fix either: in the [benchmark](https://github.com/venslabs/vens-benchmark), which ran that scoring (limitation 2), the local models tried through Ollama all scored at or below a constant-guess baseline on the context task.

Since v0.7.0 the model picks, for each question, one named answer per CVE from a closed list. How local models do on these questions has not been measured. If you need an air-gapped setup, read a local model's answers on your own scans (`--debug-dir`) before you rely on its ratings.

On cloud, the benchmark-backed picks are `claude-sonnet-4-6` (most accurate and stable) and `gpt-5.4-mini` (best value, run it a few times); `gemini-2.5-flash-lite` is fine only for rough triage. These come from the benchmark of the earlier scoring (limitation 2). See [Choosing a model](choosing-a-model.md).

---

## 8. No built-in cost control or budget gate

Vens makes LLM calls and does not know how much they cost. There is no `--max-spend` flag, no per-run budget, no rate-limit other than the provider's. Monitor billing on your provider dashboard, and start with small batches in CI before scaling out.

Since v0.7.0 each batch makes one call per question, so a run makes several calls per batch: on the quickstart example (45 CVEs, batches of 10), 41 calls before any retry, 7 questions in each of 5 batches and 6 adjustments, as the mock model makes them. The run summary counts every call, per question.

---

## 9. No reachability analysis, and no applicability check

Vens reasons from CVE metadata (id, title, description, severity, package) and the CVSS vectors in the scanner's report, plus your text-described context. It **does not** inspect your source code, build graph, call graph, or runtime. If a CVE lives in a code path your build never executes, Vens will only know about it if you mention it in `notes` or if the CVE description makes it obvious.

vens does not handle reachability: it has no reachability check of its own, asks the model no reachability question, and publishes no VEX status, from a config entry, an upstream VEX, a note or an answer. A CVE whose vulnerable code never runs keeps the rating its answers give, and a reachability verdict in `notes` reaches it only through the model's other answers. With the likelihood at 4.25 or above (limitation 10), such a CVE is never published as `info` and rates through OWASP's matrix like any other, `low` at best with a LOW impact. The loss levels that come from the scan are the CVSS v3 vectors': Loss of confidentiality, integrity and availability take the worst value the CVE's usable v3 vectors give each axis, and Privacy violation is 3 when they give `C:N`. Fixed rules and your config set other levels without asking the model, such as Non-compliance at 2 when no framework is declared and Privacy violation at 3 when `data_subjects` is `none` or `one_individual`.

Nor does vens check whether a CVE applies to your image: no finding is set aside, and no loss floored, because its description names a platform, a runtime version or a package your image does not have, or because its path needs a listening service and `listener` is `absent`. `listener` is only shown to the model, and every CVE in the scanner's report is rated.

For true reachability signals, use a dedicated tool (Semgrep Code, Snyk Reachability, Endor Labs…) beside Vens: Vens does not read its conclusions as a status. See [Alternatives](alternatives.md).

---

## 10. Likelihood is never LOW, and the severity never `info`

vens sets Skill level to 9 for every finding, OWASP's worst-case threat agent, since no field declares the attackers' skill, and Ease of discovery and Awareness to 9: each finding is a published CVE that a scanner matched. With those three at 9, the likelihood never falls below 4.25, which is MEDIUM. So `info`, OWASP's Note, never occurs, and a `low` severity needs a LOW impact. With `detection` left out, Intrusion detection is 9 and the floor is 5.25.

---

## 11. The impact basis follows your declared context

OWASP rates on the business impact when the assessor has good business impact information, and on the technical impact otherwise. vens takes your declared context as true, so a declared `data_subjects` is taken as the business information OWASP's rule asks for, and vens rates every finding on its business impact; without it, on its technical impact. Nothing checks that declaration. Of the four business levels, Financial damage and Reputation damage are what `business_criticality` declares at the CVE's worst technical loss, the highest of its Loss of confidentiality, integrity and availability (limitation 12). Non-compliance and Privacy violation are the model's answers on the context you declared, Privacy violation capped by `data_subjects`, except where a rule sets them without asking: Non-compliance is 2 when no framework is declared, and Privacy violation 3 when `data_subjects` is `none` or `one_individual` or the CVE's usable CVSS v3 vectors give `C:N`. On the business basis, a business impact lower than the technical impact can lower the severity: it does when it falls in a lower band, as on OWASP's own worked example, High on the technical impact and Low on the business impact; in the same band it lowers the score alone. The 9s the missing-input rule sets for a CVE with no usable CVSS v3 vector reach the severity only as a high worst technical loss, at which Financial damage and Reputation damage take your declared worst case.

Each VEX vulnerability names its basis in the `vens:impact-basis` property. The vector does not say which impact the severity and the score were read on, so a tool that recomputes them from the vector alone must read that property, or it can disagree with vens. Dependency-Track 5.1 does not read it.

---

## 12. Financial damage and Reputation damage follow one declaration

vens does not ask the model what an exploit would cost the business. `business_criticality` declares it: each value states, in OWASP's options, the worst Financial damage and Reputation damage an exploit of the service could cost at a low, a medium and a high worst technical loss, and vens reads the declaration at the CVE's worst technical loss: the band of the highest of its Loss of confidentiality, integrity and availability, not OWASP's technical impact, which averages four factors (see **[How vens rates a CVE](cvss-vs-owasp.md#how-vens-rates-a-cve)**). What follows:

- At a high worst technical loss the declaration is your worst case. The steps down to medium and low are vens's customization of OWASP's options, not calibrated against experts' ratings: their direction is OWASP's, "The business impact stems from the technical impact", their sizes are not.
- One value sets both factors: a service whose financial and reputational consequences differ cannot declare them apart.
- `notes` and the CVE's description no longer reach Financial damage or Reputation damage: the value you choose is the only lever.
- With no compliance framework declared, Non-compliance is 2, and a HIGH business impact needs `critical`, a high worst technical loss and `data_subjects` of `hundreds` or more.
- A `high` service with no framework tops out at a business impact of 5.75, MEDIUM: (7 + 5 + 2 + 9) / 4.
- A `low` service never reaches a HIGH business impact.
- On a `critical` service, a `C:H` CVE gets Financial damage 9 and Reputation damage 9 even on public data: OWASP rates extensive non-sensitive data disclosed 6, so the worst technical loss is high.
- A CVE with no usable CVSS v3 vector counts as a high worst technical loss, so on the business basis it takes the declared worst case.
- Motive is shown `business_criticality` with its meaning, and `critical` no longer says compliance-required. On a `critical` service the Motive request differs from the one earlier builds sent, so answers recorded with them replay exactly for the impact, not for Motive.

---

## 13. Pre-1.0 — API surface may change

Vens is under active development and has not reached a 1.0 release yet. The CLI flags and `config.yaml` schema may evolve between minor versions. Pin a specific version in CI (`go install github.com/venslabs/vens/cmd/vens@vX.Y.Z`) and read the release notes before upgrading.

Since v0.7.0, `config.yaml` carries `schema_version`, and vens refuses a file written for another version instead of reading it differently. The version goes up only when a file valid today would change meaning or stop loading; a new optional field whose omission keeps today's behaviour, or a new value in a list, does not raise it. A field no factor reads any more stays in the schema, documented as moving nothing, as `audit_requirement` does, until the version goes up for another reason. Unknown keys are refused too, so a vens from v0.7.0 on fails on a file that uses a field it does not know, rather than scoring it differently. vens v0.6 and earlier ignore unknown keys: they do not refuse a schema-2 file for its unknown keys and score it the old way, so upgrade every runner that reads the file before you migrate it.

---

## See also

- **[Privacy and data flow](privacy-and-data-flow.md)**
- **[CVSS vs OWASP contextual](cvss-vs-owasp.md)**
- **[Alternatives](alternatives.md)**
- **[Troubleshooting](../troubleshooting.md)**
