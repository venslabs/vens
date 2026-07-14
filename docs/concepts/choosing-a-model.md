# Choosing an LLM

**Who this is for:** anyone about to run Vens and wondering *which model to put behind it* — and whether the expensive one is worth it.
**By the end of this page:** you have a model to pick for your case, and you know where the cheap ones quietly fail.

Vens makes one LLM call per CVE batch, so the model is a direct cost and quality knob. We benchmarked 12 models on the two things Vens actually does — reading a CVE and using your context — in a companion project, [venslabs/vens-benchmark](https://github.com/venslabs/vens-benchmark). The full write-up, with confidence intervals and failure cases, is in the paper:

[**Which LLM Should Score Your CVEs?** (PDF)](../assets/vens-benchmark.pdf)

---

## Recommendation

| Your case | Model | Why |
|---|---|---|
| Signed / audited VEX | `claude-sonnet-4-6` | best accuracy, the most reproducible of the accurate models, on the cost/quality Pareto front |
| Best value | `gpt-5.4-mini` | top-tier accuracy at a fraction of the cost — but jittery run-to-run, so keep repeats and take the median |
| Throwaway triage | `gemini-2.5-flash-lite` | cheapest by far; over-rates and is weak on context — coarse sorting, not final scoring |
| Skip | `gpt-5.5`, `gpt-5.4-nano` | one is Pareto-dominated by sonnet (more expensive, no more accurate), the other is jittery and adds nothing over a rule engine |

Set the model with the provider's `*_MODEL` env var (`OPENAI_MODEL`, `ANTHROPIC_MODEL`, `GOOGLE_MODEL`, `OLLAMA_MODEL`) — see [`vens generate`](../reference/generate.md).

---

## Why two things get measured, not one

**CVE understanding** — can the model read a CVE and place its severity? This is nearly a solved, cheap problem: a $0.48 model ties a $4.12 one, and every 2026 model clears 2024's GPT-4.

**Context use** — does the model actually move the score when your `config.yaml` changes (exposure, data sensitivity, business criticality, controls)? This is where the money goes, and where cheap models fail *silently*: some diverge from a non-LLM rule engine by a median of zero — they add nothing over a lookup table while looking fine on the accuracy number.

---

## Local models

Not there yet. Every local model tested (via Ollama: `llama3.2`, `qwen2.5:7b`, `gemma2:9b`, `deepseek-r1:8b`) came out statistically indistinguishable from a constant-guess baseline — their confidence intervals overlap the 1.57 floor — and only the reasoning model engaged the context at all. For context-conditioned scoring today, a small local model is close to not using an LLM.

See the [paper](../assets/vens-benchmark.pdf) for the method, the two showcases (a 10.0 that ends LOW, a 6.5 that ends HIGH), and where the models (and the test itself) break.

---

## See also

- **[Limitations](limitations.md)** — what Vens deliberately does not do (including reachability)
- **[Vens vs. alternatives](alternatives.md)** — where Vens fits
- **[`vens generate`](../reference/generate.md)** — set the model and run it
