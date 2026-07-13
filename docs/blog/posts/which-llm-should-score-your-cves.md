---
date: 2026-07-13
slug: which-llm-should-score-your-cves
---

# Which LLM should score your CVEs?

Your scanner finds 400 CVEs. Most don't matter for your system, but the CVSS score can't tell you which: it rates the bug, not your setup.

EPSS and the CISA KEV list help (how likely a CVE is to be exploited, and whether it's exploited today). But they don't know your deployment: internet-facing or internal, holds user data or not, vulnerable code reachable or never run. That last part is the job people now give an LLM: read the scan plus a short context file, and adjust the score. [vens](https://github.com/venslabs/vens) does this. So which model do you run behind it? I tested 12.

**1. Reading a CVE is cheap.**
First test: read a CVE, predict its CVSS score (I reused the public CTIBench set). Lower error is better.

| Model | Error | $ per 200 CVEs |
|---|---|---|
| claude-sonnet-4-6 | 0.75 | $1.90 |
| gpt-5.5 | 0.75 | $4.12 |
| gpt-5.4-mini | 0.84 | **$0.48** |
| gemini-2.5-flash-lite | 1.15 | $0.07 |
| *constant guess* | 1.57 | $0 |

The two best tie. gpt-5.5 costs more than 2× the price for the same result, so skip it. A $0.48 model is almost as good. Don't overpay here. (One catch: these CVEs are likely in the models' training data, so this test is more about memory than reading. Good enough, not solved.)

**2. Context is where cheap models fail.**
Second test: change the context and check if the score moves the right way. A Log4Shell 10.0 that nothing can reach should drop to LOW, and 7 of 8 models do it. A token leak (6.5) on a public site full of user data should rise to HIGH, and all 8 do.

Those two are real CVEs, on purpose; the other context tests use made-up ones, so no model can lean on a score it already saw.

I also built a simple no-LLM rule as the baseline. Two cheap models (flash-lite, gpt-5.4-nano) never beat it. They look fine on the first test. On context they add nothing. Pick a model on accuracy alone and you get a tool that ignores the context you added it for.

**3. Some models fake it.**
When a model correctly ignores the "critical data" tag for a crash-only bug, is it reasoning, or just matching the words "denial of service"?

So I rewrote the descriptions to hide the impact words. One case still works: the model sees that tampering with an audit log is a real problem, with no keyword to lean on. But the crash case breaks: remove the words, and the score jumps back up. It was matching keywords. I almost didn't check.

(Local models: all four I tried were no better than a fixed guess. Not ready for this.)

**What to run:**
- **A score you can defend** → claude-sonnet-4-6. Best and most stable.
- **Cheap and good** → gpt-5.4-mini. Top results for $0.48, but run it a few times; it's not stable.
- **Rough sorting only** → gemini-2.5-flash-lite. $0.07, but weak on context.
- **Skip** → gpt-5.5 (too expensive) and gpt-5.4-nano.

The [paper](https://github.com/venslabs/vens-benchmark/blob/main/paper/vens-benchmark.pdf) has the full numbers and the limits. The [harness](https://github.com/venslabs/vens-benchmark) is public, so you can test any model, including your own.
