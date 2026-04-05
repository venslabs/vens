# Vens

**Stop treating all vulnerabilities equally.** Vens turns generic CVSS scores into **contextual OWASP risk scores** tailored to _your_ system, and outputs a standards-compliant **CycloneDX VEX** file.

Give Vens a Trivy or Grype report plus a short description of your system, and it tells you which CVEs actually matter.

---

## What you get

| Example scenario | Before Vens | After Vens |
|---|---|---|
| Generic RCE in a library whose vulnerable code path is never executed in your build | CVSS **8.8 HIGH** | OWASP **10.0 LOW** — not reachable in your runtime |
| Information leak in a request handler that processes PII under GDPR | CVSS **5.3 MEDIUM** | OWASP **52.0 HIGH** — leaks PII in a GDPR workload |
| 300 CVEs in your report | All urgent | ~30 actually urgent |

*The two rows above are illustrative scenarios to show how contextual scoring moves a CVSS score in both directions. Actual scores depend on your `config.yaml` and the LLM model you use.*

**Result:** fix what matters. Stop wasting cycles on CVEs that don't apply to your system.

---

## How it works

```
┌───────────┐     ┌──────────────┐     ┌────────────────┐     ┌──────────────┐
│  Trivy    │     │  config.yaml │     │                │     │ CycloneDX    │
│  or       │────▶│  (your       │────▶│   vens         │────▶│ VEX with     │
│  Grype    │     │  context)    │     │   generate     │     │ OWASP scores │
└───────────┘     └──────────────┘     └────────────────┘     └──────────────┘
                                              │
                                              ▼
                                       ┌──────────────┐
                                       │  LLM         │
                                       │  (OpenAI,    │
                                       │  Anthropic,  │
                                       │  Ollama,     │
                                       │  Google AI)  │
                                       └──────────────┘
```

Vens reads your scanner report, combines it with _your_ system context (exposure, data sensitivity, compliance, controls), and asks an LLM to compute a real risk score for every CVE — one at a time.

---

## Start here

<div class="grid cards" markdown>

- :material-download: **[Install Vens](getting-started/installation.md)**
  Three commands, three options.

- :material-rocket-launch: **[Quickstart (5 minutes)](getting-started/quickstart.md)**
  Your first VEX file from a real image.

- :material-sort-descending: **[Prioritize a CVE backlog](guides/prioritize-cves.md)**
  The most common use case.

- :material-cog: **[Describe your context](guides/configuration.md)**
  The step that makes scores accurate.

</div>

---

## Is Vens for me?

Vens is built for:

- **Security engineers** drowning in CVE backlogs from Trivy / Grype / Dependency-Track.
- **DevSecOps teams** who need machine-readable VEX to suppress noise in CI.
- **Lead security architects** who want risk scores that reflect _business impact_, not generic CVSS.

Vens is **not** a scanner. You still need Trivy or Grype to find CVEs — Vens tells you which ones to care about.

---

## Before you commit

Before adopting Vens in production, read these three short pages — they tell you exactly what you're getting into:

- **[Privacy and data flow](concepts/privacy-and-data-flow.md)** — what is (and isn't) sent to your LLM provider.
- **[Limitations](concepts/limitations.md)** — the things Vens deliberately does not guarantee (reproducibility, benchmarks, BAA, and more).
- **[Vens vs alternatives](concepts/alternatives.md)** — where Vens sits in the ecosystem (vexctl, vexllm, Dependency-Track, reachability tools).

---

## License

Apache 2.0 — [LICENSE](https://github.com/venslabs/vens/blob/main/LICENSE)
