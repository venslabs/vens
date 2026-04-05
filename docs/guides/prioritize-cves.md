# Prioritize a backlog of 300 CVEs

**Who this is for:** security engineers staring at a massive CVE report and asking _"which ones do I patch first?"_.
**By the end of this page:** you have a ranked list of the CVEs that actually matter for your system, and a suppressed view of the rest.

This is the most common use case for Vens. It takes ~3 minutes end to end.

---

## The problem

A typical Trivy scan of a production image returns 150–500 CVEs. Most of them:

- Are not reachable in your runtime
- Exploit features you don't use
- Are mitigated by your existing controls (WAF, network segmentation, read-only filesystem…)
- Touch low-sensitivity data

Without context, every CVE looks equally urgent. You waste engineering time patching things that don't matter, and you miss the few that really do.

---

## The workflow

```
┌────────────┐   ┌─────────┐   ┌──────────┐   ┌────────────┐   ┌──────────┐
│  trivy     │──▶│  vens   │──▶│  jq      │──▶│  patch     │──▶│  trivy   │
│  scan      │   │ generate│   │  sort    │   │  top N     │   │  --vex   │
└────────────┘   └─────────┘   └──────────┘   └────────────┘   └──────────┘
```

---

## Step 1 — Scan

```bash
trivy image my-registry/my-app:v1.2.3 \
  --format json \
  --severity MEDIUM,HIGH,CRITICAL \
  --output report.json
```

!!! tip
    Include `MEDIUM` severity. Vens will upgrade some of them to high if your context warrants it — this is where hidden risk often lives.

---

## Step 2 — Describe your system once

Create `config.yaml` with the real characteristics of the workload:

```yaml
project:
  name: "checkout-api"
  description: "Public-facing checkout service, handles payment card data"

context:
  exposure: "internet"
  data_sensitivity: "critical"       # payment card data
  business_criticality: "critical"   # revenue-critical
  availability_requirement: "high"
  compliance_requirements:
    - "PCI-DSS"
    - "GDPR"
  controls:
    waf: true
    ddos_protection: true
    segmentation: true
    siem: true
  notes: "Behind AWS ALB, WAF with OWASP ruleset, deployed across 3 AZs"
```

This file lives in your repo. You write it **once**, version it with the service, and re-use it on every scan. See [Describe your context](configuration.md) for every field.

---

## Step 3 — Generate the VEX

```bash
vens generate \
  --config-file config.yaml \
  report.json \
  output.vex.json
```

Runtime: ~1 minute for 300 CVEs with `gpt-4o`.

---

## Step 4 — Get your top 10

```bash
jq '[.vulnerabilities[] | {
       id,
       score: .ratings[0].score,
       severity: .ratings[0].severity,
       why: .analysis.detail
     }]
    | sort_by(-.score)
    | .[0:10]' output.vex.json
```

Example output:

```json
[
  {
    "id": "CVE-2026-0915",
    "score": 64,
    "severity": "critical",
    "why": "Leaks payment card data. Exposed to internet, no mitigation by WAF."
  },
  {
    "id": "CVE-2025-4477",
    "score": 56,
    "severity": "high",
    "why": "Remote code execution in HTTP parser. Reachable from internet despite WAF."
  }
]
```

**These are the CVEs you patch first.** Everything below a threshold (e.g. score < 20) can be deferred or suppressed.

---

## Step 5 — Suppress the noise in future scans

Feed the VEX back into Trivy to hide the CVEs Vens marked as _not relevant_:

```bash
trivy image my-registry/my-app:v1.2.3 \
  --vex output.vex.json \
  --show-suppressed
```

CVEs with `analysis.state: not_affected` disappear from the main output. Developers see only what matters.

!!! note
    Grype supports `--vex` with a similar flag. Dependency-Track can also ingest the VEX file directly.

---

## Put it in CI

A typical GitHub Actions step:

```yaml
- name: Scan image
  run: trivy image $IMAGE --format json --output report.json

- name: Generate contextual VEX
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  run: vens generate --config-file .vens/config.yaml report.json vex.json

- name: Fail on high contextual risk
  run: |
    HIGH_COUNT=$(jq '[.vulnerabilities[] | select(.ratings[0].score >= 40)] | length' vex.json)
    if [ "$HIGH_COUNT" -gt 0 ]; then
      echo "::error::$HIGH_COUNT CVEs above contextual threshold"
      jq '[.vulnerabilities[] | select(.ratings[0].score >= 40) | {id, score: .ratings[0].score}]' vex.json
      exit 1
    fi

- name: Upload VEX
  uses: actions/upload-artifact@v4
  with:
    name: vex
    path: vex.json
```

This fails the build only when there is **real** risk, not when the scanner finds a CVSS 7 in a component you don't execute.

---

## What this changes

| | Without Vens | With Vens |
|---|---|---|
| Engineering time per release | hours triaging 300 CVEs | minutes reviewing top 10 |
| CI failures | flaky (every new CVE blocks) | meaningful (only real risk blocks) |
| Backlog | always growing | stays manageable |
| Developer trust | "the scanner is noise" | "this score means something" |

---

## Next

- Refine your context file: **[Describe your context](configuration.md)**
- Understand the scores: **[CVSS vs OWASP contextual](../concepts/cvss-vs-owasp.md)**
