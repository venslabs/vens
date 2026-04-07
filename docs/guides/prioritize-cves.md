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
SBOM_UUID="urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')"

vens generate \
  --config-file config.yaml \
  --sbom-serial-number "$SBOM_UUID" \
  report.json \
  output.vex.json
```

`--sbom-serial-number` is required — it feeds the BOM-Link references in the VEX. Store the UUID alongside the service if you want stable BOM-Links across runs.

Runtime: ~1 minute for 300 CVEs with `gpt-4o`.

---

## Step 4 — Get your top 10

```bash
jq '[.vulnerabilities[] | {
       id,
       score: .ratings[0].score,
       severity: .ratings[0].severity,
       vector: .ratings[0].vector
     }]
    | sort_by(-.score)
    | .[0:10]' output.vex.json
```

Example output:

```json
[
  {
    "id": "CVE-XXXX-YYYY",
    "score": 64,
    "severity": "critical",
    "vector": "SL:8/M:8/O:8/S:8/ED:7/EE:7/A:7/ID:3/LC:9/LI:9/LAV:9/LAC:9/FD:9/RD:9/NC:9/PV:9"
  },
  {
    "id": "CVE-2025-4477",
    "score": 56,
    "severity": "high",
    "vector": "SL:7/M:7/O:7/S:7/ED:7/EE:7/A:7/ID:3/LC:8/LI:8/LAV:8/LAC:8/FD:8/RD:8/NC:8/PV:8"
  }
]
```

**These are the CVEs you patch first.** Everything below a threshold (e.g. score < 20) can be deferred or suppressed.

!!! tip "Where is the reasoning?"
    Vens prints the LLM's per-CVE reasoning to stderr as it runs, and dumps every prompt and response to disk if you pass `--debug-dir ./debug`. The reasoning is intentionally not embedded in the VEX file — VEX stays a pure CycloneDX document. Use `--debug-dir` for audits.

---

## Step 5 — Feed the VEX back to your scanner / platform

Point Trivy at the VEX so CVEs are displayed with their contextual OWASP rating alongside the native scanner severity:

```bash
trivy image my-registry/my-app:v1.2.3 \
  --vex output.vex.json \
  --show-suppressed
```

Grype supports `--vex` as well. Dependency-Track can ingest the VEX file directly.

!!! note
    Vens emits OWASP ratings on every CVE — not a `not_affected` analysis state. To suppress CVEs below a contextual risk threshold, filter the VEX with `jq` as shown in [Put it in CI](#put-it-in-ci) below, or pre-process the VEX in your dashboard to drop low-score entries.

---

## Put it in CI

A typical GitHub Actions step:

```yaml
- name: Install Vens
  run: go install github.com/venslabs/vens/cmd/vens@v0.3.0

- name: Scan image
  run: trivy image $IMAGE --format json --output report.json

- name: Generate contextual VEX
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    OPENAI_MODEL: gpt-4o               # required alongside OPENAI_API_KEY
    # Stable per-service UUID so BOM-Links don't churn between builds.
    # Store it as a repo variable instead of hardcoding once you have more than one service.
    SBOM_UUID: urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79
  run: |
    vens generate \
      --config-file .vens/config.yaml \
      --sbom-serial-number "$SBOM_UUID" \
      report.json vex.json

- name: Fail on high contextual risk
  run: |
    HIGH_COUNT=$(jq '[.vulnerabilities[] | select(.ratings[0].score >= 40)] | length' vex.json)
    if [ "$HIGH_COUNT" -gt 0 ]; then
      echo "::error::$HIGH_COUNT CVEs above contextual threshold"
      jq '[.vulnerabilities[] | select(.ratings[0].score >= 40) | {id, score: .ratings[0].score}]' vex.json
      exit 1
    fi

- name: Upload VEX
  uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
  with:
    name: vex
    path: vex.json
```

!!! tip "Air-gapped CI"
    Swap the `Install Vens` step for a prebuilt binary download (see [Installation](../getting-started/installation.md#option-3-prebuilt-binary)) and replace the OpenAI env vars with `OLLAMA_MODEL` + `OLLAMA_HOST` pointing at your internal Ollama server. Nothing else in the pipeline changes.

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
