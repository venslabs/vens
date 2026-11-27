# Prioritize a CVE backlog

**Who this is for:** security engineers staring at a massive CVE report and asking _"which ones do I patch first?"_.
**By the end of this page:** you have your CVEs ranked by their risk in your context, and the top of the list to review first.

This is the main use case for Vens.

---

## The problem

A Trivy or Grype scan of a production image hands you a long list of CVEs. Some of them may:

- Not be reachable in your runtime
- Exploit features you don't use
- Be mitigated by your existing controls (WAF, network segmentation, read-only filesystem…)
- Touch low-sensitivity data

A CVE's base score is the same wherever the component runs, so it says none of this about your deployment.

---

## The workflow

```
┌────────────┐   ┌─────────┐   ┌──────────┐   ┌────────────┐   ┌──────────┐
│  trivy     │──▶│  vens   │──▶│  jq      │──▶│  patch     │──▶│  vens    │
│  scan      │   │ generate│   │  sort    │   │  top N     │   │  enrich  │
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
schema_version: 2

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
  listener: "present"
  data_subjects: "millions"          # card holders
  detection:
    network: "logged_and_reviewed"   # WAF and ALB logs, alerting on-call
    host: "logged"
    application: "logged_and_reviewed"
  traceability: "per_individual"     # every action logged with the user's id
  controls:
    waf: true
    ddos_protection: true
    segmentation: true
  notes: "Behind AWS ALB, WAF with OWASP ruleset, deployed across 3 AZs"
```

This file lives in your repo. You write it **once**, version it with the service, and re-use it on every scan. Declare `data_subjects`, `detection` and `traceability` for what is in place: each one left out takes a fallback, with a warning at load. See [Describe your context](configuration.md) for every field.

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

`--sbom-serial-number` is required — pass the `serialNumber` of the CycloneDX SBOM paired with this scan so each `affects` in the VEX resolves back to that SBOM via BOM-Link.

Runtime grows with the number of distinct CVEs: each batch of 10 makes one call per question, up to 7, and the run summary counts every call.

---

## Step 4 — Get your top 10

Each vulnerability of the VEX carries one `vens:impact-provenance` property. It is `cvss-v3` when its losses of confidentiality, integrity and availability were read from the CVE's CVSS v3 vectors, and `missing-cvss-v3-fallback` when the CVE has no usable v3 vector, so the missing-input rule set all three to 9 (the run counts it as `cvss_v3_missing`, and `--strict` refuses it). Split on it first:

```bash
jq '[.vulnerabilities[] | {
       id,
       impact: ([.properties[]? | select(.name == "vens:impact-provenance") | .value] | if length == 1 and (.[0] == "cvss-v3" or .[0] == "missing-cvss-v3-fallback") then .[0] else error("not exactly one valid vens:impact-provenance") end),
       score: .ratings[0].score,
       severity: .ratings[0].severity,
       vector: .ratings[0].vector
     }]
    | {
        cvss_v3: [.[] | select(.impact == "cvss-v3")]
          | sort_by({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[.severity], -.score, .id)
          | .[0:10],
        impact_unknown: [.[] | select(.impact == "missing-cvss-v3-fallback")] | sort_by(.id)
      }' output.vex.json
```

A VEX from an older vens carries no marker; the filter fails on it instead of dropping the finding. The marker is provenance, not a claim of human review, so the CVSS-v3 list is named `cvss_v3`, not `assessed`.

A consumer implementing vens prioritisation must present separate lists: findings marked `cvss-v3`, and "impact unknown — manual triage required." Findings marked `missing-cvss-v3-fallback` belong in the latter. The lists have no cross-list urgency order. Unknown-impact findings retain their numerical ratings, severity (the worst case on the technical impact basis, and on the business basis Financial damage and Reputation damage at the worst case `business_criticality` declares), gate contributions and totals; their identifiers order presentation only. Legitimately vector-derived maximum-impact values stay in the `cvss_v3` list.

Among findings marked `cvss-v3`, priority is matrix severity descending, then L×I descending, then published vulnerability identifier ascending by UTF-8 bytes; equal severity and product mean equal urgency, and the identifier orders presentation only. The severity comes from OWASP's matrix, not from the score, so a `high` can score below a `medium`. The impact levels the missing-input rule supplies are fail-safe gate values, not evidence of relative impact or urgency: a fallback CVE's `critical` says its impact is unknown, not that it outranks a CVSS-v3-derived one.

Each vulnerability also names, in its `vens:impact-basis` property, the impact its severity and score are read on, the same for the whole run: `business` here, the `config.yaml` above declaring `data_subjects`, and `technical` for a config that does not (see **[How vens rates a CVE](../concepts/cvss-vs-owasp.md#how-vens-rates-a-cve)**). On the business basis, the 9s the missing-input rule sets reach the severity only as a high worst technical loss, at which Financial damage and Reputation damage take the worst case `business_criticality` declares.

Example output (illustrative):

```json
{
  "cvss_v3": [
    {
      "id": "CVE-XXXX-YYYY",
      "impact": "cvss-v3",
      "score": 70.125,
      "severity": "critical",
      "vector": "SL:9/M:9/O:9/S:9/ED:9/EE:9/A:9/ID:3/LC:7/LI:7/LAV:7/LAC:9/FD:9/RD:9/NC:7/PV:9"
    },
    {
      "id": "CVE-XXXX-ZZZZ",
      "impact": "cvss-v3",
      "score": 33.125,
      "severity": "high",
      "vector": "SL:9/M:4/O:7/S:9/ED:9/EE:3/A:9/ID:3/LC:2/LI:3/LAV:5/LAC:1/FD:7/RD:5/NC:5/PV:3"
    }
  ],
  "impact_unknown": [
    {
      "id": "CVE-XXXX-WWWW",
      "impact": "missing-cvss-v3-fallback",
      "score": 55.6875,
      "severity": "critical",
      "vector": "SL:9/M:4/O:9/S:9/ED:9/EE:9/A:9/ID:8/LC:9/LI:9/LAV:9/LAC:9/FD:9/RD:9/NC:2/PV:7"
    }
  ]
}
```

**Review these CVEs first.** The rating is an input to that review, not a verdict: how well it matches real risk on your systems is not measured, and vens runs no reachability check of its own (see [Limitations](../concepts/limitations.md)). A CVE in the low band still needs a look before you defer it.

!!! tip "Where is the reasoning?"
    Pass `--attest` for a sidecar whose claims hold, per CVE, one line per question answered, or `--debug-dir ./debug` to dump every prompt and response to disk, with `answers.json`. The reasoning is intentionally not embedded in the VEX file — VEX stays a pure CycloneDX document.

---

## Step 5 — Feed the scores back to your tools

Scanner `--vex` flags are not a route for these scores. Trivy reads a VEX for `analysis.state` values such as `not_affected`, and vens emits no analysis block at all (see [Limitations](../concepts/limitations.md)). `trivy image ... --vex output.vex.json` leaves the output unchanged, and `--show-suppressed` lists nothing. Grype takes VEX in CSAF or OpenVEX form, not CycloneDX, so a vens VEX gives it nothing either.

Two routes that do work:

**Trivy JSON.** `vens enrich` copies each OWASP score, severity band, and vector onto the matching vulnerability, under `Custom`:

```bash
vens enrich --vex output.vex.json --output enriched-report.json report.json

jq '.Results[]?.Vulnerabilities[]? | {VulnerabilityID, Severity, owasp_severity: .Custom.owasp_severity, owasp_score: .Custom.owasp_score}' enriched-report.json
```

`Severity` and the CVSS block stay exactly as Trivy wrote them, so read `Custom.owasp_severity` in whatever consumes the JSON next. Reach for the raw `Custom.owasp_score` only when you need the number itself — it is likelihood × impact on a 0–81 scale, a vens extension, and the severity does not come from it.

!!! note "From v0.6.0"
    `owasp_severity` is written from v0.6.0 on. v0.5.0 and earlier don't emit it.

**Dependency-Track 5.1+.** It picks up the OWASP rating from the VEX and shows it on each finding. It reads neither the `vens:impact-provenance` and `vens:impact-basis` properties nor the order above, so it cannot keep the two lists apart. See [Send the scores to Dependency-Track](dependency-track.md).

!!! note
    Vens writes ratings only, never a `not_affected` state, so there is nothing for a scanner to suppress. To hide CVEs below a contextual threshold, filter the VEX with `jq` as shown in [Put it in CI](#put-it-in-ci), or drop low-score entries in your dashboard.

---

## Put it in CI

For a turnkey Action, see [GitHub Actions integration](github-actions.md). The manual approach below works too:

```yaml
- name: Install Vens
  run: go install github.com/venslabs/vens/cmd/vens@v0.6.0

- name: Scan image
  run: trivy image $IMAGE --format json --output report.json

- name: Generate contextual VEX
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    OPENAI_MODEL: gpt-5.4-mini               # required alongside OPENAI_API_KEY
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
    # Gate on the severity: it's the field vens commits to for gates and the one
    # vens-action's fail-on-severity reads. It comes from OWASP's matrix and is never info.
    HIGH_COUNT=$(jq '[.vulnerabilities[] | select(any(.ratings[]?; .method == "OWASP" and (.severity | IN("high", "critical"))))] | length' vex.json)
    if [ "$HIGH_COUNT" -gt 0 ]; then
      echo "::error::$HIGH_COUNT CVEs above contextual threshold"
      jq '[.vulnerabilities[] | {id} + (.ratings[]? | select(.method == "OWASP" and (.severity | IN("high", "critical"))) | {score, severity})]' vex.json
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

This step fails the build when at least one vulnerability in the VEX carries an OWASP rating of `high` or `critical`, the severities in the two `IN(...)` filters; edit both to gate on other severities. vens-action's `fail-on-severity` does the same for the level you set and every level above it: see the [GitHub Actions guide](github-actions.md).

---

## Next

- Refine your context file: **[Describe your context](configuration.md)**
- Understand the scores: **[CVSS vs OWASP contextual](../concepts/cvss-vs-owasp.md)**
