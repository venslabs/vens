# `vens enrich`

**Who this is for:** Trivy users who already have a Vens-generated VEX file and want to fold the contextual ratings back into a Trivy report.
**By the end of this page:** you know exactly what `vens enrich` consumes, what it emits, and when to use it.

---

## Synopsis

```
vens enrich --vex VEX_FILE [--output PATH] REPORT_FILE
```

`vens enrich` takes a Trivy JSON report and annotates every vulnerability the VEX document scored, adding `Custom.owasp_score`, `Custom.owasp_severity`, `Custom.owasp_vector` and, when the VEX vulnerability carries the `vens:impact-provenance` property, `Custom.owasp_impact_provenance` with its value (`cvss-v3` or `missing-cvss-v3-fallback`, see **[The VEX document](generate.md#the-vex-document)**). Matching is on the vulnerability ID alone, and only ratings whose method is OWASP are read. Trivy's own `Severity` and CVSS fields stay as they are, and nothing else in the report changes.

!!! note "From v0.6.0"
    `owasp_severity` is written from v0.6.0 on. v0.5.0 and earlier don't emit it.

```json
{
  "VulnerabilityID": "CVE-XXXX-YYYY",
  "Severity": "HIGH",
  "Custom": {
    "owasp_impact_provenance": "cvss-v3",
    "owasp_score": 39.1875,
    "owasp_severity": "high",
    "owasp_vector": "SL:9/M:4/O:9/S:9/ED:9/EE:9/A:9/ID:8/LC:2/LI:7/LAV:1/LAC:9/FD:3/RD:5/NC:7/PV:3"
  }
}
```

`Severity` still holds Trivy's value. Gate on `Custom.owasp_severity`, and sort by band rank then `Custom.owasp_score` — sorting on the band sorts strings alphabetically, so order the bands yourself and break ties by the score, likelihood × impact on a 0–81 scale. The band comes from OWASP's matrix, not from the score, so a `high` can score below a `medium`. Keep the rows whose `Custom.owasp_impact_provenance` is `missing-cvss-v3-fallback` in a separate "impact unknown" list, with no order across the two lists: see **[Get your top 10](../guides/prioritize-cves.md#step-4-get-your-top-10)**. If a CVE appears more than once in the VEX, the last OWASP rating wins.

Use it when your downstream tooling reads Trivy JSON directly and does not know how to parse a separate CycloneDX VEX.

---

## Arguments

| Argument | Description |
|---|---|
| `REPORT_FILE` | Path to a Trivy JSON report (positional, required). |

---

## Flags

### `--vex <path>` (required)

Path to a CycloneDX VEX document produced by [`vens generate`](generate.md).

### `--output <path>`

Path to write the enriched report. Default: stdout.

---

## Examples

### Write the enriched report to a file

```bash
export OPENAI_API_KEY=sk-...

SBOM_UUID="urn:uuid:$(uuidgen | tr '[:upper:]' '[:lower:]')"

trivy image nginx:1.25 --format json --output report.json
vens generate --config-file vens.yaml --sbom-serial-number "$SBOM_UUID" report.json vex.json
vens enrich --vex vex.json --output enriched-report.json report.json
```

Only `vens generate` calls the LLM. `vens enrich` is a local file transform and needs no credentials.

The `enriched-report.json` is still a valid Trivy JSON report, so you can feed it to any tool that understands Trivy output.

### Pipe to another tool

```bash
vens enrich --vex vex.json report.json \
  | jq '.Results[]?.Vulnerabilities[]? | {VulnerabilityID, Severity, owasp_severity: .Custom.owasp_severity, owasp_score: .Custom.owasp_score}'
```

`Severity` is Trivy's own rating, unchanged. `owasp_severity` is the contextual severity band; `owasp_score` is the raw score on the 0 to 81 scale. A CVE the VEX did not score comes back with both as `null`.

---

## Getting the score into Trivy JSON

Trivy has no field for an OWASP rating, and its `--vex` flag only consumes VEX statuses (`analysis.state`), which Vens never emits. Pointing `trivy --vex` at a Vens VEX has no visible effect.

`vens enrich` is the way to carry the score into a Trivy report. The VEX itself is for consumers that read ratings, such as Dependency-Track.

---

## See also

- **[`vens generate`](generate.md)** — produces the VEX document consumed here.
- **[Prioritize a CVE backlog](../guides/prioritize-cves.md)** — end-to-end workflow.
