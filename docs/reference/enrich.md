# `vens enrich`

**Who this is for:** Trivy users who already have a Vens-generated VEX file and want to fold the contextual ratings back into a Trivy report.
**By the end of this page:** you know exactly what `vens enrich` consumes, what it emits, and when to use it.

---

## Synopsis

```
vens enrich --vex VEX_FILE [--output PATH] REPORT_FILE
```

`vens enrich` takes a Trivy JSON report and annotates every vulnerability the VEX document scored, adding `Custom.owasp_score` and `Custom.owasp_vector`. Matching is on the vulnerability ID alone, and only ratings whose method is OWASP are read. Trivy's own `Severity` and CVSS fields stay as they are, and nothing else in the report changes.

```json
{
  "VulnerabilityID": "CVE-XXXX-YYYY",
  "Severity": "HIGH",
  "Custom": {
    "owasp_score": 45.5,
    "owasp_vector": "SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:3/LC:7/LI:7/LAV:7/LAC:7/FD:7/RD:7/NC:7/PV:7"
  }
}
```

`Severity` still holds Trivy's value. If you gate or sort downstream, read `Custom.owasp_score`. If a CVE appears more than once in the VEX, the last OWASP rating wins.

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
  | jq '.Results[]?.Vulnerabilities[]? | {VulnerabilityID, Severity, owasp: .Custom.owasp_score}'
```

`Severity` is Trivy's own rating, unchanged. `owasp` is the contextual score on the 0 to 81 scale. A CVE the VEX did not score comes back as `owasp: null`.

---

## Getting the score into Trivy JSON

Trivy has no field for an OWASP rating, and its `--vex` flag only consumes VEX statuses (`analysis.state`), which Vens never emits. Pointing `trivy --vex` at a Vens VEX has no visible effect.

`vens enrich` is the way to carry the score into a Trivy report. The VEX itself is for consumers that read ratings, such as Dependency-Track.

---

## See also

- **[`vens generate`](generate.md)** — produces the VEX document consumed here.
- **[Prioritize a CVE backlog](../guides/prioritize-cves.md)** — end-to-end workflow.
