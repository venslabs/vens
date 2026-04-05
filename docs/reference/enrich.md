# `vens enrich`

**Who this is for:** Trivy users who already have a Vens-generated VEX file and want to fold the contextual ratings back into a Trivy report.
**By the end of this page:** you know exactly what `vens enrich` consumes, what it emits, and when to use it instead of (or alongside) Trivy's native `--vex` flag.

---

## Synopsis

```
vens enrich --vex VEX_FILE [--output PATH] REPORT_FILE
```

`vens enrich` takes a Trivy JSON report and overwrites each vulnerability's ratings with the OWASP ratings found in the provided VEX document. Everything else in the report (metadata, packages, non-rating fields) is preserved.

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

### Enrich a Trivy report in place

```bash
trivy image nginx:1.25 --format json --output report.json
vens generate --config-file vens.yaml report.json vex.json
vens enrich --vex vex.json --output enriched-report.json report.json
```

The `enriched-report.json` is still a valid Trivy JSON report — you can feed it to any tool that understands Trivy output.

### Pipe to another tool

```bash
vens enrich --vex vex.json report.json | jq '.Results[].Vulnerabilities[] | {VulnerabilityID, Severity}'
```

---

## When to use `enrich` vs. Trivy `--vex`

- Use `trivy ... --vex vex.json` when Trivy itself is your display surface.
- Use `vens enrich` when you need the OWASP ratings embedded inside a Trivy JSON report that will be consumed by another tool (dashboards, custom scripts, enterprise scanners that don't read VEX natively).

---

## See also

- **[`vens generate`](generate.md)** — produces the VEX document consumed here.
- **[Prioritize a CVE backlog](../guides/prioritize-cves.md)** — end-to-end workflow.
