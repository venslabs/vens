# What is a VEX file?

**Who this is for:** anyone seeing the term "VEX" for the first time.
**By the end of this page:** you understand what Vens produces, and why.

---

## VEX in one sentence

**VEX (Vulnerability Exploitability eXchange)** is a machine-readable document that says, for each CVE detected in a software artifact, whether it actually matters in a specific deployment and how severe it is — separately from the generic scanner output.

A scanner tells you _"this image contains CVE-X"_. A VEX document tells you _"CVE-X in this deployment is critical / high / medium / low / not relevant"_.

---

## Why VEX exists

Modern container scanners happily return hundreds of CVEs per image. Most of them don't apply:

- The vulnerable code path is never executed in production.
- A compensating control (WAF, segmentation, sandboxing) neutralizes the CVE.
- The affected component is a transitive dependency you never reach.
- The data or operation at stake is low-value.

Without VEX, every consumer of the scanner output has to re-do this analysis from scratch. VEX gives vendors, security teams, and downstream tooling a **standard way to share the analysis once**.

---

## What does Vens put in a VEX?

Vens emits a **CycloneDX 1.6 VEX BOM** (1.6 is the default so Dependency-Track can ingest it; `--cyclonedx-spec-version 1.7` opts up). For each CVE, it writes:

- `id` — the CVE identifier
- `source` — where the CVE comes from (NVD, GHSA, vendor tracker, …)
- `ratings[0]` — a single OWASP rating with:
  - `method: "OWASP"`
  - `score` — likelihood × impact on a 0–81 scale, a vens extension to rank CVEs within a severity
  - `severity` — `low` / `medium` / `high` / `critical`, from OWASP's likelihood × impact matrix
  - `vector` — the 16 OWASP factor levels the severity and the score are computed from (e.g. `SL:9/M:4/O:9/...`), on the impact the vulnerability's `vens:impact-basis` property names, `business` or `technical`
- `affects[]` — BOM-Link references to the vulnerable components

Vens does **not** set a CycloneDX `analysis` block (`state`, `justification`, `detail`). It deliberately leaves it out, which keeps the VEX focused on scoring information. The model's reasoning for each CVE is in the replies that `--debug-dir` writes and in the claims of the attestation that `--attest` writes; the log on stderr carries each rating, not its reasoning.

---

## Who consumes a VEX file?

- **Trivy** — `trivy image ... --vex vex.json`
- **Grype** — `grype ... --vex vex.json`
- **Dependency-Track** — ingests the file directly.
- **Your own scripts / dashboards** — via `jq` on `ratings[0].severity`, then `ratings[0].score` (see the [quickstart](../getting-started/quickstart.md#step-5-sort-by-severity-then-score)).
- **Any CI pipeline** — apply your CI policy to vens's computed ratings, for example by filtering the VEX on `ratings[0].severity`.

---

## See also

- **[CVSS vs OWASP contextual scoring](cvss-vs-owasp.md)** — how the score is computed and why it differs from CVSS.
- **[CycloneDX VEX specification](https://cyclonedx.org/capabilities/vex/)** — the full format.
