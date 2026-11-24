# Describe your system context

**Who this is for:** anyone using Vens for the first time on a real system.
**By the end of this page:** you can write a `config.yaml` that states what is true of your service, and know what each field changes in the rating.

The context file is the **single most important input to Vens**: every rating is computed from it, and each level a field feeds follows what you declare, true or not.

---

## The 30-second version

A minimal, valid `config.yaml`:

```yaml
schema_version: 2

project:
  name: "my-service"

context:
  exposure: "internet"
  data_sensitivity: "high"
  business_criticality: "high"
```

Three required fields. That's enough to run, with three warnings: `traceability`, `detection` and `data_subjects` are not declared, so vens uses each one's fallback, and `--strict` refuses the file. Declare them next ([below](#what-is-in-place-traceability-detection-data_subjects)), then add optional fields as you need more precision.

---

## The mental model

Vens rates each CVE on the 16 factors of the [OWASP Risk Rating methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology). The LLM answers closed questions about the CVE in your deployment, and vens computes every level, the severity and the score (see **[How vens rates a CVE](../concepts/cvss-vs-owasp.md#how-vens-rates-a-cve)**).

Your `config.yaml` fields work in two ways. A field **shown to the model** is context for its answers: it can move an answer, and so a level, but the model decides. A field **vens reads alone** moves a level directly, exactly as you declared it, and the model never sees it.

| Field | How it is used | Why it matters |
|---|---|---|
| `exposure` | vens sets Size from it; every question names the attacker group it gives | An internet-facing service has more attackers than an internal tool. |
| `data_sensitivity` | vens picks Loss of confidentiality's column from it; shown to Motive, Loss of integrity, Privacy violation | Leaking PII is worse than leaking debug logs. |
| `business_criticality` | vens reads it alone, at the CVE's technical impact, for Financial damage and Reputation damage; shown to Motive | A breach of checkout can cost far more than one of a dashboard. |
| `compliance_requirements` | the Non-compliance question names them | A GDPR violation raises the stakes. |
| `traceability` | vens reads it alone, for Loss of accountability | An attacker who leaves no trace is worse. |
| `detection` | vens reads it alone, for Intrusion detection | An attempt nobody records goes unseen. |
| `data_subjects` | vens reads it alone, to cap Privacy violation; declared, every finding is rated on its business impact | A leak of a hundred people's data is not a leak of millions. |
| `availability_requirement` | vens reads it alone, to pick Loss of availability's column | An outage of a 24/7 service is worse than one of a best-effort tool. |
| `listener` | shown in every call when `present` or `absent` | A batch job accepts no connection. |
| `controls.*` | the Ease of exploit question shows five of them | A WAF makes some exploits harder. |
| `notes` | shown in every call | What the other fields cannot say about your architecture. |

---

## The three required fields

### `exposure` — who can reach this system?

| Value | Meaning |
|---|---|
| `internal` | Corporate network only, no external access |
| `private` | Requires VPN / authenticated tunnel |
| `internet` | Publicly accessible |

**Rule of thumb:** if a stranger on the internet can send packets to it, pick `internet`.

### `data_sensitivity` — what data does it handle?

| Value | Meaning |
|---|---|
| `low` | Public data |
| `medium` | Internal data, limited confidentiality |
| `high` | PII, financial data, customer info |
| `critical` | Secrets, PHI, payment card data |

**Rule of thumb:** what is the worst thing that leaks if this service is fully compromised?

### `business_criticality` — what could an exploit cost the business?

Choosing a value declares the worst an exploit of this service could cost, in OWASP's words for Financial damage and Reputation damage, with a low, a medium and a high technical impact. vens sets both factors from it, at the band of the highest of the CVE's Loss of confidentiality, integrity and availability (high with no usable CVSS v3 vector); no question asks them.

| Value | Meaning | What choosing it declares |
|---|---|---|
| `low` | Dev / test / sandbox | With a high technical impact, less than the cost to fix the vulnerability (FD 1) and minimal damage (RD 1); medium, less than the cost to fix the vulnerability (1) and minimal damage (1); low, less than the cost to fix the vulnerability (1) and minimal damage (1). |
| `medium` | Internal tools | With a high technical impact, a minor effect on annual profit (FD 3) and loss of major accounts (RD 4); medium, less than the cost to fix the vulnerability (1) and minimal damage (1); low, less than the cost to fix the vulnerability (1) and minimal damage (1). |
| `high` | Customer-facing, important operations | With a high technical impact, a significant effect on annual profit (FD 7) and loss of goodwill (RD 5); medium, a minor effect on annual profit (3) and loss of major accounts (4); low, less than the cost to fix the vulnerability (1) and minimal damage (1). |
| `critical` | Revenue-critical | With a high technical impact, bankruptcy (FD 9) and brand damage (RD 9); medium, a significant effect on annual profit (7) and loss of goodwill (5); low, a minor effect on annual profit (3) and loss of major accounts (4). |

**Rule of thumb:** read the high technical impact first and pick the row whose worst case is yours. Could a breach of this service bankrupt the business or damage the brand? That is `critical`.

With a high technical impact, the row is your worst case. The steps down to medium and low are vens's customization of OWASP's options, not calibrated against experts' ratings; their direction is OWASP's: "The business impact stems from the technical impact". Compliance is not part of the value: declare frameworks in `compliance_requirements`. Since v0.7.0 the values keep their names with this meaning, and `critical` no longer says compliance-required: reconfirm yours.

The meanings in these tables are the words the model is shown with each value; the Motive question shows `business_criticality` with its meaning, and no call sends the declaration.

---

## What is in place: traceability, detection, data_subjects

These three fields are optional, but each one left out has a fallback: without `traceability`, Loss of accountability takes its `none` column on every finding; without `detection`, Intrusion detection is 9 on every finding; without `data_subjects`, nothing caps Privacy violation wherever it is asked, and every finding is rated on its technical impact. vens warns at load, counts each use in the run summary, and `--strict` refuses the run. vens reads them alone and never shows them to the model, so declare what is true across the whole service today, not what a policy requires.

### `traceability` — does the service record who did what?

| Value | Meaning |
|---|---|
| `none` | nothing records the requests the service receives or who made them |
| `per_request` | each request is recorded with its time and origin (source address, client), not with the individual who made it |
| `per_individual` | as `per_request`, and each action of an authenticated user is recorded with that user's identity |

A gateway or proxy log counts when it covers every request to the service. Where only part of the service records this, declare the weaker value. vens crosses the value with the model's answer on whether the attacker must authenticate and, apart, whether the exploit could defeat attribution, for Loss of accountability. `audit_requirement` does not stand in for it and moves no score.

### `detection` — what records an attack attempt, channel by channel?

```yaml
detection:
  network: "logged"                  # not_logged | logged | logged_and_reviewed
  host: "not_logged"                 # not_logged | logged | logged_and_reviewed
  application: "logged_and_reviewed" # ... | active_in_application
```

Declare the three channels, or leave the key out. `logged` means recorded and nobody reviews it; `logged_and_reviewed` means people review it, or alerts that people act on; `active_in_application` means the service itself detects attacks and acts on them. The model picks where an attempt on each CVE would show, and Intrusion detection takes the lowest level declared among those channels: an attempt seen in any of them can be detected. An IDS, a SIEM or an EDR set under `controls` gives no credit: it says a tool exists, not that this service's attempts are recorded and reviewed.

### `data_subjects` — how many people's personal data can it read?

| Value | People |
|---|---|
| `none` | 0 |
| `one_individual` | 1 |
| `hundreds` | 2 to 999 |
| `thousands` | 1,000 to 999,999 |
| `millions` | 1,000,000 or more |

Count what the service stores, what passes through it, and what it can fetch with its own access. The band caps Privacy violation: the model's answer stands up to it. Nothing is inferred from `data_sensitivity`.

vens takes what you declare as true. With `data_subjects` declared, `config.yaml` holds the business information OWASP asks for, and vens rates every finding on its business impact, as OWASP does when the business is known; left out, on its technical impact. See **[How vens rates a CVE](../concepts/cvss-vs-owasp.md#how-vens-rates-a-cve)**.

### `listener` — does it accept connections?

`present` for a service others connect to, `absent` for a batch job, a command-line tool or a client that only opens connections. Left out, it reads `unknown` and is not shown; nothing warns.

Each value's full meaning is in the **[config.yaml reference](../reference/config-schema.md)**.

---

## Optional fields worth adding

### `compliance_requirements`

A list of regulations that apply. Vens knows these frameworks:

`PCI-DSS`, `HIPAA`, `GDPR`, `SOX`, `ISO27001`, `FedRAMP`, `NIST`, `CCPA`, `SOC2`, `FISMA`, `ITAR`, `CMMC`

```yaml
compliance_requirements:
  - "PCI-DSS"
  - "GDPR"
```

**Impact:** the Non-compliance question names these frameworks, and the model judges how serious a violation exploiting the CVE would cause. With no framework declared, Non-compliance is at its lowest level and the question is not asked. No fixed amount is added.

### `availability_requirement`

How strict is your uptime target?

| Value | Meaning |
|---|---|
| `low` | Best-effort uptime |
| `medium` | Business-hours SLA |
| `high` | 24/7 required |
| `critical` | Zero downtime tolerance |

vens reads it alone and no call sends it. It picks the column in which Loss of availability is read from the CVE's CVSS v3 vectors: `low` and `medium` read OWASP's secondary services, `high` and `critical` its primary services, so `A:L` and `A:H` weigh less on `low` and `medium`. Left out, unset reads primary, and each CVE whose Loss of availability comes from a usable v3 vector adds one to the `availability_requirement_missing` counter; vens does not warn and `--strict` does not refuse it.

### `controls` — what defenses are already in place?

```yaml
controls:
  waf: true              # Web Application Firewall
  ddos_protection: true  # DDoS mitigation (CloudFlare, AWS Shield...)
  antivirus: false
  segmentation: true     # Network micro-segmentation
  zero_trust: false      # Zero-trust architecture
```

**Only set `true` for controls that are actually active in production.** The Ease of exploit question shows five controls (`waf`, `ddos_protection`, `segmentation`, `zero_trust`, `antivirus`) when they are set to `true`, each with its documented scope, and the model judges whether it stands in the way of this exploit in this deployment. vens applies no fixed reduction. Lying here produces false confidence.

`ids`, `siem` and `edr` still load but move no score and are not sent: declare [`detection`](#detection-what-records-an-attack-attempt-channel-by-channel) instead.

!!! warning
    A WAF does **not** neutralize every web CVE. The question shows `waf` with its scope, SQL injection, XSS and path traversal, so a logic flaw or a deserialization bug is outside it; whether the WAF stands in the way of a given exploit is the model's judgment, not a rule vens applies.

### `notes` — free-form context

```yaml
notes: |
  FastAPI backend on Python 3.11-slim. PostgreSQL on RDS.
  SSL terminated at ALB. Rate limiting via API Gateway.
  Container runs as non-root. Secrets from AWS Secrets Manager.
```

Anything an engineer would say in a threat modeling session. Every question shows it, with the rest of the deployment, and the model uses it on ambiguous CVEs. vens does not handle reachability: no question asks whether a CVE is reachable and vens publishes no VEX status, so a verdict written here reaches the rating only through the model's other answers.

!!! warning "What goes in notes leaves your network"
    When you use a cloud LLM provider, the `notes` field is sent **verbatim** to that provider in every call. Do not paste secrets, credentials, customer data, PHI, PII, or information your NDA/classification policy would forbid sharing with a third party. If any of that could reasonably appear in your `notes`, [use Ollama locally](../getting-started/installation.md#configure-an-llm-provider) — nothing leaves your network. See [Privacy and data flow](../concepts/privacy-and-data-flow.md) for the full list of what is (and isn't) sent to the LLM.

---

## A complete, production-ready example

```yaml
schema_version: 2

project:
  name: "checkout-api"
  description: "Public-facing checkout service, handles payment card data"

context:
  exposure: "internet"
  data_sensitivity: "critical"
  business_criticality: "critical"
  availability_requirement: "high"

  compliance_requirements:
    - "PCI-DSS"
    - "GDPR"
    - "SOC2"

  listener: "present"
  data_subjects: "millions"
  detection:
    network: "logged_and_reviewed"
    host: "logged"
    application: "logged_and_reviewed"
  traceability: "per_individual"

  controls:
    waf: true
    ddos_protection: true
    segmentation: true

  notes: |
    FastAPI on Python 3.11-slim behind AWS ALB with AWS WAF (OWASP ruleset).
    PostgreSQL on RDS in private subnet. 3-AZ deployment. Container runs
    as non-root. Secrets from Secrets Manager. No direct DB access from
    outside VPC. Payment tokenization via Stripe — raw card data never
    stored. PCI scope is limited to this service.
```

---

## Anti-patterns

❌ **Copy-pasting the same config everywhere.** Your dev API and your prod checkout service should not have the same context. Different criticality → different scores.

❌ **Setting all controls to `true` "just in case".** For the five controls the Ease of exploit question shows (`waf`, `ddos_protection`, `segmentation`, `zero_trust`, `antivirus`), claiming one as present when it is absent can lower ratings through the model's answer.

❌ **Declaring what is required instead of what is in place.** `traceability` and `detection` describe what records an attack today. A policy that requires per-user audit logs, or a SIEM bought last quarter, does not make this service's attempts recorded and reviewed. vens applies these fields exactly as declared, and the model never sees them to object.

❌ **Leaving `traceability`, `detection` and `data_subjects` out.** Each one left out takes its fallback ([above](#what-is-in-place-traceability-detection-data_subjects)). Declare the worst case explicitly if that is the truth (`traceability: none`, every channel `not_logged`, `data_subjects: millions`): the levels are the same, without the warning, and with `data_subjects` declared every finding is rated on its business impact.

❌ **Leaving `notes` empty on complex systems.** Every call shows `notes`; empty, the model judges your architecture from the other fields alone.

❌ **Using `internet` for everything.** `internal` sets a lower Size and names a different attacker group in every question, so an internal service declared `internal` gets different ratings.

---

## Managing multiple services

Once you have more than one service scanned by Vens, copy-pasting the same `config.yaml` everywhere is the first mistake to avoid. A dev sandbox and a production checkout service should **not** share context — different criticality, different exposure, different compliance scope. Each service's ratings are computed from its own file.

The pattern that works:

- **One `config.yaml` per service, lives in the service's own repository**, typically under `.vens/config.yaml`. It ships and versions with the code it describes.
- **A canonical CycloneDX SBOM per service**: pass its `serialNumber` to [`--sbom-serial-number`](../reference/generate.md#-sbom-serial-number-urnuuid) so each `affects` entry in the VEX resolves back to that SBOM via BOM-Link. Reuse the same SBOM across rescans of the same artefact for stable references.
- If you have genuinely shared defaults across many services (e.g. every fintech service under the same compliance perimeter), maintain a **template** in a central repo and have services vendor it with a short delta file on top. Avoid inheritance engines — YAML merging is a maintenance trap.
- If you maintain an internal platform, publish a **tiered catalogue** (`dev-sandbox.yaml`, `internal-tool.yaml`, `customer-facing.yaml`, `pci-scope.yaml`) and let service owners pick the closest one as their starting point.

## Governing your context file

`config.yaml` is a security artefact as much as an operational one: a wrong value silently changes the risk scores your team sees. Treat it accordingly.

- **Version it.** It belongs in Git, committed alongside the service.
- **Review it.** Add a `CODEOWNERS` entry so the security team (or a specific reviewer) must approve any PR touching `.vens/config.yaml`. This is where `exposure: internal → internet` sneaks in.
- **Log changes.** The PR history on the file is your audit log. Do not edit it out of band.
- **Restrict who can run Vens with alternate configs.** In CI, pin the path to the repo-committed file (`--config-file .vens/config.yaml`). Do not let ad-hoc configs land in production artefacts.
- **Tie it to incidents.** When something goes wrong and a CVE is later exploited, the `config.yaml` content at the time of the scan — recoverable from `git show <sha>:.vens/config.yaml` — is your defensible record of what Vens knew about your system.

See [Privacy and data flow](../concepts/privacy-and-data-flow.md) for what this file transmits to your LLM provider.

---

## Next

- See every field in one place: **[config.yaml reference](../reference/config-schema.md)**
- Understand how the scores are computed: **[CVSS vs OWASP contextual](../concepts/cvss-vs-owasp.md)**
- Understand what is sent to the LLM: **[Privacy and data flow](../concepts/privacy-and-data-flow.md)**
