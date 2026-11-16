# config.yaml reference

**Who this is for:** anyone who needs to look up a field quickly.
**By the end of this page:** you know every field, its valid values, its default, and its effect on scoring.

For a narrative explanation of how to use these fields, see **[Describe your system context](../guides/configuration.md)**.

---

## Top-level structure

```text
project:
  name: string       # required
  description: string # optional

context:
  # required
  exposure: string
  data_sensitivity: string
  business_criticality: string

  # optional
  availability_requirement: string
  audit_requirement: string
  compliance_requirements: [string]
  controls: {...}
  notes: string
```

---

## `schema_version`

Required: the integer `2`. The version of this file's format. `2` is the format of the 16-factor scoring; a file without it was written for vens v0.6 or earlier, which is schema 1.

---

## `project`

| Field | Type | Required | Description |
|---|---|:---:|---|
| `project.name` | string | ✅ | Short identifier of the project or service. Shown in the VEX metadata. |
| `project.description` | string | ❌ | Free-form one-line description. Helps the LLM on ambiguous CVEs. |

---

## `context` — required fields

### `context.exposure`

How the system is exposed to attackers.

| Value | Meaning | OWASP factor affected |
|---|---|---|
| `internal` | Corporate network only, no external access | Lowers Threat Agent |
| `private` | Requires VPN / authenticated tunnel | Moderate Threat Agent |
| `internet` | Publicly accessible | Raises Threat Agent |

### `context.data_sensitivity`

Type of data handled by the system.

| Value | Meaning | OWASP factor affected |
|---|---|---|
| `low` | Public data | Low Technical Impact |
| `medium` | Internal data, limited confidentiality | Medium Technical Impact |
| `high` | PII, financial data, customer info | High Technical Impact |
| `critical` | Secrets, PHI, payment card data | Max Technical Impact |

### `context.business_criticality`

How critical the system is to the business.

| Value | Meaning | OWASP factor affected |
|---|---|---|
| `low` | Dev / test / sandbox | Low Business Impact |
| `medium` | Internal tools | Medium Business Impact |
| `high` | Customer-facing, important operations | High Business Impact |
| `critical` | Revenue-critical, compliance-required | Max Business Impact |

---

## `context` — optional fields

### `context.availability_requirement`

Strictness of uptime requirements. If omitted, Vens instructs the LLM to reuse `business_criticality` as the availability score.

| Value | Meaning |
|---|---|
| `low` | Best-effort uptime |
| `medium` | Business-hours SLA |
| `high` | 24/7 required |
| `critical` | Zero downtime tolerance |

**When to set it explicitly:** only when availability needs differ from business criticality (e.g. a `medium`-criticality internal tool that must not go down during trading hours).

### `context.audit_requirement`

Importance of audit logging and traceability.

| Value | Meaning |
|---|---|
| `low` | Basic logging |
| `medium` | Audit trail required |
| `high` | Forensic-grade, immutable logging |

Raises the score of CVEs affecting accountability or log integrity.

### `context.compliance_requirements`

List of compliance frameworks that apply. Each entry raises Business Impact for relevant CVEs.

**Supported values:**

```
PCI-DSS, HIPAA, GDPR, SOX, ISO27001, FedRAMP, NIST,
CCPA, SOC2, FISMA, ITAR, CMMC
```

Example:

```yaml
compliance_requirements:
  - "PCI-DSS"
  - "GDPR"
```

!!! warning
    Unknown framework names cause a **validation error** — Vens will refuse to start. Use the exact identifiers listed above.

### `context.listener`

Does this deployment accept connections others open? Omitted, it reads `unknown`.

| Value | Meaning |
|---|---|
| `present` | this deployment accepts connections that other parties open: it listens on a port or socket, as a server or as a peer others connect to |
| `absent` | it accepts none: no listening port or socket, such as a batch job, a command-line tool, or a client that only opens connections |
| `unknown` | not stated |

### `context.data_subjects`

How many distinct people's personal data this service can read: what it stores, what passes through it, and what it can fetch with its own access. A count belongs to the band whose interval holds it, and a count of 2 to 99 belongs to `hundreds`. Nothing is inferred from `data_sensitivity`.

| Value | People | Privacy violation at most |
|---|---|---|
| `none` | 0 | 3 |
| `one_individual` | 1 | 3 |
| `hundreds` | 2 to 999 | 5 |
| `thousands` | 1,000 to 999,999 | 7 |
| `millions` | 1,000,000 or more | 9 |

### `context.detection`

Declaring a channel's level states it for every instance of this service. Where only part of the service is covered, the level declared is the one that holds for all of it. Once `detection` is written, all three channels are required; `active_in_application` applies to `application` only.

| Field | Meaning |
|---|---|
| `network` | each attempt crossing the network to or from the service is recorded where it can be seen |
| `host` | process, file and privilege activity on the hosts that run the service is recorded |
| `application` | the service's own logs record each request or action an attempt would make |

| Value | Meaning |
|---|---|
| `not_logged` | nothing is recorded |
| `logged` | recorded, and nobody reviews it |
| `logged_and_reviewed` | recorded and reviewed, by people or by alerts that people act on |
| `active_in_application` | the service itself detects attacks and acts on them |

### `context.traceability`

What is in place, not what is required. Records kept in front of the service count when they cover every request to it (a gateway or proxy log). The value declared must hold across the whole service: where only part of it records this, declare the weaker value.

| Value | Meaning |
|---|---|
| `none` | nothing records the requests the service receives or who made them |
| `per_request` | each request is recorded with its time and origin (source address, client), not with the individual who made it |
| `per_individual` | as `per_request`, and each action of an authenticated user is recorded with that user's identity |

### `context.controls`

Security controls currently active in production. All fields are booleans, default `false`. Each enabled control lowers the Vulnerability Factor for the attack types it neutralizes.

| Field | Description | Reduces scores for |
|---|---|---|
| `waf` | Web Application Firewall | SQL injection, XSS, path traversal |
| `ddos_protection` | DDoS mitigation (CloudFlare, AWS Shield…) | Availability / DoS CVEs |
| `ids` | Intrusion Detection System | Network-level exploits |
| `siem` | SIEM collecting and alerting on logs | Post-exploitation visibility |
| `edr` | Endpoint Detection & Response | Malware, privilege escalation |
| `antivirus` | Traditional AV / anti-malware | Known malware signatures |
| `segmentation` | Network micro-segmentation | Lateral movement |
| `zero_trust` | Zero-trust architecture | Authentication bypass, lateral movement |

Example:

```yaml
controls:
  waf: true
  segmentation: true
  siem: true
```

!!! warning
    Only set controls to `true` when they are actually operational. Claiming controls you don't run produces optimistic scores that miss real risk.

### `context.notes`

Free-form multi-line string. Anything an engineer would share in a threat modeling session: architecture, deployment environment, authentication, data flow, known threat model assumptions.

```yaml
notes: |
  FastAPI on Python 3.11-slim. PostgreSQL on RDS in private subnet.
  SSL terminated at ALB. Rate limiting via API Gateway. Container
  runs as non-root. Secrets from AWS Secrets Manager.
```

The LLM reads this on every CVE and uses it for edge cases and tie-breaks.

---

## Validation rules

Vens validates the file on load. It will fail fast with a clear error if:

- `project.name` is empty
- `context.exposure` is missing or not in `{internal, private, internet}`
- `context.data_sensitivity` is missing or not a valid value
- `context.business_criticality` is missing or not a valid value
- any optional enum field has an unknown value

Values are normalized to lowercase. Under schema 2 an unknown key is refused, and the error names its line.

---

## Minimal valid file

```yaml
schema_version: 2

project:
  name: "my-service"

context:
  exposure: "private"
  data_sensitivity: "medium"
  business_criticality: "medium"
```

---

## See also

- **[Describe your system context](../guides/configuration.md)** — guided walkthrough
- **[vens generate](generate.md)** — the command that consumes this file
