# config.yaml reference

**Who this is for:** anyone who needs to look up a field quickly.
**By the end of this page:** you know every field, its valid values, its default, and what it does to the rating.

For a narrative explanation of how to use these fields, see **[Describe your system context](../guides/configuration.md)**. For how the fields and the model's answers become a rating, see **[CVSS vs OWASP contextual](../concepts/cvss-vs-owasp.md#how-vens-rates-a-cve)**.

This page describes schema 2, the format vens reads since v0.7.0. A file written for v0.6 or earlier is refused at load: see **[Migrating from vens v0.6](#migrating)**.

---

## Top-level structure

```text
schema_version: 2            # required

project:
  name: string               # required
  description: string        # optional

context:
  # required
  exposure: string
  data_sensitivity: string
  business_criticality: string

  # optional
  availability_requirement: string
  compliance_requirements: [string]
  listener: string
  data_subjects: string
  detection:
    network: string
    host: string
    application: string
  traceability: string
  controls: {...}
  notes: string
  audit_requirement: string  # moves no score
```

`data_subjects`, `detection` and `traceability` are optional, but each one left out takes the fallback its section states: vens warns at load, counts each use in the run summary, and `--strict` refuses the run. Declare them. See the **[fully declared file](#fully-declared-file)**.

---

## `schema_version`

Required since v0.7.0: the integer `2`, written plain. The version of this file's format. A file without it was written for vens v0.6 or earlier, which is schema 1, and is refused (E1); any other value is refused too (E2). See **[Load errors](#load-errors)**.

---

## `project`

| Field | Type | Required | Description |
|---|---|:---:|---|
| `project.name` | string | ✅ | Short identifier of the project or service. Shown to the model in every call, and logged when the config loads. |
| `project.description` | string | ❌ | Free-form one-line description. Shown to the model in every call. |

---

## `context` — required fields

### `context.exposure`

How the system is exposed to attackers. Every call shows the model the value, its meaning and the attacker group it names. vens sets Size from it.

| Value | Meaning | Size | Attacker group the questions name |
|---|---|---|---|
| `internal` | Corporate network only, no external access | 4 | intranet users |
| `private` | Requires VPN / authenticated tunnel | 6 | authenticated users |
| `internet` | Publicly accessible | 9 | anonymous Internet users |

### `context.data_sensitivity`

Type of data handled by the system. vens uses it to pick the column of Loss of confidentiality, which no question asks: vens reads it from the CVE's CVSS v3 vectors and crosses it with the column. The Motive and Privacy violation questions show this field, with its meaning.

| Value | Meaning | Loss of confidentiality column |
|---|---|---|
| `low` | Public data | non-sensitive |
| `medium` | Internal data, limited confidentiality | non-sensitive |
| `high` | PII, financial data, customer info | critical |
| `critical` | Secrets, PHI, payment card data | critical |

Loss of confidentiality, integrity and availability come from the worst value, `H` over `L` over `N`, that the CVE's usable CVSS v3 vectors give `C`, `I` and `A`, across every row and source of the scanner's report. A v3 vector is usable when its version is 3.0 or 3.1, it parses, any `CVSS:` prefix stating 3.0 or 3.1, and it gives `C`, `I` and `A` each once on `H`, `L` or `N`; any other, another 3.x version included, is refused whole and named by `--strict`. v2 and v4 vectors are not read.

| CVSS v3 | Loss of confidentiality, non-sensitive | Loss of confidentiality, critical | Loss of integrity | Loss of availability |
|---|---|---|---|---|
| `N` | 2 | 2 | 1 | 1 |
| `L` | 2 | 6 | 3 | 5 |
| `H` | 6 | 7 | 7 | 7 |
| no usable v3 vector | 9 | 9 | 9 | 9 |

No default is documented for a CVE with no usable v3 vector: the three take 9, the CVE adds one to the `cvss_v3_missing` counter, and `--strict` refuses the run.

### `context.business_criticality`

How critical the system is to the business. No level reads it directly. The Motive, Financial damage and Reputation damage questions show it, with its meaning.

| Value | Meaning |
|---|---|
| `low` | Dev / test / sandbox |
| `medium` | Internal tools |
| `high` | Customer-facing, important operations |
| `critical` | Revenue-critical, compliance-required |

---

## `context` — optional fields

### `context.availability_requirement`

Strictness of uptime requirements. Moves no score and no call sends it: Loss of availability, which it described, is read from the CVE's CVSS v3 vectors (see [`data_sensitivity`](#contextdata_sensitivity)). The key still loads.

| Value | Meaning |
|---|---|
| `low` | Best-effort uptime |
| `medium` | Business-hours SLA |
| `high` | 24/7 required |
| `critical` | Zero downtime tolerance |

### `context.compliance_requirements`

List of compliance frameworks that apply. When the list holds at least one, the Non-compliance question names them, and the model picks how serious a violation exploiting the CVE would cause: a minor violation (2), a clear violation (5) or a high profile violation (7); `cannot_tell` reads as 7. When the list is empty or left out, Non-compliance is 2 and the question is not asked. A framework adds no fixed amount to the score.

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

New in v0.7.0. Does this deployment accept connections others open? Omitted, it reads `unknown`.

| Value | Meaning |
|---|---|
| `present` | this deployment accepts connections that other parties open: it listens on a port or socket, as a server or as a peer others connect to |
| `absent` | it accepts none: no listening port or socket, such as a batch job, a command-line tool, or a client that only opens connections |
| `unknown` | not stated |

`present` and `absent` are shown to the model in every call, with their meaning; `unknown` is not shown. No level reads it directly. Leaving it out is not a fallback: nothing warns or counts it.

### `context.data_subjects`

New in v0.7.0. How many distinct people's personal data this service can read: what it stores, what passes through it, and what it can fetch with its own access. A count belongs to the band whose interval holds it, and a count of 2 to 99 belongs to `hundreds`. Nothing is inferred from `data_sensitivity`.

| Value | People | Privacy violation at most |
|---|---|---|
| `none` | 0 | 3 |
| `one_individual` | 1 | 3 |
| `hundreds` | 2 to 999 | 5 |
| `thousands` | 1,000 to 999,999 | 7 |
| `millions` | 1,000,000 or more | 9 |

vens reads this field alone; no call sends it. The Privacy violation question asks the model for the band of people whose data an exploit could disclose, and the declared band caps that answer. With `none` or `one_individual`, Privacy violation is 3 and the question is not asked; so it is for a CVE whose usable CVSS v3 vectors give `C:N` (see [`data_sensitivity`](#contextdata_sensitivity)). A flagged CVE's adjustment asks confidentiality again from the flag's evidence, and `not_affected` lowers Privacy violation to 3.

Left out, nothing caps the model's answer: each CVE asked Privacy violation adds one to the `data_subjects_missing` counter, vens warns at load (W5), and `--strict` refuses the run.

### `context.detection`

New in v0.7.0. Declaring a channel's level states it for every instance of this service. Where only part of the service is covered, the level declared is the one that holds for all of it. Once `detection` is written, all three channels are required; `active_in_application` applies to `application` only.

| Field | Meaning |
|---|---|
| `network` | each attempt crossing the network to or from the service is recorded where it can be seen |
| `host` | process, file and privilege activity on the hosts that run the service is recorded |
| `application` | the service's own logs record each request or action an attempt would make |

| Value | Meaning | Intrusion detection |
|---|---|---|
| `not_logged` | nothing is recorded | 9 |
| `logged` | recorded, and nobody reviews it | 8 |
| `logged_and_reviewed` | recorded and reviewed, by people or by alerts that people act on | 3 |
| `active_in_application` | the service itself detects attacks and acts on them | 1 |

vens reads this field alone; no call sends it. When the channels are declared at different levels, the Intrusion detection question asks where an attempt would show (network, host, application, one or more), and Intrusion detection is the lowest level declared among the channels chosen. `cannot_tell` reads as the highest of the three. When all three are declared at the same level, Intrusion detection is that level and the question is not asked.

Left out, every channel counts as `not_logged`: Intrusion detection is 9 on every finding, each CVE adds one to the `detection_undeclared` counter, vens warns at load (W2 or W4), and `--strict` refuses the run. The `ids`, `siem` and `edr` controls give no credit.

### `context.traceability`

New in v0.7.0. What is in place, not what is required. Records kept in front of the service count when they cover every request to it (a gateway or proxy log). The value declared must hold across the whole service: where only part of it records this, declare the weaker value.

| Value | Meaning |
|---|---|
| `none` | nothing records the requests the service receives or who made them |
| `per_request` | each request is recorded with its time and origin (source address, client), not with the individual who made it |
| `per_individual` | as `per_request`, and each action of an authenticated user is recorded with that user's identity |

vens reads this field alone; no call sends it. The Loss of accountability question asks, as two separate facts, whether the attacker must authenticate and whether the exploit lets them act as someone else or tamper with the records, not whether records exist; vens crosses the answer with this field:

| Answer to the Loss of accountability question | `none` | `per_request` | `per_individual` |
|---|---|---|---|
| `identified` | 7 | 7 | 1 |
| `unidentified` | 9 | 7 | 7 |
| `defeats_attribution` | 9 | 9 | 9 |

`identified` (no accountability loss: the attacker must authenticate under an identity of their own, and the exploit leaves the records intact; not having to authenticate never counts) takes the lowest level the column gives. `cannot_tell` reads as `defeats_attribution`. Left out, vens uses the `none` column: each CVE adds one to the `traceability_missing` counter, vens warns at load (W1 or W3), and `--strict` refuses the run.

### `context.controls`

Security controls currently active in production. All fields are booleans, default `false`.

`waf`, `ddos_protection`, `segmentation`, `zero_trust` and `antivirus`, when `true`, are shown with their scope to the Ease of exploit question only. The model judges whether the control stands in the way of this exploit in this deployment; vens applies no fixed reduction.

Since v0.7.0, `ids`, `siem` and `edr` move no score and no call sends them: a tool being present says neither that an attempt on this service is recorded nor that someone reviews it. Declare [`detection`](#contextdetection) instead. They still load, so existing files keep working, until a future schema version removes them ([#427](https://github.com/venslabs/vens/issues/427)). Set to `true` while `detection` is left out, they get a warning at load (W2).

| Field | Description | Scope |
|---|---|---|
| `waf` | Web Application Firewall | SQL injection, XSS, path traversal |
| `ddos_protection` | DDoS mitigation (CloudFlare, AWS Shield…) | Availability / DoS CVEs |
| `segmentation` | Network micro-segmentation | Lateral movement |
| `zero_trust` | Zero-trust architecture | Authentication bypass, lateral movement |
| `antivirus` | Traditional AV / anti-malware | Known malware signatures |
| `ids` | Intrusion Detection System | none, moves no score |
| `siem` | SIEM collecting and alerting on logs | none, moves no score |
| `edr` | Endpoint Detection & Response | none, moves no score |

Example:

```yaml
controls:
  waf: true
  segmentation: true
```

!!! warning
    Only set controls to `true` when they are actually operational. For the five controls the Ease of exploit question shows (`waf`, `ddos_protection`, `segmentation`, `zero_trust`, `antivirus`), claiming one as present when it is absent can lower ratings through the model's answer.

### `context.notes`

Free-form multi-line string. Anything an engineer would share in a threat modeling session: architecture, deployment environment, authentication, data flow, known threat model assumptions.

```yaml
notes: |
  FastAPI on Python 3.11-slim. PostgreSQL on RDS in private subnet.
  SSL terminated at ALB. Rate limiting via API Gateway. Container
  runs as non-root. Secrets from AWS Secrets Manager.
```

Shown to the model in every call, with the rest of the deployment. vens does not handle reachability: no question asks whether a CVE is reachable and vens publishes no VEX status, so a verdict written here reaches the rating only through the model's other answers.

### `context.audit_requirement`

Since v0.7.0, moves no score and no call sends it. It states a requirement, not what is in place: Loss of accountability reads [`traceability`](#contexttraceability) instead. The key still loads, so existing files keep working, until a future schema version removes it ([#427](https://github.com/venslabs/vens/issues/427)). Set while `traceability` is left out, it gets a warning at load (W1).

| Value | Meaning |
|---|---|
| `low` | Basic logging |
| `medium` | Audit trail required |
| `high` | Forensic-grade, immutable logging |

---

## Load errors and warnings { #load-errors }

vens reads the file before it sets up the LLM provider. Values are normalized to lowercase. An error stops the run with exit code 1, before any LLM call:

```text
failed to load config file "config.yaml": <message>
```

The file is refused when:

- it is empty, holds more than one YAML document, or is not a mapping;
- `project.name` is empty;
- `context.exposure`, `context.data_sensitivity` or `context.business_criticality` is missing or not one of its values;
- an optional field has a value off its list, or `compliance_requirements` names an unknown framework;
- one of E1 to E5 below applies. vens checks `schema_version` first, so a file written for another schema gets E1 or E2 and no other error.

E1 to E5 and W1 to W5 are labels on this page; the messages do not print them.

### E1: no schema_version

```text
config.yaml has no schema_version: it was written for vens v0.6 or earlier (schema 1). This vens reads schema 2, which scores each OWASP factor on its own: audit_requirement and controls ids/siem/edr no longer move any score, and listener, data_subjects, detection and traceability are new. Read https://venslabs.github.io/vens/reference/config-schema/#migrating, then add `schema_version: 2` at the top of the file.
```

### E2: schema_version other than 2

For `1`:

```text
schema_version 1 is not supported: this vens reads schema 2 only. Read https://venslabs.github.io/vens/reference/config-schema/#migrating, then set `schema_version: 2`.
```

For a plain integer above 2, such as `3`:

```text
schema_version 3 is not supported: this vens reads schema 2; the file needs a newer vens.
```

For anything else: `0`, a negative number, a string such as `"2"`, a float such as `2.0`, a hex or signed form such as `0x2` or `+2`, a tag, or no value:

```text
schema_version must be the integer 2, got "2"
```

### E3: unknown key

A key that schema 2 does not have, with its line and where it sits. A misspelled key is refused rather than ignored; for `tracability:` written on line 10 of the file:

```text
config.yaml line 10: unknown key `tracability` under context
```

A key outside `project` and `context` reads `at the top level` instead of `under context`. `reachability:` is one: vens reads no reachability declaration.

### E4: listener, data_subjects or traceability

A value off the list:

```text
context.traceability must be one of [none per_request per_individual], got "full"
```

The key written with no value, or for `listener` a value that is blank:

```text
context.listener has no value: write one of [present absent unknown] or remove the key
```

A list or a mapping instead of one value:

```text
context.data_subjects must be a single value, one of [none one_individual hundreds thousands millions]
```

### E5: detection

Written with no value or as `{}`:

```text
context.detection has no channels: declare network, host and application, or remove the key
```

Written as a single value or a list:

```text
context.detection must be a mapping of network, host and application
```

A channel missing, each one named:

```text
context.detection.host is required once context.detection is present (values: [not_logged logged logged_and_reviewed]); context.detection.application is required once context.detection is present (values: [not_logged logged logged_and_reviewed active_in_application])
```

`active_in_application` on `network` or `host`:

```text
context.detection.network: active_in_application applies to application only
```

A channel's value off its list, or a channel written as a list or a mapping, gets E4's form for `context.detection.network`, `host` or `application`.

### Warnings

A warning does not stop the run. vens logs it at load, before any LLM call, at the default log level. Each field left out gets one warning, which says what its fallback does.

**W1**: `audit_requirement` set, `traceability` left out.

```text
context.audit_requirement no longer moves any score, and context.traceability is not declared: Loss of accountability uses its `none` column, 7 when the attacker must authenticate and cannot act as someone else or tamper with the records, 9 otherwise.
```

**W2**: `ids`, `siem` or `edr` set to `true`, `detection` left out.

```text
controls ids/siem/edr give no detection credit, and context.detection is not declared: every channel counts as not logged, so Intrusion detection is 9 on every finding.
```

**W3**: `traceability` and `audit_requirement` both left out.

```text
context.traceability is not declared: Loss of accountability uses its `none` column, 7 or 9 on every finding.
```

**W4**: `detection` left out, and none of `ids`, `siem` or `edr` set to `true`.

```text
context.detection is not declared: every channel counts as not logged, so Intrusion detection is 9 on every finding.
```

**W5**: `data_subjects` left out.

```text
context.data_subjects is not declared: Privacy violation has no cap, so the model's band stands wherever Privacy violation is asked.
```

Nothing warns when `listener` is left out.

---

## Fully declared file

Every field that has a fallback is declared, so this file loads with no warning and passes the config check of `--strict`. The values describe one example service; declare yours.

```yaml
schema_version: 2

project:
  name: "payments-api"
  description: "Customer-facing payment API"

context:
  exposure: "internet"
  data_sensitivity: "critical"
  business_criticality: "critical"
  availability_requirement: "high"
  compliance_requirements: ["PCI-DSS", "GDPR"]
  listener: "present"
  data_subjects: "thousands"
  detection:
    network: "logged"
    host: "not_logged"
    application: "logged_and_reviewed"
  traceability: "per_individual"
  controls:
    waf: true
    segmentation: true
  notes: |
    Go service behind a load balancer that terminates TLS.
    PostgreSQL in a private subnet. Card numbers are tokenized by the
    payment provider and never stored.
```

`--strict` can still fail on the scan itself: see **[vens generate](generate.md#-strict)**.

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

It loads with three warnings (W3, W4, W5), and `--strict` refuses it.

---

## Migrating from vens v0.6 { #migrating }

vens v0.7.0 reads schema 2 only. A file without `schema_version` is refused with E1, and `schema_version: 1` with E2. Every key of schema 1 keeps its name, its values and its validation.

1. Add `schema_version: 2` at the top of the file.
2. Declare `traceability`, `detection` and `data_subjects` for what is in place. vens does not derive them from `audit_requirement` or `controls`: a logging requirement is not a record, and an IDS or a SIEM does not show that this service's attempts are recorded.
3. Set `listener: absent` for a job or a client that accepts no connection, `present` for a service that does.
4. Run once and read the warnings. Fix any key refused as unknown (E3): schema 1 ignored a misspelled key, so `compliance_requirement:` (singular) used to drop your frameworks without a word.

What each schema-1 key does once `schema_version: 2` is added and nothing else:

| Schema-1 key | Under schema 2 | What to do |
|---|---|---|
| `project.name`, `project.description`, `notes` | shown to the model in every call | nothing |
| `exposure` | sets Size and the attacker group every question names | nothing |
| `data_sensitivity` | picks the column in which Loss of confidentiality is read from the CVSS v3 vectors; shown to the Motive and Privacy violation questions | nothing |
| `business_criticality` | shown to the questions it concerns | nothing |
| `availability_requirement` | moves no score: Loss of availability is read from the CVSS v3 vectors | nothing |
| `compliance_requirements` | Non-compliance is asked only when the list is not empty; no fixed amount is added | nothing |
| `audit_requirement` | moves no score; W1 while `traceability` is left out | declare `traceability` for what is recorded, not what is required: `audit_requirement: high` does not mean `per_individual` |
| `controls.waf`, `ddos_protection`, `segmentation`, `zero_trust`, `antivirus` | shown with their scope to the Ease of exploit question | nothing |
| `controls.ids`, `siem`, `edr` | move no score; W2 while `detection` is left out | declare `detection`, channel by channel |
| `listener` (new) | left out, reads `unknown` and is not shown | `present` or `absent` |
| `data_subjects` (new) | left out, nothing caps Privacy violation; W5 | declare the band |
| `detection` (new) | left out, Intrusion detection is 9 on every finding; W2 or W4 | declare the three channels |
| `traceability` (new) | left out, Loss of accountability takes the `none` column, 7 or 9; W1 or W3 | declare it |

Declaring the worst case (`traceability: none`, every channel `not_logged`, `data_subjects: millions`) gives the same levels as leaving the field out, without the warning or the counter, and passes the config check of `--strict`.

Expect ratings to change with v0.7.0, whatever the file declares: see **[CVSS vs OWASP contextual](../concepts/cvss-vs-owasp.md#what-changed-in-v070)**.

!!! warning "Upgrade every runner first"
    vens v0.6 and earlier ignore unknown keys, so they load a schema-2 file without an error and score it the old way. Upgrade every runner that reads the file, CI included, before you migrate it.

---

## See also

- **[Describe your system context](../guides/configuration.md)** — guided walkthrough
- **[vens generate](generate.md)** — the command that consumes this file
- **[vens init](init.md)** — writes a schema-2 file from your answers
