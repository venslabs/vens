# Describe your system context

**Who this is for:** anyone using Vens for the first time on a real system.
**By the end of this page:** you can write a `config.yaml` that produces accurate, defensible OWASP scores.

The context file is the **single most important input to Vens**. Good context → useful scores. Sloppy context → scores you can't trust.

---

## The 30-second version

A minimal, valid `config.yaml`:

```yaml
project:
  name: "my-service"

context:
  exposure: "internet"
  data_sensitivity: "high"
  business_criticality: "high"
```

Three required fields. That's enough to run. Add optional fields as you need more precision.

---

## The mental model

Vens maps your context onto the four factors of the [OWASP Risk Rating methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology):

```
              Likelihood × Impact
                   │
      ┌────────────┴────────────┐
      │                         │
  Likelihood                 Impact
      │                         │
  ┌───┴───┐                ┌────┴────┐
  Threat  Vulnerability    Technical  Business
  Agent   Factors          Impact     Impact
```

Your `config.yaml` fields feed these factors. Every field you add nudges the score of every CVE in the right direction.

| Field | Affects | Why it matters |
|---|---|---|
| `exposure` | Threat Agent | An internet-facing service has more attackers than an internal tool. |
| `data_sensitivity` | Technical Impact | Leaking PII is worse than leaking debug logs. |
| `business_criticality` | Business Impact | Downtime on checkout is worse than downtime on a dashboard. |
| `compliance_requirements` | Business Impact | GDPR fines raise the stakes. |
| `controls.*` | Vulnerability Factors | A WAF makes some exploits harder. |
| `notes` | Free-form context | Helps the LLM on edge cases. |

---

## The three required fields

### `exposure` — who can reach this system?

| Value | Meaning |
|---|---|
| `internal` | Corporate network only, no external access |
| `private` | Requires VPN or authenticated tunnel |
| `internet` | Publicly accessible |

**Rule of thumb:** if a stranger on the internet can send packets to it, pick `internet`.

### `data_sensitivity` — what data does it handle?

| Value | Meaning |
|---|---|
| `low` | Public data |
| `medium` | Internal data, limited confidentiality |
| `high` | PII, financial data, customer information |
| `critical` | Secrets, credentials, PHI, payment card data |

**Rule of thumb:** what is the worst thing that leaks if this service is fully compromised?

### `business_criticality` — what happens if it goes down?

| Value | Meaning |
|---|---|
| `low` | Dev / test / experimental |
| `medium` | Internal tools, non-essential services |
| `high` | Customer-facing, important operations |
| `critical` | Revenue-critical, compliance-required, core business |

**Rule of thumb:** if it stops, does someone get paged at 3am?

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

**Impact:** CVEs touching confidentiality or integrity get an impact bump when compliance is relevant.

### `availability_requirement`

How strict is your uptime target?

| Value | Meaning |
|---|---|
| `low` | Best-effort |
| `medium` | Business-hours SLA |
| `high` | 24/7 required |
| `critical` | Zero downtime, lives at risk |

If omitted, Vens instructs the LLM to reuse `business_criticality` as the availability score. Set it explicitly only when availability needs differ from business criticality (e.g. an internal tool that absolutely cannot go down during trading hours).

### `audit_requirement`

Values: `low`, `medium`, `high`. Set to `high` for systems that need forensic-grade logging (financial, HIPAA). Raises the score of CVEs that affect accountability/logging.

### `controls` — what defenses are already in place?

```yaml
controls:
  waf: true              # Web Application Firewall
  ddos_protection: true  # DDoS mitigation (CloudFlare, AWS Shield...)
  ids: true              # Intrusion Detection System
  siem: true             # SIEM collecting logs
  edr: false             # Endpoint Detection & Response
  antivirus: false
  segmentation: true     # Network micro-segmentation
  zero_trust: false      # Zero-trust architecture
```

**Only set `true` for controls that are actually active in production.** Vens will lower scores for CVEs that the control neutralizes. Lying here produces false confidence.

!!! warning
    A WAF does **not** neutralize every web CVE. Vens knows that. Setting `waf: true` reduces scores for CVEs that WAFs typically block (SQL injection, XSS) — not for logic flaws or deserialization bugs.

### `notes` — free-form context

```yaml
notes: |
  FastAPI backend on Python 3.11-slim. PostgreSQL on RDS.
  SSL terminated at ALB. Rate limiting via API Gateway.
  Container runs as non-root. Secrets from AWS Secrets Manager.
```

Anything an engineer would say in a threat modeling session. The LLM reads it and uses it on ambiguous CVEs.

!!! warning "What goes in notes leaves your network"
    When you use a cloud LLM provider, the `notes` field is sent **verbatim** to that provider alongside every batch of CVEs. Do not paste secrets, credentials, customer data, PHI, PII, or information your NDA/classification policy would forbid sharing with a third party. If any of that could reasonably appear in your `notes`, [use Ollama locally](../getting-started/installation.md#configure-an-llm-provider) — nothing leaves your network. See [Privacy and data flow](../concepts/privacy-and-data-flow.md) for the full list of what is (and isn't) sent to the LLM.

---

## A complete, production-ready example

```yaml
project:
  name: "checkout-api"
  description: "Public-facing checkout service, handles payment card data"

context:
  exposure: "internet"
  data_sensitivity: "critical"
  business_criticality: "critical"
  availability_requirement: "high"
  audit_requirement: "high"

  compliance_requirements:
    - "PCI-DSS"
    - "GDPR"
    - "SOC2"

  controls:
    waf: true
    ddos_protection: true
    ids: true
    siem: true
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

❌ **Setting all controls to `true` "just in case".** You'll get optimistic scores that miss real risk.

❌ **Leaving `notes` empty on complex systems.** The LLM does better with 2 sentences of architecture than with nothing.

❌ **Using `internet` for everything.** Internal services with `internal` exposure produce very different — and more accurate — scoring.

---

## Managing multiple services

Once you have more than one service scanned by Vens, copy-pasting the same `config.yaml` everywhere is the first mistake to avoid. A dev sandbox and a production checkout service should **not** share context — different criticality, different exposure, different compliance scope. The scores you get out of Vens are only as accurate as that per-service distinction.

The pattern that works:

- **One `config.yaml` per service, lives in the service's own repository**, typically under `.vens/config.yaml`. It ships and versions with the code it describes.
- **One stable BOM-Link UUID per service**, stored as a repository/environment variable next to the config file. Reuse it forever on every CI run — see [`--sbom-serial-number`](../reference/generate.md#--sbom-serial-number-urnuuid).
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
