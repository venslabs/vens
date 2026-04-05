# CVSS vs OWASP contextual scoring

**Who this is for:** anyone who wants to understand why Vens scores differ from their scanner.
**By the end of this page:** you know what the OWASP score represents and why it moves.

---

## The one-sentence answer

**CVSS describes the vulnerability. OWASP Risk Rating describes the risk to _your_ system.**

A CVE has one CVSS score, forever. It has as many OWASP scores as there are systems running the vulnerable component.

---

## A concrete example

Two services both contain `libfoo-1.2.3` with `CVE-2026-0915`. The CVE is a denial-of-service in a CSV parsing function.

**CVSS says:** 8.8 HIGH. This is the generic severity of the flaw. Same number for everyone.

**Vens says, for service A (internal dashboard, no CSV parsing in production):**
```
OWASP score: 8 / 81
Severity: low
Reason: The vulnerable CSV parser is not reachable in production.
        Internal exposure limits threat actors. Business impact is low.
```

**Vens says, for service B (public checkout, parses uploaded CSVs, GDPR):**
```
OWASP score: 56 / 81
Severity: high
Reason: CSV upload is a direct user input. Internet exposure means high
        threat agent. DoS affects availability of a revenue-critical
        service. Compliance impact under GDPR breach reporting.
```

Same CVE, same CVSS, two completely different risks. Vens quantifies that.

---

## The OWASP Risk Rating formula

```
Risk = Likelihood × Impact             (0 to 81)

Likelihood = (Threat Agent + Vulnerability Factors) / 2
Impact     = (Technical Impact + Business Impact)   / 2
```

Each of the four factors is a number from 0 to 9. Multiply the two averages together and you get a risk score from 0 to 81.

| Score | Severity |
|---|---|
| 0–9 | none / info |
| 10–19 | low |
| 20–39 | medium |
| 40–59 | high |
| 60–81 | critical |

Full methodology: [owasp.org/www-community/OWASP_Risk_Rating_Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology).

---

## The four factors, plain English

### 1. Threat Agent — "who would attack this?"

- `internet` exposure → many attackers, easy access → high
- `internal` exposure → few attackers, need a foothold → low

Fed by your `exposure` field.

### 2. Vulnerability Factors — "how easy is it to exploit?"

- Public exploit available, no auth needed → high
- Requires specific config, authenticated access, WAF in front → low

Fed by the CVE metadata **and** your `controls` (WAF, segmentation, etc.).

### 3. Technical Impact — "what breaks if this is exploited?"

- Confidentiality loss on PII → high
- Availability loss on a dev sandbox → low

Fed by your `data_sensitivity`, `availability_requirement`, `audit_requirement`.

### 4. Business Impact — "what does it cost the business?"

- Revenue-critical + compliance fines → high
- Internal tooling outage → low

Fed by your `business_criticality` and `compliance_requirements`.

---

## Why scores go _down_ from CVSS

The most common case. A CVE is CVSS 8.8 but:

- The vulnerable code path is not used in your build (LLM infers from CVE description + your `notes`)
- You have compensating controls (WAF, segmentation)
- The affected data is public
- The service has low business criticality

A generic 8.8 becomes, say, a contextual 10. **You should not patch it urgently.**

---

## Why scores go _up_ from CVSS

Less common but critical. A CVE is CVSS 5.3 "medium" but:

- It leaks the exact type of data your system handles (PII)
- You are under GDPR / PCI-DSS — one breach triggers disclosure obligations
- The service is publicly exposed with no WAF
- The business impact of a disclosed breach exceeds normal scoring bounds

A generic 5.3 becomes, say, a contextual 52. **This is the CVE you patch first, and it was buried in your scanner report.**

---

## When to trust the Vens score

✅ You've described your context honestly and precisely in `config.yaml`
✅ Your `controls` reflect reality (no wishful thinking)
✅ You've added architectural detail in `notes` for non-obvious systems
✅ You've reviewed the `analysis.detail` field on the top 10 scores

---

## When to be cautious

⚠️ Generic or sparse `config.yaml` → scores will be generic
⚠️ You lie about controls → optimistic scores that miss real risk
⚠️ The LLM has no information about a very recent CVE (< 2 weeks) → score may regress to the generic CVSS interpretation
⚠️ Deeply custom internal CVEs → the LLM may not know the specifics; review manually

---

## So what do I do with CVSS?

CVSS still matters as the **input**. Your scanner produces it, Vens reads it, and the LLM uses it as a baseline before applying your context. You don't have to choose between the two — Vens is _CVSS plus context_, not CVSS replaced.

---

## Next

- Put this into practice: **[Prioritize a CVE backlog](../guides/prioritize-cves.md)**
- Refine your context: **[Describe your system context](../guides/configuration.md)**
