# CVSS vs OWASP contextual scoring

**Who this is for:** anyone who wants to understand why Vens scores differ from their scanner.
**By the end of this page:** you know what the OWASP rating represents, how vens computes it, and why it moves.

---

## The one-sentence answer

**A CVSS base score describes the vulnerability. OWASP Risk Rating describes the risk to _your_ system.**

The base score your scanner prints is the same wherever that component runs. A CVE has as many OWASP ratings as there are systems running it.

CVSS does have environmental metrics for exactly this, and they are the right idea. They also arrive empty: filling them takes a judgment per CVE and per asset that nobody produces at scale. That gap is what Vens fills.

---

## A concrete example

*The CVE id and the levels below are illustrative, not a real published CVE or a recorded run.*

Two services both contain `libfoo-1.2.3` with a hypothetical CVE `CVE-XXXX-YYYY`. The CVE is a denial-of-service in a CSV parsing function, and its CVSS vectors give no confidentiality or integrity impact.

**CVSS says:** 7.5 HIGH. That is the base score, and it is the same wherever the component runs.

**Vens says, for service A (internal dashboard, no CSV parsing in production):**
```
Vector:   SL:9/M:1/O:0/S:4/ED:9/EE:1/A:9/ID:8/LC:2/LI:1/LAV:1/LAC:7/FD:1/RD:1/NC:2/PV:3
Severity: low      (likelihood 5.13 MEDIUM, impact 2.75 LOW)
Score:    14.09
Why:      The model answers that reaching the parser takes full access to the
          host and that exploiting it is theoretical here; an outage would
          touch a secondary function. The CVSS vectors floor confidentiality,
          integrity and privacy.
```

**Vens says, for service B (public checkout, parses uploaded CSVs, GDPR):**
```
Vector:   SL:9/M:4/O:9/S:9/ED:9/EE:5/A:9/ID:8/LC:2/LI:1/LAV:7/LAC:7/FD:7/RD:5/NC:2/PV:3
Severity: high     (likelihood 7.75 HIGH, impact 4.25 MEDIUM)
Score:    32.94
Why:      The model answers that the CSV upload is open to anonymous
          Internet users, so no access is needed, and that an outage stops
          what the service exists to do, with a significant effect on
          annual profit.
```

Same CVE, same base score, two different risks. The model answered the questions; vens computed every level, the severity and the score.

---

## How vens rates a CVE

OWASP's Risk Rating Methodology rates a vulnerability from 16 factors, each with a few named levels from 0 to 9. vens sets each factor in one of three ways:

1. **Set by vens (4 factors).** Skill level, Ease of discovery and Awareness are 9 for every finding: each finding is a published CVE that a scanner matched, so vens takes OWASP's worst case for them. Size comes from your declared `exposure`.
2. **Read from the model's answer (8 factors).** The model gets one question per call, about a batch of CVEs, and picks one named answer from a closed list that always includes `cannot_tell`. vens maps the answer to the factor's level; `cannot_tell` maps to the worst case and is counted.
3. **An answer combined with a declared field (4 factors).** vens crosses the model's answer with a field of `config.yaml` the question does not show: Intrusion detection with `detection`, Loss of confidentiality with `data_sensitivity`, Loss of accountability with `traceability`, Privacy violation with `data_subjects`.

Four factors also have a CVSS floor: when every CVSS vector of the CVE rates the axis as no impact, vens asks no question and sets Loss of confidentiality to 2, Loss of integrity to 1 and Loss of availability to 1, and Privacy violation, which follows confidentiality, to 3.

A question is asked only when the factor's contract requires it: at most 12 questions per CVE. A CVE whose description says it is disputed or not a security issue, or that the scanner rates low while NVD rates it high or critical, is flagged: it gets one more call, the adjustment, which can lower Opportunity, a loss the CVSS vectors did not floor, and Privacy violation, and never raises a level.

| Factor | Group | Way | What sets the level |
|---|---|---|---|
| Skill level (SL) | likelihood | set by vens | always 9 |
| Motive (M) | likelihood | answer | the reward an exploit brings; shows `business_criticality` and `data_sensitivity` |
| Opportunity (O) | likelihood | answer | the access or resources an exploit needs; shows the CVSS AV, AT, PR and UI metrics |
| Size (S) | likelihood | set by vens | `exposure`: `internal` 4, `private` 6, `internet` 9 |
| Ease of discovery (ED) | likelihood | set by vens | always 9 |
| Ease of exploit (EE) | likelihood | answer | how easy the exploit is here; shows the CVSS AC, AT, PR and UI metrics and five of the controls, when set to `true` |
| Awareness (A) | likelihood | set by vens | always 9 |
| Intrusion detection (ID) | likelihood | answer and `detection` | the lowest declared level among the channels the model picks; 9 when `detection` is left out |
| Loss of confidentiality (LC) | technical impact | answer and `data_sensitivity` | how much data an exploit could read, crossed with the sensitivity; 2 when the CVSS vectors floor it |
| Loss of integrity (LI) | technical impact | answer | how much data an exploit could corrupt; 1 when the CVSS vectors floor it |
| Loss of availability (LAV) | technical impact | answer | how much of the service an exploit could interrupt; 1 when the CVSS vectors floor it |
| Loss of accountability (LAC) | technical impact | answer and `traceability` | whether the attacker must authenticate or can defeat attribution, crossed with what is recorded |
| Financial damage (FD) | business impact | answer | shows `business_criticality` |
| Reputation damage (RD) | business impact | answer | shows `business_criticality` |
| Non-compliance (NC) | business impact | answer | how serious a violation of the declared frameworks; 2, not asked, when none is declared |
| Privacy violation (PV) | business impact | answer and `data_subjects` | how many people's data could be disclosed, capped by the declared band; 3 when the CVSS vectors floor confidentiality |

Each field's effect is in the **[config.yaml reference](../reference/config-schema.md)**.

From the 16 levels, vens computes, in Go:

```
Likelihood       = average of SL, M, O, S, ED, EE, A, ID
Technical impact = average of LC, LI, LAV, LAC
Business impact  = average of FD, RD, NC, PV
Impact           = the larger of the technical and the business impact
Severity         = OWASP's matrix of the likelihood level and the impact level
Score            = Likelihood × Impact
```

A value below 3 is LOW, 3 to under 6 MEDIUM, 6 and up HIGH. The severity is OWASP's matrix:

| Likelihood \ Impact | LOW | MEDIUM | HIGH |
|---|---|---|---|
| **HIGH** | `medium` | `high` | `critical` |
| **MEDIUM** | `low` | `medium` | `high` |
| **LOW** | `info` | `low` | `medium` |

With Skill level, Ease of discovery and Awareness at 9, the likelihood never falls below 4.25, so it is never LOW and `info` never occurs: a `low` severity needs a LOW impact.

OWASP rates the impact on the business impact when the assessor holds good business information, and on the technical impact otherwise. vens cannot establish that per finding, so it takes the larger of the two: see **[Limitations](limitations.md)**.

The score is a vens extension: OWASP's method stops at the severity. It is likelihood × impact, each from 0 to 9, so it lies on a 0 to 81 scale, and it is published in `ratings[].score` to sort CVEs within a severity. The severity does not come from the score: a `high` can score lower than a `medium`, so sort by severity first.

The VEX carries, per CVE, `ratings[].method` `OWASP`, the 16 levels in `ratings[].vector`, the severity and the score. Anyone can recompute the severity and the score from the vector.

Full OWASP methodology: [owasp.org/www-community/OWASP_Risk_Rating_Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology).

---

## What changed in v0.7.0

This explains the mechanism; it is not a measurement of accuracy.

| | Up to v0.6 | Since v0.7.0 |
|---|---|---|
| What the model returns | four numbers from 0 to 9 per CVE: threat agent, vulnerability, technical impact, business impact | one named answer per question, from a closed list; never a number |
| Calls | one call per batch of CVEs | one call per question per batch, at most 12 questions per CVE, and one adjustment call per flagged CVE |
| The 16 levels in the vector | each of the four numbers repeated over its group's four factors | 4 set by vens, 8 read from an answer, 4 from an answer combined with a declared field |
| Impact | the average of the technical and the business impact | the larger of the two |
| Severity | bands of the score: 0–4 `info`, 5–19 `low`, 20–39 `medium`, 40–59 `high`, 60–81 `critical` | OWASP's matrix of the likelihood and impact levels; never `info` |
| Score | likelihood × impact | the same product, which no longer sets the severity |
| Compliance frameworks | the model was told to add 2 for a compliance violation | the Non-compliance question names them and the model judges the violation |
| `audit_requirement`, `ids`, `siem`, `edr` | shown to the model | move no score; `traceability` and `detection` replace them |

Expect ratings to change, whatever your `config.yaml` declares. Your file also needs `schema_version: 2`: see **[Migrating from vens v0.6](../reference/config-schema.md#migrating)**.

---

## Why scores go _down_ from CVSS

A CVE has a base score of 7.5 but:

- The model judges, from the CVE description and your `notes`, that the vulnerable code path is not used in your build, and answers Opportunity and Ease of exploit accordingly
- The model judges that a control set to `true` stands in the way of this exploit, and answers Ease of exploit accordingly
- The CVSS vectors give no confidentiality or integrity impact, so vens floors those losses
- Your `data_sensitivity` is `low` or `medium`, so vens reads the model's Loss of confidentiality answer in the non-sensitive column, or the declared `data_subjects` caps Privacy violation
- The model reads a low `business_criticality` and answers Financial damage and Reputation damage accordingly

A generic 7.5 can come out `low` or `medium`. That rating is an input to your review, not a verdict: how well it matches real risk is not measured, and vens runs no reachability check of its own (see [Limitations](limitations.md)).

---

## Why scores go _up_ from CVSS

A CVE has a base score of 5.3, "medium", but:

- The model answers that an exploit discloses data, and your `data_sensitivity` is `high` or `critical`, so vens reads that answer in the critical-data column
- You declared GDPR or PCI-DSS, and the model judges a breach a high profile violation
- You declared `exposure: internet`, which sets Size to 9, and `listener: present`, which the model reads
- The model answers that many people's personal data could be disclosed, within the declared `data_subjects`

A generic 5.3 can come out `high` or `critical`, which moves the CVE from deep in your scanner report to near the top of your review. That rating is an input to the review, not a patch decision.

---

## Before you use a rating

✅ You've described your context honestly and precisely in `config.yaml`
✅ You declared `traceability`, `detection` and `data_subjects` for what is in place
✅ Your `controls` reflect reality (no wishful thinking)
✅ You've added architectural detail in `notes` for non-obvious systems
✅ You've read the model's answers for the top CVEs, in the `--attest` claims or `--debug-dir`'s `answers.json`

---

## When to be cautious

⚠️ Generic or sparse `config.yaml` → the questions get generic answers
⚠️ Fields left out → their fallback: Intrusion detection 9 and Loss of accountability's `none` column on every finding, no cap on Privacy violation; the run summary counts them
⚠️ For the five controls the Ease of exploit question shows (`waf`, `ddos_protection`, `segmentation`, `zero_trust`, `antivirus`), claiming one as present when it is absent can lower ratings through the model's answer
⚠️ The LLM has no information about a very recent CVE (< 2 weeks) → its answers rest on the description alone, and `cannot_tell` takes the worst case
⚠️ Deeply custom internal CVEs → the LLM may not know the specifics; review manually

---

## So what do I do with CVSS?

The base score still matters as the **input** that puts the CVE in your report at all. Vens does not read the number. It reads the CVSS vectors: their C, I and A metrics let vens floor a loss the CVE cannot cause, and the Opportunity and Ease of exploit questions show the attack metrics. Every question also gets the CVE title, description and the scanner's severity label, then judges your context. You don't have to choose between the two, Vens is _CVSS plus context_, not CVSS replaced.

---

## Next

- Put this into practice: **[Prioritize a CVE backlog](../guides/prioritize-cves.md)**
- Refine your context: **[Describe your system context](../guides/configuration.md)**
