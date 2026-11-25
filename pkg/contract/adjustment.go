// Copyright 2025 venslabs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// A flagged CVE first gets the ordinary questions; then one call shows it the
// evidence the flag rests on and lets it lower Opportunity, when a row
// describes the CVE, and Privacy violation, when the CVE was asked it, never
// raise them. Loss of confidentiality, integrity and availability are read
// from the CVSS v3 vectors: the confidentiality question corrects Privacy
// violation alone.

const adjustmentTemplate = `FLAGGED VULNERABILITY
{entry}

This vulnerability is flagged: its maintainers dispute it, or its severity sources disagree. Its entry carries the evidence: every CVSS vector published for it with its source, every vendor severity, {given}

QUESTIONS
{questions}

Choose cannot_tell only when the evidence does not decide.
Reply with {"reasoning": "...", {fields}}.`

// What the entry carries besides the vectors and the severities, as the
// adjustment's text names it: the Opportunity answer, to reconsider, when a
// row describes the CVE; the flag's evidence alone otherwise.
const (
	givenAnswer  = "the flag's quoted evidence, and the answer it was given without that evidence. Reconsider it from that evidence."
	givenNothing = "and the flag's quoted evidence."
)

const (
	adjustOpportunityLine     = `opportunity: Given this evidence, what access or resources do {group} really need to exploit it here? Answer with one of: {o_ids}; keep, if the answer it was given stands; or cannot_tell.`
	adjustConfidentialityLine = `confidentiality: Given this evidence, can exploiting it here affect confidentiality at all? Answer with affected, not_affected or cannot_tell.`
)

// The flags that send a CVE to the adjustment.
const (
	MaintainerDisputed = "maintainer_disputed"
	SeverityContested  = "severity_contested"
)

// Flag is one flag a row of a flagged CVE raised: its name, the evidence the
// adjustment quotes for it, and that row's package as Row.Package names it.
type Flag struct {
	Name     string `json:"flag"`
	Evidence string `json:"evidence"`
	Package  string `json:"package"`
}

// adjustmentEntry is a flagged CVE's entry with the evidence its ordinary
// questions were not shown: every vendor severity with the packages it came
// from, every distinct vector of every version and source, C, I and A
// included, the flags, and the Opportunity answer the ordinary call gave,
// when a row describes the CVE.
type adjustmentEntry struct {
	entry
	VendorSeverity []sourcedSeverity `json:"vendorSeverity"`
	CVSS           []sourcedVector   `json:"cvss"`
	Flags          []Flag            `json:"flags"`
	Answers        *shownAnswers     `json:"answers,omitempty"`
}

type sourcedSeverity struct {
	Source   string   `json:"source"`
	Severity string   `json:"severity"`
	Packages []string `json:"packages"`
}

type sourcedVector struct {
	Source  string `json:"source"`
	Version string `json:"version"`
	Vector  string `json:"vector"`
}

// shownAnswers is the baseline the adjustment may lower and shows:
// Opportunity's answer.
type shownAnswers struct {
	Opportunity string `json:"opportunity"`
}

const (
	adjustOpportunity     = "opportunity"
	adjustConfidentiality = "confidentiality"
)

// AdjustmentFields lists the fields a flagged CVE's adjustment asks, in the
// order its request asks them: opportunity, when a row describes the CVE, a
// description being a prerequisite of any Opportunity answer, ordinary or
// adjusted; then confidentiality, when the CVE was asked Privacy violation,
// which the answer not_affected lowers. With no field left, there is no
// adjustment to make.
func AdjustmentFields(d Deployment, c CVE) []string {
	p := profileOf(c)
	var fields []string
	if p.described {
		fields = append(fields, adjustOpportunity)
	}
	if asked(PV, d, p) {
		fields = append(fields, adjustConfidentiality)
	}
	return fields
}

// AdjustmentRequest returns the request of a flagged CVE's adjustment call:
// its entry with every row's evidence, its flags and, when a row describes
// it, the Opportunity answer its ordinary call gave, then one question per
// field AdjustmentFields lists. The call shares the run's system prompt.
func AdjustmentRequest(d Deployment, c CVE, flags []Flag, given Answers) (string, error) {
	if err := d.Check(); err != nil {
		return "", err
	}
	entry, err := newAdjustmentEntry(c, flags, given)
	if err != nil {
		return "", err
	}
	fields := AdjustmentFields(d, c)
	if len(fields) == 0 {
		return "", noAdjustment(c)
	}
	e, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	shown := givenNothing
	if entry.Answers != nil {
		shown = givenAnswer
	}
	var questions, replied []string
	for _, name := range fields {
		line := adjustConfidentialityLine
		if name == adjustOpportunity {
			line = fill(adjustOpportunityLine, "{group}", group(d), "{o_ids}", strings.Join(lowerable(), ", "))
		}
		questions = append(questions, line)
		replied = append(replied, `"`+name+`": "..."`)
	}
	return fill(adjustmentTemplate,
		"{entry}", string(e),
		"{given}", shown,
		"{questions}", strings.Join(questions, "\n"),
		"{fields}", strings.Join(replied, ", "),
	), nil
}

// AdjustmentSchema returns the JSON Schema of a flagged CVE's adjustment
// call: the reasoning; then, for each field AdjustmentFields lists,
// Opportunity's answer, keep or cannot_tell, or confidentiality's affected,
// not_affected or cannot_tell.
func AdjustmentSchema(d Deployment, c CVE) (json.RawMessage, error) {
	fields := AdjustmentFields(d, c)
	if len(fields) == 0 {
		return nil, noAdjustment(c)
	}
	ps := []property{{"reasoning", &schema{Type: "string"}}}
	for _, name := range fields {
		answers := enum(affected, notAffected, cannotTell)
		if name == adjustOpportunity {
			answers = enum(append(lowerable(), keep, cannotTell)...)
		}
		ps = append(ps, property{name, answers})
	}
	return json.Marshal(object(ps...))
}

func noAdjustment(c CVE) error {
	return fmt.Errorf("%s has nothing to adjust: no row describes it and it was not asked %s", c.ID, PV)
}

// lowerable returns Opportunity's answers besides cannot_tell, the ones an
// adjustment can lower its level to.
func lowerable() []string {
	ids := table[O].ids
	return slices.Clone(ids[:len(ids)-1])
}

// newAdjustmentEntry writes a flagged CVE's entry, its evidence and, when a
// row describes it, the Opportunity answer its ordinary call gave, which is
// the baseline the adjustment may lower.
func newAdjustmentEntry(c CVE, flags []Flag, given Answers) (adjustmentEntry, error) {
	if err := checkCVE(c); err != nil {
		return adjustmentEntry{}, err
	}
	if err := CheckFlags(flags, c); err != nil {
		return adjustmentEntry{}, err
	}
	if err := checkGiven(c, given); err != nil {
		return adjustmentEntry{}, err
	}
	e := adjustmentEntry{
		entry:          newEntry(c, true),
		VendorSeverity: vendorSeverities(c),
		CVSS:           []sourcedVector{},
		Flags:          flags,
	}
	if c.Described() {
		e.Answers = &shownAnswers{Opportunity: given.O}
	}
	for _, v := range c.vectors() {
		sv := sourcedVector{Source: v.Source, Version: v.Version, Vector: v.Vector}
		if !slices.Contains(e.CVSS, sv) {
			e.CVSS = append(e.CVSS, sv)
		}
	}
	return e, nil
}

// vendorSeverities lists each source's severity once, with the names of the
// packages whose rows give it, sorted.
func vendorSeverities(c CVE) []sourcedSeverity {
	out := []sourcedSeverity{}
	for _, r := range c.Rows {
		for _, s := range r.VendorSeverities {
			i := slices.IndexFunc(out, func(x sourcedSeverity) bool { return x.Source == s.Source && x.Severity == s.Severity })
			if i < 0 {
				out = append(out, sourcedSeverity{Source: s.Source, Severity: s.Severity, Packages: []string{}})
				i = len(out) - 1
			}
			if r.PkgName != "" && !slices.Contains(out[i].Packages, r.PkgName) {
				out[i].Packages = append(out[i].Packages, r.PkgName)
			}
		}
	}
	for _, s := range out {
		slices.Sort(s.Packages)
	}
	return out
}

// CheckFlags checks a flagged CVE's flags as its adjustment request does:
// each names one of the two flags, quotes its evidence and names a row of the
// CVE by its package.
func CheckFlags(flags []Flag, c CVE) error {
	if len(flags) == 0 {
		return errors.New("a CVE with no flag gets no adjustment")
	}
	for _, f := range flags {
		switch {
		case f.Name != MaintainerDisputed && f.Name != SeverityContested:
			return fmt.Errorf("%q is not a flag", f.Name)
		case strings.TrimSpace(f.Evidence) == "":
			return fmt.Errorf("%s on %s quotes no evidence", f.Name, c.ID)
		case !slices.ContainsFunc(c.Rows, func(r Row) bool { return r.Package() == f.Package }):
			return fmt.Errorf("%s names the package %q, not one of %s's", f.Name, f.Package, c.ID)
		}
	}
	return nil
}

// checkGiven checks the baseline the adjustment shows: the Opportunity
// answer of a CVE a row describes, one its question lists, cannot_tell
// included. A CVE no row describes was not asked Opportunity and has no
// answer.
func checkGiven(c CVE, given Answers) error {
	switch {
	case !c.Described() && given.O != "":
		return fmt.Errorf("%s was not asked, %s described by no row, yet has the answer %q", O, c.ID, given.O)
	case c.Described() && !slices.Contains(table[O].ids, given.O):
		return fmt.Errorf("%s's answer %q is not one its question lists", O, given.O)
	}
	return nil
}
