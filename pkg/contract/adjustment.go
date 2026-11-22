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

	"github.com/venslabs/vens/pkg/cvss"
)

// A flagged CVE first gets the ordinary questions; then one call shows it the
// evidence the flag rests on and lets it lower Opportunity, when a row
// describes the CVE, and each axis Applicability did not floor, never raise
// them. A CVE not reachable here has those at their lowest already: its call
// shows reachability's answer as the one given and asks confidentiality
// alone, which Privacy violation follows.

const adjustmentTemplate = `FLAGGED VULNERABILITY
{entry}

This vulnerability is flagged: its maintainers dispute it, or its severity sources disagree. Its entry carries the evidence: every CVSS vector published for it with its source, every vendor severity, the flag's quoted evidence, and {given}. Reconsider it from that evidence.

QUESTIONS
{questions}

Choose cannot_tell only when the evidence does not decide.
Reply with {"reasoning": "...", {fields}}.`

// What the entry's answers are, as the adjustment's text names them: the
// answers of the questions it may lower, or, for a CVE not reachable here,
// reachability's.
const (
	givenAnswers      = "the answers it was given without that evidence"
	givenNotReachable = "the answer it was given without that evidence: not reachable here, as reachability is defined above"
)

const (
	adjustOpportunityLine = `opportunity: Given this evidence, what access or resources do {group} really need to exploit it here? Answer with one of: {o_ids}; keep, if the answer it was given stands; or cannot_tell.`
	adjustAxisLine        = `{axis}: Given this evidence, can exploiting it here affect {axis} at all? Answer with affected, not_affected or cannot_tell.`
)

// The flags that send a CVE to the adjustment.
const (
	MaintainerDisputed = "maintainer_disputed"
	SeverityContested  = "severity_contested"
)

// axisNames names the axes, indexed as cvss's, as the adjustment's questions
// and reply do.
var axisNames = [3]string{
	cvss.Confidentiality: "confidentiality",
	cvss.Integrity:       "integrity",
	cvss.Availability:    "availability",
}

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
// included, the flags, and the answers the ordinary calls gave.
type adjustmentEntry struct {
	entry
	VendorSeverity []sourcedSeverity `json:"vendorSeverity"`
	CVSS           []sourcedVector   `json:"cvss"`
	Flags          []Flag            `json:"flags"`
	Answers        shownAnswers      `json:"answers"`
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

// shownAnswers are the baselines the adjustment may lower: Opportunity's
// answer, when a row describes the CVE, and the answer of each axis's factor
// Applicability did not floor; for a CVE not reachable here, reachability's
// answer alone.
type shownAnswers struct {
	Reachability    *string `json:"reachability,omitempty"`
	Opportunity     *string `json:"opportunity,omitempty"`
	Confidentiality *string `json:"confidentiality,omitempty"`
	Integrity       *string `json:"integrity,omitempty"`
	Availability    *string `json:"availability,omitempty"`
}

const adjustOpportunity = "opportunity"

// AdjustmentFields lists the fields a flagged CVE's adjustment asks, in the
// order its request asks them: opportunity, when a row describes the CVE,
// then each axis Applicability did not floor (indexed as cvss's axes). A
// description is a prerequisite of any Opportunity answer, ordinary or
// adjusted. A CVE whose reachability answer says not reachable has its
// Opportunity and axes at their lowest: it is asked confidentiality alone,
// when it was asked Privacy violation, which the answer not_affected lowers.
// With no field left, there is no adjustment to make.
func AdjustmentFields(d Deployment, c CVE, floored [3]bool, reachabilityAnswer string) []string {
	if !Reachable(reachabilityAnswer) {
		if asked(PV, d, floored, c.Described()) {
			return []string{axisNames[cvss.Confidentiality]}
		}
		return nil
	}
	var fields []string
	if c.Described() {
		fields = append(fields, adjustOpportunity)
	}
	for axis, name := range axisNames {
		if !floored[axis] {
			fields = append(fields, name)
		}
	}
	return fields
}

// AdjustmentRequest returns the request of a flagged CVE's adjustment call:
// its entry with every row's evidence, its flags and the answers its
// ordinary calls gave, reachability's alone for a CVE not reachable here,
// then one question per field AdjustmentFields lists. The call shares the
// run's system prompt.
func AdjustmentRequest(d Deployment, c CVE, floored [3]bool, flags []Flag, given Answers) (string, error) {
	if err := d.Check(); err != nil {
		return "", err
	}
	entry, err := newAdjustmentEntry(c, floored, flags, given)
	if err != nil {
		return "", err
	}
	fields := AdjustmentFields(d, c, floored, given.R)
	if len(fields) == 0 {
		return "", noAdjustment(c, given.R)
	}
	shown := givenAnswers
	if !Reachable(given.R) {
		shown = givenNotReachable
	}
	e, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	var questions, replied []string
	for _, name := range fields {
		line := fill(adjustAxisLine, "{axis}", name)
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
// Opportunity's answer, keep or cannot_tell, or an axis's affected,
// not_affected or cannot_tell.
func AdjustmentSchema(d Deployment, c CVE, floored [3]bool, reachabilityAnswer string) (json.RawMessage, error) {
	fields := AdjustmentFields(d, c, floored, reachabilityAnswer)
	if len(fields) == 0 {
		return nil, noAdjustment(c, reachabilityAnswer)
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

func noAdjustment(c CVE, reachabilityAnswer string) error {
	if !Reachable(reachabilityAnswer) {
		return fmt.Errorf("%s has nothing left to adjust: it is not reachable here and was not asked %s", c.ID, PV)
	}
	return fmt.Errorf("%s has nothing left to adjust: no row describes it and every axis is floored", c.ID)
}

// lowerable returns Opportunity's answers besides cannot_tell, the ones an
// adjustment can lower its level to.
func lowerable() []string {
	ids := table[O].ids
	return slices.Clone(ids[:len(ids)-1])
}

// newAdjustmentEntry writes a flagged CVE's entry, its evidence and the
// answers its ordinary calls gave, which are the baselines the adjustment may
// lower. A CVE no row describes was not asked Opportunity: it shows none. A
// CVE not reachable here was asked none of them: it shows reachability's
// answer.
func newAdjustmentEntry(c CVE, floored [3]bool, flags []Flag, given Answers) (adjustmentEntry, error) {
	if err := checkCVE(c); err != nil {
		return adjustmentEntry{}, err
	}
	if err := CheckFlags(flags, c); err != nil {
		return adjustmentEntry{}, err
	}
	if err := checkGiven(c, given, floored); err != nil {
		return adjustmentEntry{}, err
	}
	e := adjustmentEntry{
		entry:          newEntry(c, true),
		VendorSeverity: vendorSeverities(c),
		CVSS:           []sourcedVector{},
		Flags:          flags,
	}
	for _, v := range c.vectors() {
		sv := sourcedVector{Source: v.Source, Version: v.Version, Vector: v.Vector}
		if !slices.Contains(e.CVSS, sv) {
			e.CVSS = append(e.CVSS, sv)
		}
	}
	if !Reachable(given.R) {
		e.Answers.Reachability = &given.R
		return e, nil
	}
	if c.Described() {
		e.Answers.Opportunity = &given.O
	}
	if !floored[cvss.Confidentiality] {
		e.Answers.Confidentiality = &given.LC
	}
	if !floored[cvss.Integrity] {
		e.Answers.Integrity = &given.LI
	}
	if !floored[cvss.Availability] {
		e.Answers.Availability = &given.LAV
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

// checkGiven checks the baselines the adjustment shows: Opportunity's answer,
// when a row describes the CVE, and, for each axis Applicability did not
// floor, its factor's, each one its question lists, cannot_tell included. An
// axis floored, and Opportunity for a CVE no row describes, were not asked
// and have no answer; nor were any of the four for a CVE not reachable here.
func checkGiven(c CVE, given Answers, floored [3]bool) error {
	if !Reachable(given.R) {
		factors, answers := [...]Factor{O, LC, LI, LAV}, [...]string{given.O, given.LC, given.LI, given.LAV}
		for i, f := range factors {
			if answers[i] != "" {
				return fmt.Errorf("%s was not asked, %s not reachable here, yet has the answer %q", f, c.ID, answers[i])
			}
		}
		return nil
	}
	switch {
	case !c.Described() && given.O != "":
		return fmt.Errorf("%s was not asked, %s described by no row, yet has the answer %q", O, c.ID, given.O)
	case c.Described() && !slices.Contains(table[O].ids, given.O):
		return fmt.Errorf("%s's answer %q is not one its question lists", O, given.O)
	}
	factors := [3]Factor{cvss.Confidentiality: LC, cvss.Integrity: LI, cvss.Availability: LAV}
	answers := [3]string{cvss.Confidentiality: given.LC, cvss.Integrity: given.LI, cvss.Availability: given.LAV}
	for axis, f := range factors {
		switch {
		case floored[axis] && answers[axis] != "":
			return fmt.Errorf("%s was not asked, its axis floored, yet has the answer %q", f, answers[axis])
		case !floored[axis] && !slices.Contains(table[f].ids, answers[axis]):
			return fmt.Errorf("%s's answer %q is not one its question lists", f, answers[axis])
		}
	}
	return nil
}
