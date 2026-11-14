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
// evidence the flag rests on and lets it lower Opportunity and each axis
// Applicability did not floor, never raise them.

const adjustmentTemplate = `FLAGGED VULNERABILITY
{entry}

This vulnerability is flagged: its maintainers dispute it, or its severity sources disagree. Its entry carries the evidence: every CVSS vector published for it with its source, every vendor severity, the flag's quoted evidence, and the answers it was given without that evidence. Reconsider it from that evidence.

QUESTIONS
{questions}

Choose cannot_tell only when the evidence does not decide.
Reply with {"reasoning": "...", {fields}}.`

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
// adjustment quotes for it, and that row's package.
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
	Answers        givenAnswers      `json:"answers"`
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

// givenAnswers are the baselines the adjustment may lower: Opportunity's
// answer, and the answer of each axis's factor Applicability did not floor.
type givenAnswers struct {
	Opportunity     string  `json:"opportunity"`
	Confidentiality *string `json:"confidentiality,omitempty"`
	Integrity       *string `json:"integrity,omitempty"`
	Availability    *string `json:"availability,omitempty"`
}

// AdjustmentRequest returns the request of a flagged CVE's adjustment call:
// its entry with every row's evidence, its flags and the answers its
// ordinary calls gave, then the question on Opportunity and one per axis
// Applicability did not floor (indexed as cvss's axes). The call shares the
// run's system prompt.
func AdjustmentRequest(d Deployment, c CVE, floored [3]bool, flags []Flag, given Answers) (string, error) {
	if err := d.Check(); err != nil {
		return "", err
	}
	if err := checkCVE(c); err != nil {
		return "", err
	}
	if err := checkFlags(flags); err != nil {
		return "", err
	}
	e, err := json.Marshal(newAdjustmentEntry(c, floored, flags, given))
	if err != nil {
		return "", err
	}
	questions := []string{fill(adjustOpportunityLine, "{group}", group(d), "{o_ids}", strings.Join(lowerable(), ", "))}
	fields := []string{`"opportunity": "..."`}
	for axis, name := range axisNames {
		if !floored[axis] {
			questions = append(questions, fill(adjustAxisLine, "{axis}", name))
			fields = append(fields, `"`+name+`": "..."`)
		}
	}
	return fill(adjustmentTemplate,
		"{entry}", string(e),
		"{questions}", strings.Join(questions, "\n"),
		"{fields}", strings.Join(fields, ", "),
	), nil
}

// AdjustmentSchema returns the JSON Schema of a flagged CVE's adjustment
// call: the reasoning; Opportunity's answer, keep or cannot_tell; and
// affected, not_affected or cannot_tell for each axis Applicability did not
// floor.
func AdjustmentSchema(floored [3]bool) (json.RawMessage, error) {
	ps := []property{
		{"reasoning", &schema{Type: "string"}},
		{"opportunity", enum(append(lowerable(), keep, cannotTell)...)},
	}
	for axis, name := range axisNames {
		if !floored[axis] {
			ps = append(ps, property{name, enum(affected, notAffected, cannotTell)})
		}
	}
	return json.Marshal(object(ps...))
}

// lowerable returns Opportunity's answers besides cannot_tell, the ones an
// adjustment can lower its level to.
func lowerable() []string {
	ids := table[O].ids
	return slices.Clone(ids[:len(ids)-1])
}

func newAdjustmentEntry(c CVE, floored [3]bool, flags []Flag, given Answers) adjustmentEntry {
	e := adjustmentEntry{
		entry:          newEntry(c),
		VendorSeverity: []sourcedSeverity{},
		CVSS:           []sourcedVector{},
		Flags:          flags,
		Answers:        givenAnswers{Opportunity: given.O},
	}
	for _, r := range c.Rows {
		for _, s := range r.VendorSeverities {
			i := slices.IndexFunc(e.VendorSeverity, func(x sourcedSeverity) bool {
				return x.Source == s.Source && x.Severity == s.Severity
			})
			if i < 0 {
				e.VendorSeverity = append(e.VendorSeverity, sourcedSeverity{Source: s.Source, Severity: s.Severity, Packages: []string{}})
				i = len(e.VendorSeverity) - 1
			}
			if r.PkgName != "" && !slices.Contains(e.VendorSeverity[i].Packages, r.PkgName) {
				e.VendorSeverity[i].Packages = append(e.VendorSeverity[i].Packages, r.PkgName)
			}
		}
	}
	for _, s := range e.VendorSeverity {
		slices.Sort(s.Packages)
	}
	for _, v := range c.vectors() {
		sv := sourcedVector{Source: v.Source, Version: v.Version, Vector: v.Vector}
		if !slices.Contains(e.CVSS, sv) {
			e.CVSS = append(e.CVSS, sv)
		}
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
	return e
}

func checkFlags(flags []Flag) error {
	if len(flags) == 0 {
		return errors.New("a CVE with no flag gets no adjustment")
	}
	for _, f := range flags {
		if f.Name != MaintainerDisputed && f.Name != SeverityContested {
			return fmt.Errorf("%q is not a flag", f.Name)
		}
	}
	return nil
}
