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

// Package contract holds the contracts of the 16 OWASP Risk Rating factors
// as #310 scores them: the question each model-answered factor gets and its
// closed answers, the rules that turn the answers, the config and a CVE's
// CVSS v3 vectors into the calculator's levels, and the requests and JSON
// Schemas of the calls that ask the questions.
//
// The model never gives a level. It picks a named answer from a closed list,
// which the call's schema enforces, and Go maps that answer to a level of
// pkg/owasp.
package contract

import "slices"

// Factor is one of the 16 factors, named by the abbreviation the vector
// writes. Nine are model-answered, each through a question of its own; Skill
// level, Size, Ease of discovery and Awareness are Go's alone, and so are
// Loss of confidentiality, integrity and availability, read from the CVE's
// CVSS v3 vectors.
type Factor string

const (
	SL  Factor = "SL"
	M   Factor = "M"
	O   Factor = "O"
	S   Factor = "S"
	ED  Factor = "ED"
	EE  Factor = "EE"
	A   Factor = "A"
	ID  Factor = "ID"
	LC  Factor = "LC"
	LI  Factor = "LI"
	LAV Factor = "LAV"
	LAC Factor = "LAC"
	FD  Factor = "FD"
	RD  Factor = "RD"
	NC  Factor = "NC"
	PV  Factor = "PV"
)

// order is the order the calls of a batch ask the questions in. It never
// depends on which questions the batch's first CVE gets.
var order = [...]Factor{M, O, EE, ID, LAC, FD, RD, NC, PV}

// Order returns the nine model-answered factors in the order the calls of a
// batch ask them.
func Order() []Factor {
	return slices.Clone(order[:])
}

var factorNames = map[Factor]string{
	SL: "Skill level", M: "Motive", O: "Opportunity", S: "Size",
	ED: "Ease of discovery", EE: "Ease of exploit", A: "Awareness", ID: "Intrusion detection",
	LC: "Loss of confidentiality", LI: "Loss of integrity", LAV: "Loss of availability", LAC: "Loss of accountability",
	FD: "Financial damage", RD: "Reputation damage", NC: "Non-compliance", PV: "Privacy violation",
}

// Name returns the factor's name as OWASP's methodology writes it.
func (f Factor) Name() string {
	return factorNames[f]
}

// Counter returns the counter a question's cannot_tell adds to, "" for a
// factor Go sets alone.
func (f Factor) Counter() string {
	return table[f].counter
}

// Reading is how Go read an asked factor's answer.
type Reading int

const (
	// Answered: one of the listed answers other than cannot_tell.
	Answered Reading = iota + 1
	// CannotTell: cannot_tell, or for Intrusion detection a set holding it.
	// It takes the factor's worst case and is counted.
	CannotTell
	// Invalid: an answer off the list, which only a provider ignoring the
	// schema can give. It is read as cannot_tell and counted with it.
	Invalid
	// NoDescription: no row of the CVE has a description, a prerequisite of
	// Motive's, Opportunity's and Ease of exploit's answers. Those questions
	// are not asked, and each takes cannot_tell's level, counted.
	NoDescription
)

var readingNames = [...]string{
	Answered: "answered", CannotTell: "cannot_tell", Invalid: "invalid", NoDescription: "no_description",
}

func (r Reading) String() string {
	if r > 0 && int(r) < len(readingNames) {
		return readingNames[r]
	}
	return "unknown"
}

// MarshalText writes the reading by name.
func (r Reading) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}

// Source is where a level came from.
type Source int

const (
	// SourceAnswer: the model's answer as Go read it, cannot_tell included,
	// crossed with the config for a factor Go crosses it with; for a question
	// not asked for want of a description, cannot_tell's.
	SourceAnswer Source = iota + 1
	// SourceConstant: the same level for every finding.
	SourceConstant
	// SourceConfig: the config alone, the question not asked or its answer
	// capped.
	SourceConfig
	// SourceFloor: Privacy violation's floor, the CVE's usable CVSS v3
	// vectors giving C:N, the question not asked.
	SourceFloor
	// SourceAdjustment: a flagged CVE's adjustment, which lowered the level.
	SourceAdjustment
	// SourceCVSS: the CVE's CVSS v3 vectors, crossed with data_sensitivity
	// for Loss of confidentiality; with no usable v3 vector, the worst
	// level, counted.
	SourceCVSS
	// SourceWorstCase: OWASP's worst case for what no config field
	// declares, the attacking group's skill: Skill level
	// (OWASP_Risk_Rating_Methodology.md:87-89, :111).
	SourceWorstCase
)

var sourceNames = [...]string{
	SourceAnswer: "answer", SourceConstant: "constant", SourceConfig: "config",
	SourceFloor: "floor", SourceAdjustment: "adjustment", SourceCVSS: "cvss",
	SourceWorstCase: "worst_case",
}

func (s Source) String() string {
	if s > 0 && int(s) < len(sourceNames) {
		return sourceNames[s]
	}
	return "unknown"
}

// MarshalText writes the source by name.
func (s Source) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

const cannotTell = "cannot_tell"

// An answer is one closed answer: the id the model replies with, the text the
// request shows for it, and what Go maps it to, a level or, for a factor Go
// crosses with the config, the value it crosses.
type answer[V any] struct {
	id    string
	text  string
	value V
}

// A contract is a model-answered factor's question and its closed answers in
// the order the request lists them, cannot_tell last.
type contract[V any] struct {
	factor   Factor
	question string
	answers  []answer[V]
	// counter is what cannot_tell, or an answer read as it, adds to.
	counter string
}

// read maps an answer id to its value. An id off the list reads as
// cannot_tell.
func (c contract[V]) read(id string) (V, Reading) {
	for _, a := range c.answers {
		if a.id != id {
			continue
		}
		if id == cannotTell {
			return a.value, CannotTell
		}
		return a.value, Answered
	}
	return c.answers[len(c.answers)-1].value, Invalid
}

// shown is what the request and the schema read of a contract.
type shown struct {
	factor   Factor
	question string
	ids      []string
	texts    []string
	counter  string
}

func (c contract[V]) shown() shown {
	s := shown{factor: c.factor, question: c.question, counter: c.counter}
	for _, a := range c.answers {
		s.ids = append(s.ids, a.id)
		s.texts = append(s.texts, a.text)
	}
	return s
}
