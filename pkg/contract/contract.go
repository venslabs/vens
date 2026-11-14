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
// CVSS vectors into the calculator's levels, and the requests and JSON
// Schemas of the calls that ask the questions.
//
// The model never gives a level. It picks a named answer from a closed list,
// which the call's schema enforces, and Go maps that answer to a level of
// pkg/owasp.
package contract

import "slices"

// Factor is a model-answered factor, named by the abbreviation the vector
// writes. Skill level, Size, Ease of discovery and Awareness are Go's alone
// and have no question.
type Factor string

const (
	M   Factor = "M"
	O   Factor = "O"
	EE  Factor = "EE"
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
var order = [...]Factor{M, O, EE, ID, LC, LI, LAV, LAC, FD, RD, NC, PV}

// Order returns the 12 model-answered factors in the order the calls of a
// batch ask them.
func Order() []Factor {
	return slices.Clone(order[:])
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
)

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
