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

package generator

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/owasp"
)

// answersFile is answers.json, which --debug-dir gets once per run: per CVE
// and factor, the answer as the reply gave it and how Go read it, the level
// and where it came from; and the counters, per CVE and summed over the run.
// It holds no reasoning and no CVE text.
type answersFile struct {
	Vulnerabilities []answersEntry `json:"vulnerabilities"`
	Counters        map[string]int `json:"counters"`
}

type answersEntry struct {
	VulnID string `json:"vulnId"`
	// Factors holds the 16 in the vector's order.
	Factors  []factorRecord `json:"factors"`
	Counters []string       `json:"counters,omitempty"`
}

type factorRecord struct {
	Factor contract.Factor `json:"factor"`
	// Answer is the question's answer, an id or for Intrusion detection a
	// list of them; absent when the question was not asked.
	Answer  any              `json:"answer,omitempty"`
	Reading contract.Reading `json:"reading,omitempty"`
	// Adjusted is a flagged CVE's adjustment answer for Opportunity or an
	// axis's factor, as the reply gave it.
	Adjusted string          `json:"adjusted,omitempty"`
	Level    int             `json:"level"`
	Source   contract.Source `json:"source"`
}

// rated records a rated CVE for answers.json and adds its counters to the
// run's.
func (run *scoringRun) rated(c *cve, a *assessment, l contract.Levels) {
	counters := c.counters(l)
	for _, name := range counters {
		run.counters[name]++
	}
	levels := vectorLevels(l.Vector)
	e := answersEntry{VulnID: c.id(), Counters: counters}
	for _, f := range vectorOrder {
		r := factorRecord{Factor: f, Reading: l.Readings[f], Level: levels[f], Source: l.Sources[f]}
		if c.asks(f) {
			r.Answer = answerOf(a.answers, f)
		}
		if a.adjusted != nil {
			r.Adjusted = adjustedAnswer(*a.adjusted, f)
		}
		e.Factors = append(e.Factors, r)
	}
	run.entries = append(run.entries, e)
}

// writeAnswers writes answers.json to the run's debug directory, if any.
func (g *Generator) writeAnswers(ctx context.Context, run *scoringRun) {
	if g.debugRunDir == "" {
		return
	}
	b, err := json.MarshalIndent(answersFile{Vulnerabilities: run.entries, Counters: run.counters}, "", "  ")
	if err != nil {
		slog.ErrorContext(ctx, "failed to write a debug file", "file", "answers.json", "error", err)
		return
	}
	g.writeDebugFile(ctx, "answers.json", string(b)+"\n")
}

// vectorOrder is the 16 factors in the order the vector writes them.
var vectorOrder = [...]contract.Factor{
	contract.SL, contract.M, contract.O, contract.S, contract.ED, contract.EE, contract.A, contract.ID,
	contract.LC, contract.LI, contract.LAV, contract.LAC, contract.FD, contract.RD, contract.NC, contract.PV,
}

func vectorLevels(v owasp.Vector) map[contract.Factor]int {
	return map[contract.Factor]int{
		contract.SL: int(v.SL), contract.M: int(v.M), contract.O: int(v.O), contract.S: int(v.S),
		contract.ED: int(v.ED), contract.EE: int(v.EE), contract.A: int(v.A), contract.ID: int(v.ID),
		contract.LC: int(v.LC), contract.LI: int(v.LI), contract.LAV: int(v.LAV), contract.LAC: int(v.LAC),
		contract.FD: int(v.FD), contract.RD: int(v.RD), contract.NC: int(v.NC), contract.PV: int(v.PV),
	}
}

func answerOf(a contract.Answers, f contract.Factor) any {
	if f == contract.ID {
		if a.ID == nil {
			return []string{}
		}
		return a.ID
	}
	return *answerField(&a, f)
}

func adjustedAnswer(a contract.Adjusted, f contract.Factor) string {
	switch f {
	case contract.O:
		return a.Opportunity
	case contract.LC:
		return a.Confidentiality
	case contract.LI:
		return a.Integrity
	case contract.LAV:
		return a.Availability
	}
	return ""
}
