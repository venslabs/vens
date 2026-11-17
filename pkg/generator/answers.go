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
	"cmp"
	"context"
	"encoding/json"
	"log/slog"

	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/owasp"
)

// answersFile is answers.json, which --debug-dir gets once per run: per CVE,
// how its adjustment read, and per factor, the answer as the reply gave it
// and how Go read it, the level and where it came from; the counters, per
// CVE and summed over the run; and the run summary's defects, each kind found
// with its total, {} when the replies held none. A failed run also lists,
// unrated, the CVEs of its failing batch it read answers for, and the defects
// counted before it stopped. It holds no reasoning and no CVE text Go sent,
// but keeps each answer verbatim: one off its list is the model's own text,
// which may quote the CVE's.
type answersFile struct {
	Vulnerabilities []answersEntry `json:"vulnerabilities"`
	Counters        map[string]int `json:"counters"`
	Defects         map[string]int `json:"defects"`
}

type answersEntry struct {
	VulnID string `json:"vulnId"`
	// Unrated marks a CVE of the batch a run failed in: its factors are the
	// questions it was answered, read as the replies give them, with the
	// adjustment's answers if it was made, without the levels Go would have
	// computed.
	Unrated bool `json:"unrated,omitempty"`
	// Adjustment is how the adjustment reply read: not_asked, answered,
	// unreadable or key_written_twice.
	Adjustment adjustmentReading `json:"adjustment"`
	// Factors holds the 16 in the vector's order; an unrated entry, only the
	// questions answered, in call order.
	Factors  []factorRecord `json:"factors"`
	Counters []string       `json:"counters,omitempty"`
}

type factorRecord struct {
	Factor contract.Factor `json:"factor"`
	// Answer is the question's answer as the reply wrote it, its JSON type
	// kept; absent when the question was not asked.
	Answer  json.RawMessage  `json:"answer,omitempty"`
	Reading contract.Reading `json:"reading,omitempty"`
	// Adjusted is a flagged CVE's adjustment answer for Opportunity or an
	// axis's factor, as the reply gave it.
	Adjusted string          `json:"adjusted,omitempty"`
	Level    *int            `json:"level,omitempty"`
	Source   contract.Source `json:"source,omitempty"`
}

// rated records a rated CVE for answers.json and adds its counters to the
// run's, reasoning_missing last.
func (run *scoringRun) rated(c *cve, a *assessment, l contract.Levels) {
	counters := c.counters(l)
	if a.unexplained {
		counters = append(counters, reasoningMissing)
	}
	for _, name := range counters {
		run.counters[name]++
	}
	levels := vectorLevels(l.Vector)
	e := answersEntry{VulnID: c.id(), Adjustment: cmp.Or(a.adjustment, adjustmentNotAsked), Counters: counters}
	for _, f := range vectorOrder {
		level := levels[f]
		r := factorRecord{Factor: f, Reading: l.Readings[f], Level: &level, Source: l.Sources[f]}
		if c.asks(f) {
			r.Answer = rawAnswer(a, f)
		}
		if a.adjusted != nil {
			r.Adjusted = adjustedAnswer(*a.adjusted, f)
		}
		e.Factors = append(e.Factors, r)
	}
	run.entries = append(run.entries, e)
}

// unrated records, unrated, a CVE of a failing batch that was answered at
// least once: each answer as its reply reads, before Go crosses it with the
// CVE or the config, and the adjustment's if it was made; the cannot_tell
// each such reading counts, and reasoning_missing.
func (run *scoringRun) unrated(c *cve, a *assessment) {
	if len(a.read) == 0 {
		return
	}
	e := answersEntry{VulnID: c.id(), Unrated: true, Adjustment: cmp.Or(a.adjustment, adjustmentNotAsked)}
	for _, f := range a.read {
		reading, _ := contract.ReadAnswer(f, answerOf(a.answers, f)...)
		r := factorRecord{Factor: f, Answer: rawAnswer(a, f), Reading: reading}
		if a.adjusted != nil {
			r.Adjusted = adjustedAnswer(*a.adjusted, f)
		}
		e.Factors = append(e.Factors, r)
		if reading == contract.CannotTell || reading == contract.Invalid {
			e.Counters = append(e.Counters, f.Counter())
		}
	}
	if a.unexplained {
		e.Counters = append(e.Counters, reasoningMissing)
	}
	for _, name := range e.Counters {
		run.counters[name]++
	}
	run.entries = append(run.entries, e)
}

// rawAnswer is factor f's answer as the reply wrote it, null when it wrote
// none.
func rawAnswer(a *assessment, f contract.Factor) json.RawMessage {
	if raw := a.raw[f]; len(raw) > 0 {
		return raw
	}
	return json.RawMessage("null")
}

// writeAnswers writes answers.json to the run's debug directory, if any.
func (g *Generator) writeAnswers(ctx context.Context, run *scoringRun) {
	if g.debugRunDir == "" {
		return
	}
	b, err := json.MarshalIndent(answersFile{Vulnerabilities: run.entries, Counters: run.counters, Defects: run.defects}, "", "  ")
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

// answerOf is factor f's answer as Go keeps it, one id or the ids of a set.
func answerOf(a contract.Answers, f contract.Factor) []string {
	if f == contract.ID {
		return a.ID
	}
	return []string{*answerField(&a, f)}
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
