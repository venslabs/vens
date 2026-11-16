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
	"log/slog"
	"maps"
	"slices"

	"github.com/venslabs/vens/pkg/contract"
)

// scoringRun is what one GenerateRiskScore call counts and records.
type scoringRun struct {
	// llmCalls counts every LLM call, rate-limit retries happening inside
	// one; askedAgain the asks-again for CVEs a reply left out; splits the
	// truncated calls split in half.
	llmCalls, askedAgain, splits int
	// calls counts the calls of each question, and of the adjustments.
	calls map[string]int
	// counters sums each counter over the CVEs rated.
	counters map[string]int
	// defects counts each defect reading the replies found, by kind.
	defects map[string]int
	// entries holds each CVE rated, in run order, as answers.json writes it.
	entries []answersEntry
}

// The defects reading a reply can find, which a provider honouring the
// schema and the prompt does not write. Each is counted once per answer,
// entry or adjustment reply that has it.
const (
	// An answer off its question's list, read as cannot_tell.
	defectAnswerOffList = "answer_off_list"
	// An answer its entry, or its reply outside every entry, leaves in doubt
	// by writing a key twice, read as cannot_tell.
	defectAnswerKeyTwice = "answer_key_written_twice"
	// An answer without reasoning, or with one blank or no JSON string, kept.
	defectAnswerNoReasoning = "answer_without_reasoning"
	// An entry for a CVE the call did not ask about, ignored.
	defectCVENotAsked = "answer_cve_not_asked"
	// A CVE's second entry in one reply, ignored.
	defectCVERepeated = "answer_cve_repeated"
	// An adjustment reply that is no JSON object: the baselines stand.
	defectAdjustmentUnreadable = "adjustment_unreadable"
	// An adjustment reply that writes a key twice: the baselines stand.
	defectAdjustmentKeyTwice = "adjustment_key_written_twice"
	// A field the adjustment asked, left out or off its list: its baseline
	// stands.
	defectAdjustmentOffList = "adjustment_off_list"
	// An adjustment reply without reasoning, or with one blank or no JSON
	// string, its fields kept.
	defectAdjustmentNoReasoning = "adjustment_without_reasoning"
)

func newScoringRun() *scoringRun {
	return &scoringRun{calls: map[string]int{}, counters: map[string]int{}, defects: map[string]int{}, entries: []answersEntry{}}
}

func (run *scoringRun) call(question string) {
	run.llmCalls++
	run.calls[question]++
}

// defect counts one defect of a reply's, one of the kinds above.
func (run *scoringRun) defect(kind string) {
	run.defects[kind]++
}

// summarize logs the run's summary: rows and distinct CVEs, the calls made,
// per question too, the asks-again and splits, and each counter and each
// defect that is not zero.
func (run *scoringRun) summarize(ctx context.Context, rows, cves int, err error) {
	var calls []any
	for _, q := range append(contract.Order(), adjustmentCall) {
		if n := run.calls[string(q)]; n > 0 {
			calls = append(calls, slog.Int(string(q), n))
		}
	}
	slog.InfoContext(ctx, "Scoring run finished",
		"rows", rows,
		"cves", cves,
		"llm_calls", run.llmCalls,
		"asked_again", run.askedAgain,
		"splits", run.splits,
		slog.Group("calls", calls...),
		slog.Group("counters", byName(run.counters)...),
		slog.Group("defects", byName(run.defects)...),
		"failed", err != nil,
	)
}

// byName lists each count of counts as an attribute, sorted by name.
func byName(counts map[string]int) []any {
	var out []any
	for _, name := range slices.Sorted(maps.Keys(counts)) {
		out = append(out, slog.Int(name, counts[name]))
	}
	return out
}
