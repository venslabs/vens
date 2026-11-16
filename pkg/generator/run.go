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
	// entries holds each CVE rated, in run order, as answers.json writes it.
	entries []answersEntry
}

func newScoringRun() *scoringRun {
	return &scoringRun{calls: map[string]int{}, counters: map[string]int{}, entries: []answersEntry{}}
}

func (run *scoringRun) call(question string) {
	run.llmCalls++
	run.calls[question]++
}

// summarize logs the run's summary: rows and distinct CVEs, the calls made,
// per question too, the asks-again and splits, and each counter that is not
// zero.
func (run *scoringRun) summarize(ctx context.Context, rows, cves int, err error) {
	var calls []any
	for _, q := range append(contract.Order(), adjustmentCall) {
		if n := run.calls[string(q)]; n > 0 {
			calls = append(calls, slog.Int(string(q), n))
		}
	}
	var counters []any
	for _, name := range slices.Sorted(maps.Keys(run.counters)) {
		counters = append(counters, slog.Int(name, run.counters[name]))
	}
	slog.InfoContext(ctx, "Scoring run finished",
		"rows", rows,
		"cves", cves,
		"llm_calls", run.llmCalls,
		"asked_again", run.askedAgain,
		"splits", run.splits,
		slog.Group("calls", calls...),
		slog.Group("counters", counters...),
		"failed", err != nil,
	)
}
