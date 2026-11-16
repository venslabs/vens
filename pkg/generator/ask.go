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
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/llm"
)

// reply is one CVE's answer to a question as the first reply that gave it
// wrote it, and the evidence of that call.
type reply struct {
	// answer is one id, or for Intrusion detection the ids of the set
	// chosen; a value of another JSON type is kept as its JSON text.
	answer      []string
	reasoning   string
	evidenceRef string
}

// ask asks question f about cves. A call the provider truncates is split in
// half and each half asked on its own, down to a single CVE. The CVEs the
// replies leave out are asked again together, once; one still left out
// stops the run, since no other batch holds it.
func (g *Generator) ask(ctx context.Context, run *scoringRun, f contract.Factor, cves []*cve) (map[string]reply, error) {
	got, err := g.askSplitting(ctx, run, f, cves)
	if err != nil {
		return nil, err
	}
	missing := unanswered(cves, got)
	if len(missing) == 0 {
		return got, nil
	}
	// Counts go by distinct CVE: one hitting several components is one entry.
	slog.WarnContext(ctx, "Model skipped vulnerabilities; asking again for those alone",
		"question", string(f), "skipped", len(missing), "of", len(cves), "vulns", strings.Join(cveIDs(missing), ","))
	run.askedAgain++
	again, err := g.askSplitting(ctx, run, f, missing)
	if err != nil {
		return nil, err
	}
	maps.Copy(got, again)
	if still := unanswered(cves, got); len(still) > 0 {
		ids := cveIDs(still)
		slices.Sort(ids)
		return nil, fmt.Errorf("model returned no answer to %s (%s) for %s after asking again; stopping the run",
			f.Name(), f, strings.Join(ids, ", "))
	}
	return got, nil
}

// askSplitting asks f about cves in one call or, when the provider truncates
// it, in two halves, each split again until it fits or holds one CVE.
func (g *Generator) askSplitting(ctx context.Context, run *scoringRun, f contract.Factor, cves []*cve) (map[string]reply, error) {
	got, err := g.askOnce(ctx, run, f, cves)
	if len(cves) == 1 || !errors.Is(err, llm.ErrTruncated) {
		return got, err
	}
	half := (len(cves) + 1) / 2
	run.splits++
	slog.WarnContext(ctx, "LLM truncated the call; asking each half on its own",
		"question", string(f), "from", len(cves), "to", half)
	// The WARN above doesn't show which CVEs each half keeps, which is what
	// you reach for when a split behaves oddly.
	slog.DebugContext(ctx, "splitting truncated call",
		"question", string(f),
		"first_half", strings.Join(cveIDs(cves[:half]), ","),
		"second_half", strings.Join(cveIDs(cves[half:]), ","),
	)
	first, err := g.askSplitting(ctx, run, f, cves[:half])
	if err != nil {
		return nil, err
	}
	second, err := g.askSplitting(ctx, run, f, cves[half:])
	if err != nil {
		return nil, err
	}
	maps.Copy(first, second)
	return first, nil
}

// askOnce makes one call asking f about cves and reads its reply. A strict
// run stops right after a call that gave an answer Go reads as cannot_tell.
func (g *Generator) askOnce(ctx context.Context, run *scoringRun, f contract.Factor, cves []*cve) (map[string]reply, error) {
	request, err := contract.Request(f, g.deployment, contractCVEs(cves))
	if err != nil {
		return nil, err
	}
	schema, err := contract.Schema(f, cveIDs(cves))
	if err != nil {
		return nil, err
	}
	raw, ref, err := g.send(ctx, run, string(f), request, schema)
	if err != nil {
		return nil, fmt.Errorf("LLM evaluation failed: %w", err)
	}
	got, err := readReplies(ctx, f, raw, ref, cves)
	if err != nil {
		return nil, err
	}
	if g.o.Strict {
		if err := firstCannotTell(f, cves, got); err != nil {
			return nil, err
		}
	}
	return got, nil
}

// readReplies reads a call's reply by key, one answer per CVE. An answer for
// a CVE the call did not ask about is ignored, and a CVE answered twice keeps
// its first answer. An answer off its list is kept as given and logged: Go
// reads it as cannot_tell.
func readReplies(ctx context.Context, f contract.Factor, raw, evidenceRef string, cves []*cve) (map[string]reply, error) {
	var out struct {
		Answers []map[string]json.RawMessage `json:"answers"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("unable to parse LLM output: %w: %q", err, raw)
	}
	asked := make(map[string]bool, len(cves))
	for _, c := range cves {
		asked[c.id()] = true
	}
	got := make(map[string]reply, len(cves))
	for _, a := range out.Answers {
		id := text(a["vulnId"])
		if !asked[id] {
			// A provider honouring the schema cannot write one: the call's
			// ids are an enum.
			slog.DebugContext(ctx, "ignoring an answer for a CVE the call did not ask about",
				"vuln", id, "question", string(f))
			continue
		}
		if _, ok := got[id]; ok {
			continue
		}
		answer := answerIDs(f, a["answer"])
		if r, _ := contract.ReadAnswer(f, answer...); r == contract.Invalid {
			slog.WarnContext(ctx, "Model gave an answer off the list; reading it as cannot_tell",
				"vuln", id, "question", string(f), "answer", string(a["answer"]))
		}
		got[id] = reply{answer: answer, reasoning: text(a["reasoning"]), evidenceRef: evidenceRef}
	}
	return got, nil
}

// answerIDs reads an answer as a reply writes it: one id, or for Intrusion
// detection an array of ids. Any other value is kept as its JSON text, which
// no list holds.
func answerIDs(f contract.Factor, raw json.RawMessage) []string {
	if f == contract.ID {
		var set []string
		if json.Unmarshal(raw, &set) == nil {
			return set
		}
		return []string{string(raw)}
	}
	return []string{text(raw)}
}

func unanswered(cves []*cve, got map[string]reply) []*cve {
	var out []*cve
	for _, c := range cves {
		if _, ok := got[c.id()]; !ok {
			out = append(out, c)
		}
	}
	return out
}
