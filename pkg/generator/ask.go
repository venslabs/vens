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
	"bytes"
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
	answer []string
	// raw is the answer as the reply wrote it, absent when it wrote none:
	// every answer it wrote, as a JSON array, when a key written twice
	// leaves it in doubt.
	raw         json.RawMessage
	reasoning   string
	evidenceRef string
}

// ask asks question f about cves, keeping each answer in its CVE's
// assessment as soon as a reply gives it. A call the provider truncates is
// split in half and each half asked on its own, down to a single CVE. The
// CVEs the replies leave out are asked again together, once; one still left
// out stops the run, since no other batch holds it.
func (g *Generator) ask(ctx context.Context, run *scoringRun, f contract.Factor, cves []*cve, assessed map[string]*assessment) error {
	got, err := g.askSplitting(ctx, run, f, cves, assessed)
	if err != nil {
		return err
	}
	missing := unanswered(cves, got)
	if len(missing) == 0 {
		return nil
	}
	// Counts go by distinct CVE: one hitting several components is one entry.
	slog.WarnContext(ctx, "Model skipped vulnerabilities; asking again for those alone",
		"question", string(f), "skipped", len(missing), "of", len(cves), "vulns", strings.Join(cveIDs(missing), ","))
	run.askedAgain++
	again, err := g.askSplitting(ctx, run, f, missing, assessed)
	if err != nil {
		return err
	}
	maps.Copy(got, again)
	if still := unanswered(cves, got); len(still) > 0 {
		ids := cveIDs(still)
		slices.Sort(ids)
		return fmt.Errorf("model returned no answer to %s (%s) for %s after asking again; stopping the run",
			f.Name(), f, strings.Join(ids, ", "))
	}
	return nil
}

// askSplitting asks f about cves in one call or, when the provider truncates
// it, in two halves, each split again until it fits or holds one CVE.
func (g *Generator) askSplitting(ctx context.Context, run *scoringRun, f contract.Factor, cves []*cve, assessed map[string]*assessment) (map[string]reply, error) {
	got, err := g.askOnce(ctx, run, f, cves, assessed)
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
	first, err := g.askSplitting(ctx, run, f, cves[:half], assessed)
	if err != nil {
		return nil, err
	}
	second, err := g.askSplitting(ctx, run, f, cves[half:], assessed)
	if err != nil {
		return nil, err
	}
	maps.Copy(first, second)
	return first, nil
}

// askOnce makes one call asking f about cves, reads its reply and keeps each
// answer in its CVE's assessment. A strict run stops right after a call that
// gave an answer Go reads as cannot_tell, the answer kept.
func (g *Generator) askOnce(ctx context.Context, run *scoringRun, f contract.Factor, cves []*cve, assessed map[string]*assessment) (map[string]reply, error) {
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
	got, err := readReplies(ctx, run, f, raw, ref, cves)
	if err != nil {
		return nil, err
	}
	for _, c := range cves {
		if r, ok := got[c.id()]; ok {
			assessed[c.id()].answer(f, r)
		}
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
// its first answer. An answer off its list, or one a key written twice
// leaves in doubt, is kept as given and logged: Go reads it as cannot_tell.
// Each of these counts as a defect of the run's.
func readReplies(ctx context.Context, run *scoringRun, f contract.Factor, raw, evidenceRef string, cves []*cve) (map[string]reply, error) {
	entries, err := readEntries(ctx, f, raw)
	if err != nil {
		return nil, fmt.Errorf("unable to parse LLM output: %w: %q", err, raw)
	}
	asked := make(map[string]bool, len(cves))
	for _, c := range cves {
		asked[c.id()] = true
	}
	got := make(map[string]reply, len(cves))
	for _, e := range entries {
		id := text(e.fields["vulnId"])
		if !asked[id] {
			// A provider honouring the schema cannot write one: the call's
			// ids are an enum.
			run.defect(defectCVENotAsked)
			slog.DebugContext(ctx, "ignoring an answer for a CVE the call did not ask about",
				"vuln", id, "question", string(f))
			continue
		}
		if _, ok := got[id]; ok {
			run.defect(defectCVERepeated)
			continue
		}
		got[id] = readEntry(ctx, run, f, id, e, evidenceRef)
	}
	return got, nil
}

// entry is one answer of a reply: its fields by key and its text. repeated
// marks an answer a key written twice leaves in doubt, in the answer or
// outside every answer of the reply.
type entry struct {
	fields   map[string]json.RawMessage
	text     json.RawMessage
	repeated bool
}

// readEntries decodes a reply's answers, each key read as written.
// encoding/json keeps the last value of a key written twice and says
// nothing, so the reply is walked for one; one outside every answer marks
// them all.
func readEntries(ctx context.Context, f contract.Factor, raw string) ([]entry, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &top); err != nil {
		return nil, err
	}
	var items []json.RawMessage
	if list, ok := top["answers"]; ok {
		if err := json.Unmarshal(list, &items); err != nil {
			return nil, err
		}
	}
	outside := repeatedKeys([]byte(raw))
	entries := make([]entry, len(items))
	for i, item := range items {
		if err := json.Unmarshal(item, &entries[i].fields); err != nil {
			return nil, err
		}
		n := repeatedKeys(item)
		entries[i].text, entries[i].repeated = item, n > 0
		outside -= n
	}
	if outside > 0 {
		slog.WarnContext(ctx, "Model wrote a key twice outside its answers; reading each as cannot_tell",
			"question", string(f), "reply", raw)
		for i := range entries {
			entries[i].repeated = true
		}
	}
	return entries, nil
}

// readEntry reads the answer an entry gives for CVE id. An entry a key
// written twice leaves in doubt keeps every answer it wrote, as a JSON array
// no list holds: Go reads it as cannot_tell, as an answer off the list. An
// answer without reasoning, or with one that is no JSON string, is kept,
// logged at WARN.
func readEntry(ctx context.Context, run *scoringRun, f contract.Factor, id string, e entry, evidenceRef string) reply {
	r := reply{
		answer:      answerIDs(f, e.fields["answer"]),
		raw:         e.fields["answer"],
		reasoning:   reasoningOf(e.fields["reasoning"]),
		evidenceRef: evidenceRef,
	}
	if e.repeated {
		r.raw = answersWritten(e.text)
		r.answer = []string{string(r.raw)}
		run.defect(defectAnswerKeyTwice)
		slog.WarnContext(ctx, "Model wrote a key twice; reading the answer as cannot_tell",
			"vuln", id, "question", string(f), "entry", string(e.text))
	} else if reading, _ := contract.ReadAnswer(f, r.answer...); reading == contract.Invalid {
		run.defect(defectAnswerOffList)
		slog.WarnContext(ctx, "Model gave an answer off the list; reading it as cannot_tell",
			"vuln", id, "question", string(f), "answer", string(r.raw))
	}
	if oneLine(r.reasoning) == "" {
		run.defect(defectAnswerNoReasoning)
		slog.WarnContext(ctx, "Model gave an answer without reasoning; keeping it",
			"vuln", id, "question", string(f))
	}
	return r
}

// answersWritten is every value the JSON object item writes for "answer",
// in order, as a JSON array.
func answersWritten(item json.RawMessage) json.RawMessage {
	dec := json.NewDecoder(bytes.NewReader(item))
	var values []string
	if _, err := dec.Token(); err != nil {
		return json.RawMessage("[]")
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			break
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			break
		}
		if key == "answer" {
			values = append(values, string(value))
		}
	}
	return json.RawMessage("[" + strings.Join(values, ",") + "]")
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
