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
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/venslabs/vens/pkg/contract"
)

const (
	cannotTell = "cannot_tell"
	// adjustmentCall names the adjustment calls in the run's counts.
	adjustmentCall = "adjustment"
)

// adjustmentReading is how Go read a CVE's adjustment reply.
type adjustmentReading string

const (
	// adjustmentNotAsked: no reply was read, the CVE having no flag, nothing
	// left to adjust, or its run stopping first.
	adjustmentNotAsked   adjustmentReading = "not_asked"
	adjustmentAnswered   adjustmentReading = "answered"
	adjustmentUnreadable adjustmentReading = "unreadable"
	adjustmentKeyTwice   adjustmentReading = "key_written_twice"
)

// adjustmentReply is an adjustment reply as Go read it: the fields kept, how
// it read, the fields as the claim shows them, and the reasoning.
type adjustmentReply struct {
	adjusted  contract.Adjusted
	reading   adjustmentReading
	shown     string
	reasoning string
}

// adjust makes a flagged CVE's adjustment call, after its ordinary
// questions: it shows every row's evidence, the flags and the Opportunity
// answer given, and may lower Opportunity, never raise it. A CVE no row
// describes was not asked Opportunity: it makes no call. A reply Go cannot
// read leaves the baseline.
func (g *Generator) adjust(ctx context.Context, run *scoringRun, c *cve, a *assessment) error {
	if len(contract.AdjustmentFields(c.in)) == 0 {
		slog.DebugContext(ctx, "no adjustment call: no description", "vuln", c.id())
		return nil
	}
	given := contract.Answers{O: shownAs(contract.O, a.answers.O)}
	request, err := contract.AdjustmentRequest(g.deployment, c.in, c.flags, given)
	if err != nil {
		return err
	}
	schema, err := contract.AdjustmentSchema(c.in)
	if err != nil {
		return err
	}
	lists, err := propertyEnums(schema)
	if err != nil {
		return err
	}
	raw, ref, err := g.send(ctx, run, adjustmentCall, request, schema)
	if err != nil {
		return fmt.Errorf("LLM evaluation failed on the adjustment of %s: %w", c.id(), err)
	}
	got := readAdjustment(ctx, run, c.id(), raw, lists)
	a.adjusted, a.adjustment = &got.adjusted, got.reading
	a.note("", got.shown, got.reasoning, ref)
	return nil
}

// shownAs is the answer the adjustment shows as given: an answer Go reads as
// cannot_tell is shown as cannot_tell, so that a reply keeping it keeps what
// Go keeps.
func shownAs(f contract.Factor, answer string) string {
	if r, _ := contract.ReadAnswer(f, answer); r == contract.Invalid {
		return cannotTell
	}
	return answer
}

// readAdjustment reads an adjustment reply by key. Each field the call asked
// is kept as given; one the reply leaves out or gives off the list its schema
// sent leaves the baseline, one the call did not ask is ignored, and a reply
// that is no JSON object, or that writes a key twice at any depth, leaves
// them all, logged at WARN. A reply without reasoning, or with one that is no
// JSON string, keeps its fields, logged at WARN. Each of these counts as a
// defect of the run's.
func readAdjustment(ctx context.Context, run *scoringRun, id, raw string, lists map[string][]string) adjustmentReply {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil || fields == nil {
		run.defect(defectAdjustmentUnreadable)
		slog.WarnContext(ctx, "Unreadable adjustment reply; the baselines stand", "vuln", id, "reply", raw)
		return adjustmentReply{reading: adjustmentUnreadable, shown: "unreadable"}
	}
	if repeatedKeys([]byte(raw)) > 0 {
		// encoding/json kept the last value of the key, which may lower a
		// level the model meant to keep.
		run.defect(defectAdjustmentKeyTwice)
		slog.WarnContext(ctx, "Adjustment reply writes a key twice; the baselines stand", "vuln", id, "reply", raw)
		return adjustmentReply{reading: adjustmentKeyTwice, shown: "a key written twice", reasoning: reasoningOf(fields["reasoning"])}
	}
	var parts []string
	read := func(name string) string {
		list, asked := lists[name]
		if !asked {
			return ""
		}
		value := text(fields[name])
		shown := value
		if !slices.Contains(list, value) {
			shown = offList(fields[name])
			run.defect(defectAdjustmentOffList)
			slog.WarnContext(ctx, "Adjustment answer off its list; the baseline stands",
				"vuln", id, "field", name, "answer", string(fields[name]))
		}
		parts = append(parts, name+": "+shown)
		return value
	}
	got := adjustmentReply{
		adjusted:  contract.Adjusted{Opportunity: read("opportunity")},
		reading:   adjustmentAnswered,
		shown:     strings.Join(parts, ", "),
		reasoning: reasoningOf(fields["reasoning"]),
	}
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		if _, asked := lists[name]; !asked && name != "reasoning" {
			// A provider honouring the schema cannot write one: the object
			// is closed.
			run.defect(defectAdjustmentNotAsked)
			slog.WarnContext(ctx, "Adjustment reply gives a field the call did not ask; ignoring it",
				"vuln", id, "field", cut(name, loggedLimit), "answer", cut(string(fields[name]), loggedLimit))
		}
	}
	if oneLine(got.reasoning) == "" {
		run.defect(defectAdjustmentNoReasoning)
		slog.WarnContext(ctx, "Adjustment reply gives no reasoning; keeping its answers", "vuln", id)
	}
	return got
}

// propertyEnums reads the closed list of each property of an object schema.
func propertyEnums(schema json.RawMessage) (map[string][]string, error) {
	var s struct {
		Properties map[string]struct {
			Enum []string `json:"enum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(schema, &s); err != nil {
		return nil, err
	}
	lists := make(map[string][]string, len(s.Properties))
	for name, p := range s.Properties {
		if len(p.Enum) > 0 {
			lists[name] = p.Enum
		}
	}
	return lists, nil
}
