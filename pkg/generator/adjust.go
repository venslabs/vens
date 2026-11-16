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
	"slices"
	"strings"

	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
)

const (
	cannotTell = "cannot_tell"
	// adjustmentCall names the adjustment calls in the run's counts.
	adjustmentCall = "adjustment"
)

// adjust makes a flagged CVE's adjustment call, after its ordinary
// questions: it shows every row's evidence, the flags and the answers given,
// and may lower Opportunity and each axis Applicability did not floor, never
// raise them. A reply Go cannot read leaves the baselines.
func (g *Generator) adjust(ctx context.Context, run *scoringRun, c *cve, a *assessment) error {
	floored := c.applicability.Floored
	request, err := contract.AdjustmentRequest(g.deployment, c.in, floored, c.flags, baselines(a.answers, floored))
	if err != nil {
		return err
	}
	schema, err := contract.AdjustmentSchema(floored)
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
	adjusted, answered, reasoning := readAdjustment(ctx, c.id(), raw, lists)
	a.adjusted = &adjusted
	a.note(fmt.Sprintf("%s (%s): %s", adjustmentCall, answered, oneLine(reasoning)), ref)
	return nil
}

// baselines are the answers the adjustment shows as given: Opportunity's,
// and each axis's that Applicability did not floor. An answer Go reads as
// cannot_tell is shown as cannot_tell, so that a reply keeping it keeps what
// Go keeps.
func baselines(given contract.Answers, floored [3]bool) contract.Answers {
	b := contract.Answers{O: shownAs(contract.O, given.O)}
	if !floored[cvss.Confidentiality] {
		b.LC = shownAs(contract.LC, given.LC)
	}
	if !floored[cvss.Integrity] {
		b.LI = shownAs(contract.LI, given.LI)
	}
	if !floored[cvss.Availability] {
		b.LAV = shownAs(contract.LAV, given.LAV)
	}
	return b
}

func shownAs(f contract.Factor, answer string) string {
	if r, _ := contract.ReadAnswer(f, answer); r == contract.Invalid {
		return cannotTell
	}
	return answer
}

// readAdjustment reads an adjustment reply by key. Each field the call asked
// is kept as given; one the reply leaves out or gives off the list its schema
// sent leaves the baseline, and a reply that is no JSON object, or that
// writes a key twice at any depth, leaves them all, logged at WARN. It also
// returns the fields as answered, and the reasoning.
func readAdjustment(ctx context.Context, id, raw string, lists map[string][]string) (adjusted contract.Adjusted, answered, reasoning string) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		slog.WarnContext(ctx, "Unreadable adjustment reply; the baselines stand", "vuln", id, "reply", raw)
		return contract.Adjusted{}, "unreadable", ""
	}
	if repeatedKeys([]byte(raw)) > 0 {
		// encoding/json kept the last value of the key, which may lower a
		// level the model meant to keep.
		slog.WarnContext(ctx, "Adjustment reply writes a key twice; the baselines stand", "vuln", id, "reply", raw)
		return contract.Adjusted{}, "a key written twice", text(fields["reasoning"])
	}
	var parts []string
	read := func(name string) string {
		list, asked := lists[name]
		if !asked {
			return ""
		}
		value := text(fields[name])
		parts = append(parts, name+": "+value)
		if !slices.Contains(list, value) {
			slog.WarnContext(ctx, "Adjustment answer off its list; the baseline stands",
				"vuln", id, "field", name, "answer", string(fields[name]))
		}
		return value
	}
	adjusted = contract.Adjusted{
		Opportunity:     read("opportunity"),
		Confidentiality: read("confidentiality"),
		Integrity:       read("integrity"),
		Availability:    read("availability"),
	}
	return adjusted, strings.Join(parts, ", "), text(fields["reasoning"])
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
