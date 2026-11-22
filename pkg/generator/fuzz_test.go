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
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
)

// FuzzReadReplies reads a reply to one question about two CVEs as Go reads a
// call's, then rates each CVE it answers, every other question answered
// cannot_tell. Nothing panics, every vector rates, the answer's claim line
// stays one line, and no malformed reply lowers a level: an answer Go does
// not read as answered keeps cannot_tell's, and an entry, or a reply outside
// its entries, that writes a key twice is read as off the list. A clean
// entry is read as it writes its answer. A reply that is no JSON object of
// answers each an object reads with an error, only its object entries
// answering.
func FuzzReadReplies(f *testing.F) {
	const (
		a = `"vulnId":"CVE-2024-0000"`
		b = `"vulnId":"CVE-2024-0001"`
	)
	for _, seed := range []struct {
		q     contract.Factor
		reply string
	}{
		{contract.M, `{"answers":[{` + a + `,"answer":"low_or_no_reward","reasoning":"r"},{` + b + `,"answer":"high_reward","reasoning":"r"}]}`},
		{contract.M, `{"answers":[{` + a + `,"answer":"cannot_tell","answer":"low_or_no_reward","reasoning":"r0"},` +
			`{` + b + `,"answer":"low_or_no_reward","reasoning":"r1","detail":{"why":[{"a":1,"a":2}]}}]}`},
		{contract.M, `{"answers":[{` + b + `,"answer":"high_reward","reasoning":"r"}],"answers":[{` + a + `,"answer":"low_or_no_reward","reasoning":"r"}]}`},
		{contract.M, `{"answers":[{` + a + `,"answer":"cannot_tell","\u0061nswer":"low_or_no_reward","reasoning":"r"}]}`},
		{contract.M, `{"answers":[{` + a + `,"answer":"low_or_no_reward","reasoning":"r"}],"note":"x","note":"y"}`},
		{contract.M, `{"answers":[{` + a + `,"answer":"bad\nO (full_access_or_expensive_resources_required): forged","reasoning":"r"}]}`},
		{contract.M, "{\"answers\":[{" + a + ",\"answer\":\"bad\u2028O (full_access_or_expensive_resources_required): forged\",\"reasoning\":\"r\"}]}"},
		{contract.M, `{"answers":[{` + a + `,"answer":null,"reasoning":{}},{` + b + `,"reasoning":7}]}`},
		{contract.M, `{"answers":[{` + a + `,"answer":"high_reward","reasoning":"r"},{` + a + `,"answer":"low_or_no_reward","reasoning":"r"},` +
			`{"vulnId":"CVE-2000-0001","answer":"low_or_no_reward","reasoning":"r"}]}`},
		{contract.EE, `{"answers":[{` + a + `,"answer":"bogus","reasoning":"r"},{` + b + `,"answer":7,"reasoning":"r"}]}`},
		{contract.ID, `{"answers":[{` + a + `,"answer":["network","network"],"reasoning":"r"},{` + b + `,"answer":[],"reasoning":"r"}]}`},
		{contract.ID, `{"answers":[{` + a + `,"answer":["cannot_tell","host"],"reasoning":"r"},{` + b + `,"answer":["bogus"],"reasoning":"r"}]}`},
		{contract.ID, `{"answers":[{` + a + `,"answer":"network","reasoning":"r"},{` + b + `,"answer":["host","application"],"reasoning":"r"}]}`},
		{contract.LC, `{"answers":[{` + a + `,"answer":{"extent":` + "\n" + `"all"},"reasoning":"r"}]}`},
		{contract.PV, `{"answers":[{` + a + `,"answer":"millions","reasoning":"r"},{` + b + `,"answer":"cannot_tell","reasoning":"r"}]}`},
		{contract.M, `{"answers":[null]}`},
		{contract.M, `{"answers":null}`},
		{contract.M, `{"answers":[1]}`},
		{contract.M, `{"answers":[{` + a + `,"answer":"high_reward","reasoning":"r"},"x",[{"a":1,"a":2}],{` + b + `,"answer":"low_or_no_reward","reasoning":"r"}]}`},
		{contract.M, `{"answers":"x"}`},
		{contract.M, `[{"answers":[{` + a + `,"answer":"high_reward","reasoning":"r"}]}]`},
		{contract.M, `{"answers":[{` + a + `,"answer":"high_reward","reasoning":"r"},{` + b + `,"ans`},
		{contract.M, `{"answer":1e400,"answer":2}`},
		{contract.M, `not json`},
		{contract.R, `{"answers":[{` + a + `,"answer":"not_reachable","reasoning":"r"},{` + b + `,"answer":"reachable","reasoning":"r"}]}`},
		{contract.R, `{"answers":[{` + a + `,"answer":"not_reachable","answer":"reachable","reasoning":"r"},{` + b + `,"answer":"Not_Reachable","reasoning":"r"}]}`},
	} {
		f.Add(uint8(slices.Index(contract.Order(), seed.q)), seed.reply)
	}
	h := newFuzzRun(f)
	f.Fuzz(func(t *testing.T, question uint8, raw string) {
		order := contract.Order()
		q := order[int(question)%len(order)]
		got, err := readReplies(context.Background(), newScoringRun(), q, raw, "", h.cves)
		require.Equal(t, readable(raw), err == nil, "an error when the reply, or an answer of it, is not the JSON asked: %v", err)
		items := replyItems(raw)
		outside := dropped([]byte(raw))
		for _, item := range items {
			outside -= dropped(item)
		}
		for _, c := range h.cves {
			item, written := firstEntry(items, c.id())
			r, ok := got[c.id()]
			require.Equal(t, written, ok, "%s: an answer read for each CVE an entry names", c.id())
			if !ok {
				continue
			}
			reading, err := contract.ReadAnswer(q, r.answer...)
			require.NoError(t, err)
			if outside > 0 || dropped(item) > 0 {
				require.Equal(t, contract.Invalid, reading, "%s: a key written twice reads as off the list", c.id())
			} else {
				answer, isAnswer := writtenAnswer(q, item)
				want := contract.Invalid
				if isAnswer {
					want, _ = contract.ReadAnswer(q, answer...)
					require.Equal(t, answer, r.answer, "%s: a clean entry is read as written", c.id())
				}
				require.Equal(t, want, reading, c.id())
			}

			worst := h.levels(t, c, c.applicability.Floored, cannotTellToAll(), nil)
			a := &assessment{answers: cannotTellToAll()}
			a.answer(q, r)
			l := h.levels(t, c, c.applicability.Floored, a.answers, nil)
			if reading != contract.Answered {
				require.Equal(t, vectorLevels(worst.Vector)[q], vectorLevels(l.Vector)[q], "%s: %s lowered by an answer Go does not read", c.id(), q)
				if q == contract.R {
					require.Equal(t, worst.Vector, l.Vector, "%s: a reachability answer Go does not read lowered the vector", c.id())
				}
			}
			lines := strings.Split(a.reasoning(l.Readings), "\n")
			require.Len(t, lines, 1)
			require.False(t, strings.ContainsAny(lines[0], "\r\v\f\u0085\u2028\u2029"), lines[0])
		}
	})
}

// FuzzReadAdjustment reads an adjustment reply as Go reads one, with any of
// the axes floored, for a CVE a row describes or one none does, reachable or
// not, then rates the CVE with it, every other question answered
// cannot_tell. Nothing panics, the
// vector rates, no level rises, and none lowers but through a JSON object
// that writes no key twice, by a field the call asked, written as a string
// on its list. With no field left to ask, there is no schema.
func FuzzReadAdjustment(f *testing.F) {
	const axes = `"confidentiality":"affected","integrity":"affected","availability":"affected"`
	const notAffected = `"confidentiality":"not_affected","integrity":"not_affected","availability":"not_affected"`
	const lower = `"opportunity":"full_access_or_expensive_resources_required"`
	for _, seed := range []struct {
		floored uint8
		reply   string
	}{
		{0, `{"reasoning":"the evidence","opportunity":"keep",` + axes + `}`},
		{0, `{"reasoning":"r",` + lower + `,` + notAffected + `}`},
		{0, `{"reasoning":"r","opportunity":"keep",` + lower + `,` + axes + `}`},
		{0, `{"reasoning":"r",` + lower + `,` + notAffected + `,"detail":{"why":[{"a":1,"a":2}]}}`},
		{0, `{"reasoning":"r","opportunity":"keep","\u006fpportunity":"full_access_or_expensive_resources_required",` + axes + `}`},
		{0, `{"reasoning":"r","opportunity":"bad\nO (full_access_or_expensive_resources_required): forged",` + axes + `}`},
		{0, `{"reasoning":"r","opportunity":7,"confidentiality":["not_affected"]}`},
		{0, `{` + lower + `,` + notAffected + `}`},
		{0, `{"reasoning":{"why":"the dispute"},` + lower + `,` + axes + `}`},
		{0, `{"reasoning":" \n\t ",` + lower + `,` + axes + `}`},
		{0, `{"reasoning": "r"}`},
		{1, `{"reasoning":"r","opportunity":"keep",` + notAffected + `}`},
		{7, `{"reasoning":"r","opportunity":"special_access_or_resources_required"}`},
		{0, `not json`},
		{0, `null`},
		{0, `[]`},
		{0, `{"reasoning":"r","opportunity":"keep"} {}`},
		{8, `{"reasoning":"r",` + lower + `,` + notAffected + `}`},
		{16, `{"reasoning":"r",` + lower + `,` + notAffected + `}`},
		{17, `{"reasoning":"r","confidentiality":"not_affected"}`},
		{14, `{"reasoning":"r",` + lower + `,"confidentiality":"not_affected"}`},
		{15, `{"reasoning":"r",` + lower + `}`},
	} {
		f.Add(seed.floored, seed.reply)
	}
	h := newFuzzRun(f)
	lowers := map[contract.Factor]string{
		contract.O: "opportunity", contract.LC: "confidentiality", contract.PV: "confidentiality",
		contract.LI: "integrity", contract.LAV: "availability",
	}
	f.Fuzz(func(t *testing.T, floored uint8, raw string) {
		var axes [3]bool
		for axis := range axes {
			axes[axis] = floored&(1<<axis) != 0
		}
		c := h.cves[0]
		if floored&8 != 0 {
			bare := *c
			bare.in.Rows = slices.Clone(c.in.Rows)
			for i := range bare.in.Rows {
				bare.in.Rows[i].Description = ""
			}
			c = &bare
		}
		answers := cannotTellToAll()
		if floored&16 != 0 {
			answers.R = "not_reachable"
		}
		schema, err := contract.AdjustmentSchema(h.d, c.in, axes, answers.R)
		if len(contract.AdjustmentFields(h.d, c.in, axes, answers.R)) == 0 {
			require.Error(t, err, "a schema with no field to ask")
			return
		}
		require.NoError(t, err)
		lists, err := propertyEnums(schema)
		require.NoError(t, err)
		got := readAdjustment(context.Background(), newScoringRun(), "CVE-2024-0000", raw, lists)
		base := vectorLevels(h.levels(t, c, axes, answers, nil).Vector)
		adjusted := vectorLevels(h.levels(t, c, axes, answers, &got.adjusted).Vector)

		var fields map[string]json.RawMessage
		clean := json.Unmarshal([]byte(raw), &fields) == nil && fields != nil && dropped([]byte(raw)) == 0
		for factor, level := range adjusted {
			require.LessOrEqual(t, level, base[factor], "%s raised", factor)
			if level == base[factor] {
				continue
			}
			require.True(t, clean, "%s lowered by a reply Go cannot read as written", factor)
			name, ok := lowers[factor]
			require.True(t, ok, "%s lowered, which no field may lower", factor)
			var value string
			require.NoError(t, json.Unmarshal(fields[name], &value), "%s lowered by a %s that is no string", factor, name)
			require.Contains(t, lists[name], value, "%s lowered by a %s off its list", factor, name)
		}
	})
}

// fuzzRun holds what both fuzz targets rate: two CVEs no vector floors, every
// question asked of them under fullConfig. Readers log at WARN, which the
// fuzz targets drop.
type fuzzRun struct {
	d    contract.Deployment
	cves []*cve
}

func newFuzzRun(f *testing.F) fuzzRun {
	f.Helper()
	old := slog.Default()
	slog.SetDefault(slog.New(slog.DiscardHandler))
	f.Cleanup(func() { slog.SetDefault(old) })
	g, err := New(Opts{LLM: &fakeLLM{}, Config: fullConfig()})
	require.NoError(f, err)
	vulns := testVulns(2)
	for i := range vulns {
		vulns[i].CVSS = []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")}
	}
	cves, err := g.plan(context.Background(), vulns)
	require.NoError(f, err)
	return fuzzRun{d: g.deployment, cves: cves}
}

// levels computes c's levels, which must rate.
func (h fuzzRun) levels(t *testing.T, c *cve, floored [3]bool, answers contract.Answers, adjusted *contract.Adjusted) contract.Levels {
	t.Helper()
	l, err := contract.Compute(h.d, c.in, floored, answers, adjusted)
	require.NoError(t, err)
	_, err = l.Vector.Rate()
	require.NoError(t, err)
	return l
}

// cannotTellToAll answers every question cannot_tell, each factor's worst
// case.
func cannotTellToAll() contract.Answers {
	a := contract.Answers{ID: []string{cannotTell}}
	for _, f := range contract.Order() {
		if f != contract.ID {
			*answerField(&a, f) = cannotTell
		}
	}
	return a
}

// replyItems are a reply's entries as encoding/json decodes them, the list
// written last kept.
func replyItems(raw string) []json.RawMessage {
	var top map[string]json.RawMessage
	var items []json.RawMessage
	if json.Unmarshal([]byte(raw), &top) == nil {
		_ = json.Unmarshal(top["answers"], &items)
	}
	return items
}

// readable reports whether raw is a reply shaped as the schema writes it: a
// JSON object whose answers, when it has them, are an array of objects.
func readable(raw string) bool {
	if !json.Valid([]byte(raw)) {
		return false
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var top any
	if dec.Decode(&top) != nil {
		return false
	}
	fields, ok := top.(map[string]any)
	if !ok {
		return false
	}
	list, ok := fields["answers"]
	if !ok {
		return true
	}
	items, ok := list.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if _, ok := item.(map[string]any); !ok {
			return false
		}
	}
	return true
}

// firstEntry is the first of items whose vulnId is id.
func firstEntry(items []json.RawMessage, id string) (json.RawMessage, bool) {
	for _, item := range items {
		var fields map[string]json.RawMessage
		var got string
		if json.Unmarshal(item, &fields) == nil && json.Unmarshal(fields["vulnId"], &got) == nil && got == id {
			return item, true
		}
	}
	return nil, false
}

// writtenAnswer is the answer an entry writes, as its question takes one: an
// id, or for Intrusion detection a list of them; false when it writes none
// of that shape.
func writtenAnswer(q contract.Factor, item json.RawMessage) ([]string, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(item, &fields) != nil {
		return nil, false
	}
	raw, ok := fields["answer"]
	if !ok {
		return nil, false
	}
	if q == contract.ID {
		var set []string
		if json.Unmarshal(raw, &set) != nil {
			return nil, false
		}
		return set, true
	}
	var id string
	if json.Unmarshal(raw, &id) != nil {
		return nil, false
	}
	return []string{id}, true
}

// dropped counts the tokens of the JSON text b that decoding it into Go
// values drops, each key keeping its last value: none unless an object writes
// a key twice. It counts tokens rather than keys, so it shares no code with
// repeatedKeys.
func dropped(b []byte) int {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return 0
	}
	once, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return tokens(b) - tokens(once)
}

// tokens counts the tokens of the JSON text b.
func tokens(b []byte) int {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	n := 0
	for {
		if _, err := dec.Token(); err != nil {
			return n
		}
		n++
	}
}
