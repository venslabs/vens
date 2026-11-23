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
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/outputhandler"
)

// disputedRow is a vulnerability its description disputes, as the scanner flags
// it.
func disputedRow(v Vulnerability) Vulnerability {
	v.Description = "A crafted file overflows the parser. NOTE: the vendor disputes this, as the input is trusted."
	v.Flags = Flags{MaintainerDisputed: true}
	return v
}

// adjustedBy runs one flagged CVE whose ordinary answers are the baselines
// given, the adjustment replying reply, and returns its rating.
func adjustedBy(t *testing.T, baselines map[contract.Factor]any, reply map[string]any) (outputhandler.VulnRating, *fakeLLM) {
	t.Helper()
	m := &fakeLLM{
		answer: func(c fakeCall, _ string) any { return baselines[c.factor] },
		adjust: func(fakeCall) map[string]any { return reply },
	}
	g := newGen(t, Opts{LLM: m})
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{disputedRow(testVulns(1)[0])}, collect(&emitted)))
	require.Len(t, emitted, 1)
	return emitted[0], m
}

// A flagged CVE first gets the ordinary questions; the batch's adjustment
// calls come after them, one per flagged CVE in batch order, whichever flag
// its rows raised.
func TestGenerator_AdjustmentAfterTheOrdinaryQuestions(t *testing.T) {
	vulns := testVulns(3)
	vulns[1] = disputedRow(vulns[1])
	vulns[2].Severity, vulns[2].SeveritySource = "LOW", "debian"
	vulns[2].VendorSeverities = []VendorSeverity{{Source: "nvd", Severity: "HIGH"}}
	vulns[2].Flags = Flags{SeverityContested: true}
	m := &fakeLLM{}
	g := newGen(t, Opts{LLM: m})
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))

	require.Equal(t, append(append([]string{}, questionsUndeclared...), adjustmentCall, adjustmentCall), m.log())
	for _, c := range m.calls[:len(questionsUndeclared)] {
		require.Len(t, c.ids, 3, "every CVE gets the ordinary questions")
	}
	var adjusted []string
	for _, c := range m.calls[len(questionsUndeclared):] {
		var entry struct {
			VulnID string `json:"vulnId"`
		}
		require.NoError(t, json.Unmarshal([]byte(strings.Split(c.req.Human, "\n")[1]), &entry))
		adjusted = append(adjusted, entry.VulnID)
	}
	require.Equal(t, []string{"CVE-2024-0001", "CVE-2024-0002"}, adjusted)
}

// The adjustment only lowers Opportunity: an answer above the baseline, keep,
// cannot_tell and an answer off the list leave it, and cannot_tell, an
// abstention there, is not counted.
func TestGenerator_AdjustmentNeverRaisesOpportunity(t *testing.T) {
	for adjusted, want := range map[string]int{
		"special_access_or_resources_required":        4,
		"full_access_or_expensive_resources_required": 0,
		"no_access_or_resources_required":             7,
		"keep":                                        7,
		cannotTell:                                    7,
		"bogus":                                       7,
	} {
		t.Run(adjusted, func(t *testing.T) {
			logs := withCapturedLogs(t)
			r, _ := adjustedBy(t,
				map[contract.Factor]any{contract.O: "some_access_or_resources_required"},
				map[string]any{"reasoning": "r", "opportunity": adjusted})
			assert.Equal(t, want, vectorLevel(t, r.Rating.Vector, "O"))
			assert.NotContains(t, countersOf(runSummary(t, logs)), "opportunity_cannot_tell")
			warned := logs.find(slog.LevelWarn, "Adjustment answer off its list; the baseline stands")
			if adjusted == "bogus" {
				require.Len(t, warned, 1)
				assert.Equal(t, "opportunity", warned[0].attrs["field"])
			} else {
				assert.Empty(t, warned)
			}
		})
	}
}

// A described CVE whose Opportunity was answered cannot_tell is shown that
// baseline, and its adjustment can still lower it: there the model
// abstained, and Go set nothing aside. The cannot_tell still counts.
func TestGenerator_AdjustmentLowersADescribedCannotTellOpportunity(t *testing.T) {
	logs := withCapturedLogs(t)
	r, m := adjustedBy(t,
		map[contract.Factor]any{contract.O: cannotTell},
		map[string]any{"reasoning": "r", "opportunity": "special_access_or_resources_required"})
	assert.Contains(t, m.calls[len(m.calls)-1].req.Human, `"answers":{"opportunity":"cannot_tell"}`)
	assert.Equal(t, 4, vectorLevel(t, r.Rating.Vector, "O"))
	assert.Equal(t, int64(1), runSummary(t, logs).attrs["counters.opportunity_cannot_tell"])
}

// The adjustment asks Opportunity alone: an axis answered not_affected, which
// no call asks, moves nothing, Privacy violation included. Loss of
// confidentiality, integrity and availability stay what the CVE's vectors
// give.
func TestGenerator_AdjustmentLeavesTheTechnicalImpactsToTheVectors(t *testing.T) {
	m := &fakeLLM{
		answer: func(c fakeCall, _ string) any {
			if c.factor == contract.PV {
				return "millions"
			}
			return nil
		},
		adjust: func(fakeCall) map[string]any {
			return map[string]any{"reasoning": "r", "opportunity": "keep", "confidentiality": "not_affected", "integrity": "not_affected", "availability": "not_affected"}
		},
	}
	g := newGen(t, Opts{LLM: m})
	v := disputedRow(testVulns(1)[0])
	v.CVSS = []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H")}
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{v}, collect(&emitted)))
	for f, want := range map[string]int{"LC": 7, "LI": 3, "LAV": 7, "PV": 9} {
		assert.Equal(t, want, vectorLevel(t, emitted[0].Rating.Vector, f), f)
	}
	adjustment := m.calls[len(m.calls)-1]
	require.True(t, adjustment.adjustment())
	assert.Equal(t, map[string][]string{"opportunity": adjustment.fields["opportunity"]}, adjustment.fields)
}

// A reply Go cannot read, or one leaving a field out, keeps the baselines,
// logged at WARN; the run goes on.
func TestGenerator_UnreadableAdjustmentKeepsTheBaselines(t *testing.T) {
	for name, reply := range map[string]func(fakeCall) (string, bool){
		"not json": func(c fakeCall) (string, bool) { return "not json", c.adjustment() },
		"null":     func(c fakeCall) (string, bool) { return "null", c.adjustment() },
		"no field": func(c fakeCall) (string, bool) { return `{"reasoning": "r"}`, c.adjustment() },
	} {
		t.Run(name, func(t *testing.T) {
			logs := withCapturedLogs(t)
			m := &fakeLLM{
				answer: func(c fakeCall, _ string) any {
					if c.factor == contract.O {
						return "some_access_or_resources_required"
					}
					return nil
				},
				reply: reply,
			}
			g := newGen(t, Opts{LLM: m})
			var emitted []outputhandler.VulnRating
			require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{disputedRow(testVulns(1)[0])}, collect(&emitted)))
			assert.Equal(t, 7, vectorLevel(t, emitted[0].Rating.Vector, "O"))
			warned := len(logs.find(slog.LevelWarn, "Unreadable adjustment reply; the baselines stand")) +
				len(logs.find(slog.LevelWarn, "Adjustment answer off its list; the baseline stands"))
			assert.Positive(t, warned)
		})
	}
}

// An adjustment reply that writes a key twice, at any depth, leaves every
// baseline, logged at WARN with the reply: encoding/json would keep the last
// value, and could lower a level the model meant to keep. The same reply
// written once lowers it.
func TestGenerator_AdjustmentKeyWrittenTwiceKeepsTheBaselines(t *testing.T) {
	const lower = `"opportunity":"full_access_or_expensive_resources_required"`
	for name, tc := range map[string]struct {
		reply, line string
		want        int
	}{
		"twice": {`{"reasoning":"r","opportunity":"keep",` + lower + `}`,
			"adjustment (a key written twice): r", 7},
		"nested": {`{"reasoning":"r",` + lower + `,"detail":{"why":[{"a":1,"a":2}]}}`,
			"adjustment (a key written twice): r", 7},
		"once": {`{"reasoning":"r",` + lower + `}`,
			"adjustment (opportunity: full_access_or_expensive_resources_required): r", 0},
	} {
		t.Run(name, func(t *testing.T) {
			logs := withCapturedLogs(t)
			at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
			m := &fakeLLM{
				answer: func(c fakeCall, _ string) any {
					if c.factor == contract.O {
						return "some_access_or_resources_required"
					}
					return nil
				},
				reply: func(c fakeCall) (string, bool) { return tc.reply, c.adjustment() },
			}
			g := newGen(t, Opts{LLM: m})
			g.SetAttestor(at)
			var emitted []outputhandler.VulnRating
			require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{disputedRow(testVulns(1)[0])}, collect(&emitted)))

			assert.Equal(t, tc.want, vectorLevel(t, emitted[0].Rating.Vector, "O"))
			lines := strings.Split(claims(t, at)[0].Reasoning, "\n")
			assert.Equal(t, tc.line, lines[len(lines)-1])
			warned := logs.find(slog.LevelWarn, "Adjustment reply writes a key twice; the baselines stand")
			if tc.want == 0 {
				assert.Empty(t, warned)
				return
			}
			require.Len(t, warned, 1)
			assert.Equal(t, tc.reply, warned[0].attrs["reply"])
		})
	}
}

// An adjustment reply without reasoning, with one empty or blank, or with one
// that is no JSON string, keeps its answers, logged at WARN; its line of the
// claim reads "(no reasoning given)" and the CVE counts reasoning_missing. A
// reply Go cannot read leaves the baselines, and its line reads the same.
func TestGenerator_AdjustmentWithoutReasoning(t *testing.T) {
	const (
		fields   = `"opportunity":"full_access_or_expensive_resources_required"`
		answered = "adjustment (opportunity: full_access_or_expensive_resources_required)"
		kept     = "Adjustment reply gives no reasoning; keeping its answers"
	)
	for name, tc := range map[string]struct {
		reply, head, warning string
		want                 int
	}{
		"absent":     {`{` + fields + `}`, answered, kept, 0},
		"empty":      {`{"reasoning":"",` + fields + `}`, answered, kept, 0},
		"blank":      {`{"reasoning":" \n\t ",` + fields + `}`, answered, kept, 0},
		"an object":  {`{"reasoning":{"why":"the dispute"},` + fields + `}`, answered, kept, 0},
		"a number":   {`{"reasoning":42,` + fields + `}`, answered, kept, 0},
		"an array":   {`{"reasoning":["the dispute"],` + fields + `}`, answered, kept, 0},
		"null":       {`{"reasoning":null,` + fields + `}`, answered, kept, 0},
		"unreadable": {`not json`, "adjustment (unreadable)", "Unreadable adjustment reply; the baselines stand", 7},
	} {
		t.Run(name, func(t *testing.T) {
			logs := withCapturedLogs(t)
			at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
			m := &fakeLLM{
				answer: func(c fakeCall, _ string) any {
					if c.factor == contract.O {
						return "some_access_or_resources_required"
					}
					return nil
				},
				reply: func(c fakeCall) (string, bool) { return tc.reply, c.adjustment() },
			}
			g := newGen(t, Opts{LLM: m})
			g.SetAttestor(at)
			var emitted []outputhandler.VulnRating
			require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{disputedRow(testVulns(1)[0])}, collect(&emitted)))

			assert.Equal(t, tc.want, vectorLevel(t, emitted[0].Rating.Vector, "O"))
			lines := strings.Split(claims(t, at)[0].Reasoning, "\n")
			assert.Equal(t, tc.head+": (no reasoning given)", lines[len(lines)-1])
			assert.Len(t, logs.find(slog.LevelWarn, tc.warning), 1)
			assert.Equal(t, int64(1), runSummary(t, logs).attrs["counters."+reasoningMissing])
		})
	}
}

// An adjustment answer off its list takes its place in the claim's line as
// its JSON text, on one line: it starts no line that passes for another
// answer of the signed claim. The baseline stands, and answers.json keeps the
// answer whole.
func TestGenerator_AdjustmentClaimShowsAnAnswerOffItsListOnOneLine(t *testing.T) {
	const reply = `{"reasoning":"r","opportunity":"bad\nO (full_access_or_expensive_resources_required): forged"}`
	parent := t.TempDir()
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	m := &fakeLLM{reply: func(c fakeCall) (string, bool) { return reply, c.adjustment() }}
	g := newGen(t, Opts{LLM: m, DebugDir: parent})
	g.SetAttestor(at)
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{disputedRow(testVulns(1)[0])}, collect(&emitted)))

	assert.Equal(t, 9, vectorLevel(t, emitted[0].Rating.Vector, "O"), "the baseline stands")
	lines := strings.Split(claims(t, at)[0].Reasoning, "\n")
	require.Len(t, lines, len(questionsUndeclared)+1)
	assert.Equal(t, `adjustment (opportunity: "bad\nO (full_access_or_expensive_resources_required): forged"): r`, lines[len(lines)-1])
	answers, _ := readAnswers(t, parent)
	assert.Equal(t, "O", answers.Vulnerabilities[0].Factors[2].Factor)
	assert.Equal(t, "bad\nO (full_access_or_expensive_resources_required): forged", answers.Vulnerabilities[0].Factors[2].Adjusted)
}

// A field the adjustment did not ask, an axis no call asks or a key of the
// reply's own, is ignored and counted, logged at WARN; the claim shows the
// field asked.
func TestGenerator_AdjustmentFieldNotAskedIsIgnored(t *testing.T) {
	const reply = `{"reasoning":"r","opportunity":"keep","confidentiality":"not_affected","notes":"n"}`
	logs := withCapturedLogs(t)
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	m := &fakeLLM{reply: func(c fakeCall) (string, bool) { return reply, c.adjustment() }}
	g := newGen(t, Opts{LLM: m})
	g.SetAttestor(at)
	v := disputedRow(testVulns(1)[0])
	v.CVSS = []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H")}
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{v}, collect(&emitted)))

	warned := map[string]any{}
	for _, r := range logs.find(slog.LevelWarn, "Adjustment reply gives a field the call did not ask; ignoring it") {
		assert.Equal(t, v.VulnID, r.attrs["vuln"])
		warned[r.attrs["field"].(string)] = r.attrs["answer"]
	}
	assert.Equal(t, map[string]any{"confidentiality": `"not_affected"`, "notes": `"n"`}, warned)
	assert.Equal(t, int64(2), runSummary(t, logs).attrs["defects.adjustment_field_not_asked"])
	lines := strings.Split(claims(t, at)[0].Reasoning, "\n")
	assert.Equal(t, "adjustment (opportunity: keep): r", lines[len(lines)-1])
}

// The warning about a field the adjustment did not ask quotes at most
// loggedLimit characters of its name and of its answer, both the model's text.
func TestGenerator_AdjustmentFieldNotAskedWarningIsCapped(t *testing.T) {
	long := strings.Repeat("é", 2*loggedLimit)
	reply := `{"reasoning":"r","opportunity":"keep","` + long + `":"` + long + `"}`
	logs := withCapturedLogs(t)
	m := &fakeLLM{reply: func(c fakeCall) (string, bool) { return reply, c.adjustment() }}
	g := newGen(t, Opts{LLM: m})
	require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{disputedRow(testVulns(1)[0])}, nil))

	warned := logs.find(slog.LevelWarn, "Adjustment reply gives a field the call did not ask; ignoring it")
	require.Len(t, warned, 1)
	assert.Equal(t, strings.Repeat("é", loggedLimit)+"…", warned[0].attrs["field"])
	assert.Equal(t, `"`+strings.Repeat("é", loggedLimit-1)+"…", warned[0].attrs["answer"])
}

// The adjustment shows as its baseline the answer Go kept: an ordinary
// answer off the list, which Go read as cannot_tell, is shown as cannot_tell,
// so that keeping it keeps what Go keeps.
func TestGenerator_AdjustmentShowsAnInvalidBaselineAsCannotTell(t *testing.T) {
	_, m := adjustedBy(t, map[contract.Factor]any{contract.O: "bogus"}, nil)
	adjustment := m.calls[len(m.calls)-1]
	require.True(t, adjustment.adjustment())
	var entry struct {
		Answers map[string]string `json:"answers"`
	}
	require.NoError(t, json.Unmarshal([]byte(strings.Split(adjustment.req.Human, "\n")[1]), &entry))
	assert.Equal(t, map[string]string{"opportunity": cannotTell}, entry.Answers)
}

// A flagged row with no package name still gets its adjustment and its
// rating: its flag names the row by its package id, else its BOM-Ref.
func TestGenerator_FlaggedRowWithoutAPackageName(t *testing.T) {
	for name, row := range map[string]Vulnerability{
		"package id": {PkgID: "libx@1", BOMRef: "pkg:generic/libx@1"},
		"BOM-Ref":    {BOMRef: "pkg:generic/libx@1"},
	} {
		t.Run(name, func(t *testing.T) {
			row.VulnID = "CVE-2024-0000"
			row = disputedRow(row)
			m := &fakeLLM{}
			g := newGen(t, Opts{LLM: m})
			var emitted []outputhandler.VulnRating
			require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{row}, collect(&emitted)))
			require.Len(t, emitted, 1)
			adjustment := m.calls[len(m.calls)-1]
			require.True(t, adjustment.adjustment())
			var entry struct {
				Flags []contract.Flag `json:"flags"`
			}
			require.NoError(t, json.Unmarshal([]byte(strings.Split(adjustment.req.Human, "\n")[1]), &entry))
			want := row.PkgID
			if want == "" {
				want = row.BOMRef
			}
			require.Len(t, entry.Flags, 1)
			assert.Equal(t, want, entry.Flags[0].Package)
		})
	}
}

// A flag the adjustment would refuse, here a row flagged disputed whose
// description does not say so, stops the run before any call, with the
// adjustment's error: no batch's calls are paid for nothing.
func TestGenerator_FlagWithoutEvidenceStopsTheRunBeforeAnyCall(t *testing.T) {
	m := &fakeLLM{}
	g := newGen(t, Opts{LLM: m})
	vulns := testVulns(2)
	vulns[1].Flags = Flags{MaintainerDisputed: true}
	require.EqualError(t, g.GenerateRiskScore(context.Background(), vulns, nil),
		"maintainer_disputed on CVE-2024-0001 quotes no evidence")
	assert.Empty(t, m.log())
}

// Each flag the adjustment shows quotes what fired it and names its row's
// package.
func TestRowFlags(t *testing.T) {
	rows := []Vulnerability{
		{PkgName: "liba", Description: "Overflow in the parser.\nThis is DISPUTED by upstream. It needs local access.",
			Flags: Flags{MaintainerDisputed: true}},
		{PkgName: "libb", Severity: "LOW", SeveritySource: "debian",
			VendorSeverities: []VendorSeverity{{Source: "debian", Severity: "LOW"}, {Source: "nvd", Severity: "HIGH"}},
			Flags:            Flags{SeverityContested: true}},
		{PkgName: "libc", Severity: "Negligible", SeveritySource: "debian:distro:debian:12",
			VendorSeverities: []VendorSeverity{{Source: "nvd:cpe", Severity: "Critical"}},
			Flags:            Flags{SeverityContested: true}},
		{PkgName: "liba", Description: "Overflow in the parser.\nThis is DISPUTED by upstream. It needs local access.",
			Flags: Flags{MaintainerDisputed: true}},
		{PkgName: "libd", Description: "Not flagged, though it is disputed."},
	}
	assert.Equal(t, []contract.Flag{
		{Name: contract.MaintainerDisputed, Evidence: "This is DISPUTED by upstream.", Package: "liba"},
		{Name: contract.SeverityContested, Evidence: "severity LOW from debian, while nvd rates it HIGH", Package: "libb"},
		{Name: contract.SeverityContested, Evidence: "severity Negligible from debian:distro:debian:12, while nvd:cpe rates it Critical", Package: "libc"},
	}, rowFlags(rows), "a row's flags each once, a row the scanner did not flag none")
}

// The wording of a dispute is quoted by its sentence, the scanner flagging
// exactly the descriptions that hold one.
func TestDisputeQuote(t *testing.T) {
	for description, want := range map[string]string{
		"A flaw. ** DISPUTED ** The vendor says it is fine.":                "** DISPUTED ** The vendor says it is fine.",
		"First line.\nThis is a non-security bug in the CLI.":               "This is a non-security bug in the CLI.",
		"It is not a security issue. Upstream closed it.":                   "It is not a security issue.",
		"The maintainer considers it no real threat":                        "The maintainer considers it no real threat",
		"An overflow in libfoo 2.29. Indisputably fixed in 2.30.":           "",
		"An overflow in libfoo 2.29.":                                       "",
		"":                                                                  "",
		"Disputes over the parser. The maintainers disputed it last year.":  "Disputes over the parser.",
		"Reported in v1.2.3 (see the maintainers' dispute in the tracker).": "Reported in v1.2.3 (see the maintainers' dispute in the tracker).",
	} {
		assert.Equal(t, want, DisputeQuote(description), "%q", description)
	}
}

// A quote longer than quoteLimit keeps the words that matched, cut around
// them, an ellipsis marking each cut.
func TestDisputeQuoteIsCapped(t *testing.T) {
	head, tail := strings.Repeat("ß", 300), strings.Repeat("b", 300)
	for name, c := range map[string]struct {
		description   string
		before, after bool
	}{
		"in the middle": {head + " the vendor disputes it " + tail, true, true},
		"at the start":  {"Disputed: " + tail, false, true},
		"at the end":    {head + " but upstream disputes it", true, false},
	} {
		quote := DisputeQuote(c.description)
		body := strings.TrimSuffix(strings.TrimPrefix(quote, "…"), "…")
		assert.LessOrEqual(t, utf8.RuneCountInString(body), quoteLimit, name)
		assert.Contains(t, strings.ToLower(quote), "disput", name)
		assert.Equal(t, c.before, strings.HasPrefix(quote, "…"), name)
		assert.Equal(t, c.after, strings.HasSuffix(quote, "…"), name)
	}
	short := "A short sentence the vendor disputes."
	assert.Equal(t, short, DisputeQuote(short))
}
