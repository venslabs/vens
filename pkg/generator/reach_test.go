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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/outputhandler"
)

// unreachableAnswers answers reachability not_reachable for the CVEs named,
// and every other question at the fake's default.
func unreachableAnswers(ids ...string) func(fakeCall, string) any {
	return func(c fakeCall, id string) any {
		if c.factor == contract.R {
			for _, unreachable := range ids {
				if id == unreachable {
					return "not_reachable"
				}
			}
		}
		return nil
	}
}

// Reachability is asked first, of every CVE. A CVE answered not_reachable is
// left out of Opportunity's, Ease of exploit's and the four technical
// impacts' calls; a batch none of whose CVEs is reachable sends none of
// them. Its vector holds the six at their lowest, answers.json their source,
// reachability, and its claim the reachability line.
func TestGenerator_NotReachableIsNotAskedTheSixQuestions(t *testing.T) {
	parent := t.TempDir()
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	cfg := testConfig()
	cfg.Context.Traceability = ptr("per_individual")
	m := &fakeLLM{answer: unreachableAnswers("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003")}
	g := newGen(t, Opts{LLM: m, Config: cfg, BatchSize: 2, DebugDir: parent})
	g.SetAttestor(at)
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(4), collect(&emitted)))

	both, first := []string{"CVE-2024-0000", "CVE-2024-0001"}, []string{"CVE-2024-0000"}
	var calls []string
	for _, c := range m.calls {
		calls = append(calls, string(c.factor)+" "+strings.Join(c.ids, ","))
	}
	assert.Equal(t, []string{
		"R " + strings.Join(both, ","), "M " + strings.Join(both, ","),
		"O " + first[0], "EE " + first[0], "LC " + first[0], "LI " + first[0], "LAV " + first[0], "LAC " + first[0],
		"FD " + strings.Join(both, ","), "RD " + strings.Join(both, ","), "PV " + strings.Join(both, ","),
		"R CVE-2024-0002,CVE-2024-0003", "M CVE-2024-0002,CVE-2024-0003",
		"FD CVE-2024-0002,CVE-2024-0003", "RD CVE-2024-0002,CVE-2024-0003", "PV CVE-2024-0002,CVE-2024-0003",
	}, calls)

	got := byID(emitted)
	for _, id := range []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"} {
		for f, want := range map[string]int{"O": 0, "EE": 1, "LC": 2, "LI": 1, "LAV": 1, "LAC": 1} {
			assert.Equal(t, want, vectorLevel(t, got[id].Rating.Vector, f), "%s %s", id, f)
		}
	}
	assert.Equal(t, 9, vectorLevel(t, got["CVE-2024-0000"].Rating.Vector, "O"), "reachable, the fake's first answer")

	answers, _ := readAnswers(t, parent)
	for _, v := range answers.Vulnerabilities {
		require.NotNil(t, v.Reachability, v.VulnID)
		want := "reachable"
		if v.VulnID != "CVE-2024-0000" {
			want = "not_reachable"
		}
		assert.Equal(t, []any{want, "answered"}, []any{v.Reachability.Answer, v.Reachability.Reading}, v.VulnID)
		for _, f := range v.Factors {
			if !strings.Contains(" O EE LC LI LAV LAC ", " "+f.Factor+" ") {
				continue
			}
			if want == "not_reachable" {
				assert.Equal(t, []any{nil, "", "reachability"}, []any{f.Answer, f.Reading, f.Source}, "%s %s", v.VulnID, f.Factor)
			} else {
				assert.Equal(t, "answer", f.Source, "%s %s", v.VulnID, f.Factor)
			}
		}
		for _, counter := range v.Counters {
			assert.NotContains(t, counter, "cannot_tell", v.VulnID)
		}
	}
	reasonings := map[string][]string{}
	for _, c := range claims(t, at) {
		reasonings[c.Target] = strings.Split(c.Reasoning, "\n")
	}
	assert.Equal(t, []string{
		"R (not_reachable): because of CVE-2024-0001", "M (low_or_no_reward): because of CVE-2024-0001",
		"FD (less_than_cost_to_fix): because of CVE-2024-0001", "RD (minimal_damage): because of CVE-2024-0001",
		"PV (none): because of CVE-2024-0001",
	}, reasonings["ref-1"])
	assert.Len(t, reasonings["ref-0"], len(questionsUndeclared))
}

// A flagged CVE answered not_reachable, whose Privacy violation was asked,
// gets an adjustment call that shows reachability's answer as the one given
// and asks confidentiality alone; not_affected lowers Privacy violation to its
// floor, from the adjustment, and the six factors reachability decides stay
// at their lowest, from reachability. A flagged CVE read as reachable still
// gets its own call, unchanged.
func TestGenerator_NotReachableAdjustmentAsksConfidentialityAlone(t *testing.T) {
	parent := t.TempDir()
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	vulns := []Vulnerability{disputedRow(testVulns(2)[0]), disputedRow(testVulns(2)[1])}
	m := &fakeLLM{
		answer: func(c fakeCall, id string) any {
			switch {
			case c.factor == contract.R && id == "CVE-2024-0000":
				return "not_reachable"
			case c.factor == contract.PV:
				return "millions"
			}
			return nil
		},
		adjust: func(c fakeCall) map[string]any {
			if _, reachable := c.fields["opportunity"]; reachable {
				return map[string]any{"reasoning": "r", "opportunity": "keep", "confidentiality": "affected", "integrity": "affected", "availability": "affected"}
			}
			return map[string]any{"reasoning": "no data reached", "confidentiality": "not_affected"}
		},
	}
	g := newGen(t, Opts{LLM: m, DebugDir: parent})
	g.SetAttestor(at)
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, collect(&emitted)))

	var adjustments []fakeCall
	for _, c := range m.calls {
		if c.adjustment() {
			adjustments = append(adjustments, c)
		}
	}
	require.Len(t, adjustments, 2)
	unreached, reached := adjustments[0], adjustments[1]
	assert.Equal(t, map[string][]string{"confidentiality": {"affected", "not_affected", cannotTell}}, unreached.fields)
	for _, part := range []string{
		`"vulnId":"CVE-2024-0000"`, `"answers":{"reachability":"not_reachable"}}`,
		"and the answer it was given without that evidence: not reachable here, as reachability is defined above.",
		"QUESTIONS\nconfidentiality: Given this evidence, can exploiting it here affect confidentiality at all?",
	} {
		assert.Contains(t, unreached.req.Human, part)
	}
	assert.NotContains(t, unreached.req.Human, "opportunity")
	assert.Contains(t, reached.req.Human, `"vulnId":"CVE-2024-0001"`)
	assert.Contains(t, reached.req.Human, `"answers":{"opportunity":`)
	assert.Contains(t, reached.req.Human, "and the answers it was given without that evidence. Reconsider it")

	got := byID(emitted)
	for f, want := range map[string]int{"O": 0, "EE": 1, "LC": 2, "LI": 1, "LAV": 1, "LAC": 7, "PV": 3} {
		assert.Equal(t, want, vectorLevel(t, got["CVE-2024-0000"].Rating.Vector, f), f)
	}
	assert.Equal(t, 9, vectorLevel(t, got["CVE-2024-0001"].Rating.Vector, "PV"), "affected leaves the answer's level")

	answers, _ := readAnswers(t, parent)
	v := answers.Vulnerabilities[0]
	require.Equal(t, "CVE-2024-0000", v.VulnID)
	assert.Equal(t, "answered", v.Adjustment)
	for _, f := range v.Factors {
		switch {
		case f.Factor == "PV":
			assert.Equal(t, []any{"millions", "adjustment"}, []any{f.Answer, f.Source})
		case strings.Contains(" O EE LC LI LAV LAC ", " "+f.Factor+" "):
			assert.Equal(t, "reachability", f.Source, f.Factor)
		}
	}
	reasonings := map[string]string{}
	for _, c := range claims(t, at) {
		reasonings[c.Target] = c.Reasoning
	}
	assert.True(t, strings.HasSuffix(reasonings["ref-0"], "\nadjustment (confidentiality: not_affected): no data reached"), reasonings["ref-0"])
}

// A flagged CVE answered not_reachable whose Privacy violation was not asked,
// data_subjects capping it at its floor or Applicability flooring
// confidentiality, has nothing left to adjust: no call.
func TestGenerator_NotReachableWithoutPrivacyViolationGetsNoAdjustment(t *testing.T) {
	for name, tc := range map[string]struct {
		subjects *string
		vector   string
	}{
		"one individual":        {subjects: ptr("one_individual")},
		"confidentiality floor": {vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"},
	} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			cfg := testConfig()
			cfg.Context.DataSubjects = tc.subjects
			v := disputedRow(testVulns(1)[0])
			if tc.vector != "" {
				v.CVSS = []cvss.Vector{v31("nvd", tc.vector)}
			}
			m := &fakeLLM{answer: unreachableAnswers("CVE-2024-0000")}
			g := newGen(t, Opts{LLM: m, Config: cfg, DebugDir: parent})
			require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{v}, nil))

			assert.NotContains(t, m.log(), adjustmentCall)
			assert.NotContains(t, m.log(), "PV")
			answers, _ := readAnswers(t, parent)
			assert.Equal(t, "not_asked", answers.Vulnerabilities[0].Adjustment)
		})
	}
}

// cannot_tell on reachability is read as reachable, the worst case: the six
// questions are asked and the CVE counts reachability_cannot_tell. An answer
// off the list reads the same way.
func TestGenerator_ReachabilityCannotTellAsksTheSix(t *testing.T) {
	logs := withCapturedLogs(t)
	m := &fakeLLM{answer: func(c fakeCall, id string) any {
		if c.factor != contract.R {
			return nil
		}
		if id == "CVE-2024-0000" {
			return cannotTell
		}
		return "bogus"
	}}
	g := newGen(t, Opts{LLM: m})
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), nil))

	assert.Equal(t, questionsUndeclared, m.log())
	for _, c := range m.calls {
		assert.Len(t, c.ids, 2, "%s asks both", c.factor)
	}
	summary := runSummary(t, logs)
	assert.Equal(t, int64(2), summary.attrs["counters.reachability_cannot_tell"])
	assert.Equal(t, int64(1), summary.attrs["defects.answer_off_list"])
}

// A strict run stops at a reachability answer Go reads as cannot_tell: it
// would assume the worst case.
func TestGenerator_StrictStopsAtReachabilityCannotTell(t *testing.T) {
	m := &fakeLLM{answer: func(c fakeCall, _ string) any {
		if c.factor == contract.R {
			return cannotTell
		}
		return nil
	}}
	g := newGen(t, Opts{LLM: m, Config: strictConfig(), Strict: true})
	err := g.GenerateRiskScore(context.Background(), []Vulnerability{complete(testVulns(1)[0])}, nil)
	require.EqualError(t, err, "strict: the answer to Reachability (R) for CVE-2024-0000 reads as cannot_tell, counted as reachability_cannot_tell; stopping the run")
	assert.Equal(t, []string{"R"}, m.log())
}
