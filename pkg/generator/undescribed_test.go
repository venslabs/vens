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
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/riskconfig"
)

const undescribedWarning = "No description in the scanner's report; Motive, Opportunity and Ease of exploit are not asked, each at its worst level"

// undescribedVulns are four CVEs: CVE-2024-0000 described; CVE-2024-0001
// with a title alone; CVE-2024-0002 on two rows, one blank, one with
// nothing; CVE-2024-0003 on two rows, one described.
func undescribedVulns() []Vulnerability {
	return []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "a", Title: "t", Description: "A described vulnerability.", BOMRef: "a"},
		{VulnID: "CVE-2024-0001", PkgName: "b", Title: "[Privilege escalation possible to other user than root]", BOMRef: "b"},
		{VulnID: "CVE-2024-0002", PkgName: "c", Description: " \n\t", BOMRef: "c1"},
		{VulnID: "CVE-2024-0002", PkgName: "d", BOMRef: "c2"},
		{VulnID: "CVE-2024-0003", PkgName: "e", BOMRef: "d1"},
		{VulnID: "CVE-2024-0003", PkgName: "f", Description: "Described on one row.", BOMRef: "d2"},
	}
}

// A CVE no row describes, a title alone or a blank description included, is
// not asked Motive, Opportunity and Ease of exploit: each takes its worst
// level, 9, read no_description and counted as cannot_tell, while its other
// questions are asked as ever. answers.json gives the three no answer, and
// the claim says "not asked: no description" for each. One WARN names those
// CVEs before the first call.
func TestGenerator_UndescribedCVEIsNotAskedTheLikelihoodQuestions(t *testing.T) {
	logs := withCapturedLogs(t)
	parent := t.TempDir()
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	warnedFirst := false
	m := &fakeLLM{fail: func(c fakeCall) error {
		if c.n == 1 {
			warnedFirst = len(logs.find(slog.LevelWarn, undescribedWarning)) == 1
		}
		return nil
	}}
	g := newGen(t, Opts{LLM: m, DebugDir: parent})
	g.SetAttestor(at)
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), undescribedVulns(), collect(&emitted)))

	described, all := []string{"CVE-2024-0000", "CVE-2024-0003"}, []string{"CVE-2024-0000", "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}
	for _, c := range m.calls {
		want := all
		if c.factor == contract.M || c.factor == contract.O || c.factor == contract.EE {
			want = described
		}
		assert.Equal(t, want, c.ids, "%s's call", c.factor)
	}
	assert.Len(t, m.calls, len(questionsUndeclared))

	got := byID(emitted)
	for _, id := range []string{"CVE-2024-0001", "CVE-2024-0002"} {
		for _, f := range []string{"M", "O", "EE"} {
			assert.Equal(t, 9, vectorLevel(t, got[id].Rating.Vector, f), "%s %s", id, f)
		}
	}
	assert.Equal(t, 1, vectorLevel(t, got["CVE-2024-0003"].Rating.Vector, "M"), "one row described is enough")

	summary := runSummary(t, logs)
	for _, counter := range []string{"motive_cannot_tell", "opportunity_cannot_tell", "ease_of_exploit_cannot_tell"} {
		assert.Equal(t, int64(2), summary.attrs["counters."+counter], counter)
	}
	warned := logs.find(slog.LevelWarn, undescribedWarning)
	require.Len(t, warned, 1)
	assert.Equal(t, map[string]any{"cves": int64(2), "vulns": "CVE-2024-0001,CVE-2024-0002"}, warned[0].attrs)
	assert.True(t, warnedFirst, "logged before the first call")

	answers, _ := readAnswers(t, parent)
	records := map[string][]string{}
	for _, v := range answers.Vulnerabilities {
		for _, f := range v.Factors {
			if f.Factor == "M" || f.Factor == "O" || f.Factor == "EE" {
				records[v.VulnID] = append(records[v.VulnID], fmt.Sprintf("%s %v %s %d %s", f.Factor, f.Answer, f.Reading, *f.Level, f.Source))
			}
		}
	}
	notAsked := []string{"M <nil> no_description 9 answer", "O <nil> no_description 9 answer", "EE <nil> no_description 9 answer"}
	assert.Equal(t, notAsked, records["CVE-2024-0001"])
	assert.Equal(t, notAsked, records["CVE-2024-0002"])
	assert.Equal(t, []string{"M low_or_no_reward answered 1 answer", "O no_access_or_resources_required answered 9 answer",
		"EE theoretical answered 1 answer"}, records["CVE-2024-0000"])

	reasonings := map[string][]string{}
	for _, c := range claims(t, at) {
		reasonings[c.Target] = strings.Split(c.Reasoning, "\n")
	}
	for _, target := range []string{"b", "c1", "c2"} {
		lines := reasonings[target]
		require.Len(t, lines, len(questionsUndeclared), target)
		assert.Equal(t, []string{"M (not asked: no description)", "O (not asked: no description)", "EE (not asked: no description)"}, lines[:3], target)
		assert.True(t, strings.HasPrefix(lines[3], "LAC (identified): because of CVE-2024-000"), lines[3])
	}
	for _, target := range []string{"a", "d1", "d2"} {
		assert.NotContains(t, strings.Join(reasonings[target], "\n"), "not asked", target)
	}
}

// A batch whose CVEs no row describes makes no call for Motive, Opportunity
// or Ease of exploit: a question no CVE of the batch gets is not sent. A run
// whose CVEs are all described logs no WARN about them.
func TestGenerator_UndescribedBatchSendsNoLikelihoodCall(t *testing.T) {
	logs := withCapturedLogs(t)
	m := &fakeLLM{}
	g := newGen(t, Opts{LLM: m, BatchSize: 2})
	vulns := testVulns(3)
	vulns[0].Description, vulns[1].Description = "", ""
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))
	want := append(append([]string{}, questionsUndeclared[3:]...), questionsUndeclared...)
	assert.Equal(t, want, m.log(), "the first batch's questions from LAC on, then the second's every question")
	summary := runSummary(t, logs)
	assert.Equal(t, int64(1), summary.attrs["calls.M"])
	assert.Equal(t, int64(2), summary.attrs["calls.LAC"])

	logs = withCapturedLogs(t)
	g = newGen(t, Opts{LLM: &fakeLLM{}})
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), nil))
	assert.Empty(t, logs.find(slog.LevelWarn, undescribedWarning))
}

// A strict run still refuses a CVE no row describes at its preflight, before
// the WARN and before any call.
func TestGenerator_StrictRefusesAnUndescribedCVEFirst(t *testing.T) {
	logs := withCapturedLogs(t)
	m := &fakeLLM{}
	g := newGen(t, Opts{LLM: m, Config: strictConfig(), Strict: true})
	v := complete(testVulns(1)[0])
	v.Description = ""
	require.EqualError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{v}, nil),
		"strict: 1 vulnerability would fall back to a worst case, so no LLM call is made:\n  "+
			"CVE-2024-0000: no description in the scanner's report, so Motive, Opportunity and Ease of exploit are not asked and take their worst case")
	assert.Empty(t, m.calls)
	assert.Empty(t, logs.find(slog.LevelWarn, undescribedWarning))
}

// contestedUndescribed is a CVE no row describes that its severity sources
// flag, the one flag such a CVE can raise: the scanner rates it LOW from
// debian, NVD CRITICAL. It has no vector.
func contestedUndescribed() Vulnerability {
	v := testVulns(1)[0]
	v.Title, v.Description = "[Privilege escalation possible to other user than root]", ""
	v.Severity, v.SeveritySource = "LOW", "debian"
	v.VendorSeverities = []VendorSeverity{{Source: "debian", Severity: "LOW"}, {Source: "nvd", Severity: "CRITICAL"}}
	v.Flags = Flags{SeverityContested: true}
	return v
}

// The adjustment of a CVE no row describes asks confidentiality alone, for
// Privacy violation, which it was asked: a description is a prerequisite of
// any Opportunity answer. Its request shows no Opportunity question, baseline
// or reply field. An Opportunity the reply gives all the same is ignored,
// counted and logged, O staying at 9 with no adjusted answer recorded; not
// affected floors Privacy violation, and answers.json records it there.
func TestGenerator_AdjustmentOfAnUndescribedCVEAsksConfidentialityAlone(t *testing.T) {
	logs := withCapturedLogs(t)
	parent := t.TempDir()
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	m := &fakeLLM{
		answer: func(c fakeCall, _ string) any {
			if c.factor == contract.PV {
				return "millions"
			}
			return nil
		},
		adjust: func(fakeCall) map[string]any {
			return map[string]any{"reasoning": "r", "opportunity": "full_access_or_expensive_resources_required", "confidentiality": "not_affected"}
		},
	}
	g := newGen(t, Opts{LLM: m, DebugDir: parent})
	g.SetAttestor(at)
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{contestedUndescribed()}, collect(&emitted)))

	adjustment := m.calls[len(m.calls)-1]
	require.True(t, adjustment.adjustment())
	assert.Equal(t, map[string][]string{"confidentiality": {"affected", "not_affected", cannotTell}}, adjustment.fields)
	assert.NotContains(t, strings.ToLower(adjustment.req.Human), "opportunit")
	assert.NotContains(t, adjustment.req.Human, `"answers"`)
	for f, want := range map[string]int{"O": 9, "PV": 3, "LC": 9} {
		assert.Equal(t, want, vectorLevel(t, emitted[0].Rating.Vector, f), f)
	}
	warned := logs.find(slog.LevelWarn, "Adjustment reply gives a field the call did not ask; ignoring it")
	require.Len(t, warned, 1)
	assert.Equal(t, "opportunity", warned[0].attrs["field"])
	lines := strings.Split(claims(t, at)[0].Reasoning, "\n")
	assert.Equal(t, "adjustment (confidentiality: not_affected): r", lines[len(lines)-1])
	answers, _ := readAnswers(t, parent)
	for _, f := range answers.Vulnerabilities[0].Factors {
		switch f.Factor {
		case "O":
			assert.Equal(t, []any{"", 9, "answer"}, []any{f.Adjusted, *f.Level, f.Source})
		case "PV":
			assert.Equal(t, []any{"not_affected", 3, "adjustment"}, []any{f.Adjusted, *f.Level, f.Source})
		}
	}
}

// An adjustment with nothing left to ask makes no call: a flagged CVE no row
// describes whose usable v3 vectors give C:N, or whose Privacy violation
// data_subjects caps, keeps the levels it has, its adjustment not_asked and
// its claim without an adjustment line.
func TestGenerator_NoAdjustmentWithNothingLeftToAsk(t *testing.T) {
	capped := testConfig()
	capped.Context.DataSubjects = ptr("none")
	for name, tc := range map[string]struct {
		cfg     *riskconfig.Config
		vectors []cvss.Vector
		asked   []string
	}{
		"C at N":                  {testConfig(), []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H")}, []string{"LAC", "FD", "RD"}},
		"data_subjects none":      {capped, nil, []string{"LAC", "FD", "RD"}},
		"data_subjects none, C:H": {capped, []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")}, []string{"LAC", "FD", "RD"}},
	} {
		t.Run(name, func(t *testing.T) {
			logs := withCapturedLogs(t)
			parent := t.TempDir()
			at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
			m := &fakeLLM{}
			g := newGen(t, Opts{LLM: m, Config: tc.cfg, DebugDir: parent})
			g.SetAttestor(at)
			v := contestedUndescribed()
			v.CVSS = tc.vectors
			var emitted []outputhandler.VulnRating
			require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{v}, collect(&emitted)))

			assert.Equal(t, tc.asked, m.log(), "no Motive, Opportunity, Ease of exploit, Privacy violation or adjustment")
			assert.NotContains(t, runSummary(t, logs).attrs, "calls."+adjustmentCall)
			assert.Equal(t, 9, vectorLevel(t, emitted[0].Rating.Vector, "O"))
			assert.Equal(t, 3, vectorLevel(t, emitted[0].Rating.Vector, "PV"))
			answers, _ := readAnswers(t, parent)
			assert.Equal(t, "not_asked", answers.Vulnerabilities[0].Adjustment)
			for _, line := range strings.Split(claims(t, at)[0].Reasoning, "\n") {
				assert.False(t, strings.HasPrefix(line, adjustmentCall), line)
			}
		})
	}
}
