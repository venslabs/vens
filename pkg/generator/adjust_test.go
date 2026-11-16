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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/contract"
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
				map[string]any{"reasoning": "r", "opportunity": adjusted, "confidentiality": "affected", "integrity": "affected", "availability": "affected"})
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

// An axis answered not_affected takes its floor, confidentiality's taking
// Privacy violation's too; affected and cannot_tell leave the baselines.
func TestGenerator_AdjustmentFloorsAnAxisNotAffected(t *testing.T) {
	r, m := adjustedBy(t,
		map[contract.Factor]any{
			contract.LC: "all", contract.PV: "millions",
			contract.LI: "all_data_totally_corrupt", contract.LAV: "all_services_completely_lost",
		},
		map[string]any{"reasoning": "r", "opportunity": "keep", "confidentiality": "not_affected", "integrity": "affected", "availability": cannotTell})
	for f, want := range map[string]int{"LC": 2, "PV": 3, "LI": 9, "LAV": 9} {
		assert.Equal(t, want, vectorLevel(t, r.Rating.Vector, f), f)
	}
	assert.Equal(t, adjustmentCall, m.log()[len(m.calls)-1])
}

// A reply Go cannot read, or one leaving a field out, keeps the baselines,
// logged at WARN; the run goes on.
func TestGenerator_UnreadableAdjustmentKeepsTheBaselines(t *testing.T) {
	for name, reply := range map[string]func(fakeCall) (string, bool){
		"not json": func(c fakeCall) (string, bool) { return "not json", c.adjustment() },
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

// The adjustment shows as its baseline the answer Go kept: an ordinary
// answer off the list, which Go read as cannot_tell, is shown as cannot_tell,
// so that keeping it keeps what Go keeps. A floored axis shows none.
func TestGenerator_AdjustmentShowsAnInvalidBaselineAsCannotTell(t *testing.T) {
	_, m := adjustedBy(t,
		map[contract.Factor]any{contract.O: "bogus", contract.LC: 42, contract.LI: "minimal_seriously_corrupt"}, nil)
	adjustment := m.calls[len(m.calls)-1]
	require.True(t, adjustment.adjustment())
	var entry struct {
		Answers map[string]string `json:"answers"`
	}
	require.NoError(t, json.Unmarshal([]byte(strings.Split(adjustment.req.Human, "\n")[1]), &entry))
	assert.Equal(t, map[string]string{
		"opportunity": cannotTell, "confidentiality": cannotTell,
		"integrity": "minimal_seriously_corrupt", "availability": "minimal_secondary_interrupted",
	}, entry.Answers)
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
