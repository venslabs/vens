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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/contract"
)

// runSummary returns the run's one INFO summary.
func runSummary(t *testing.T, logs *captureHandler) capturedRecord {
	t.Helper()
	found := logs.find(slog.LevelInfo, "Scoring run finished")
	require.Len(t, found, 1, "one summary per run")
	return found[0]
}

// countersOf reads the summary's counters.
func countersOf(r capturedRecord) map[string]int64 {
	out := map[string]int64{}
	for k, v := range r.attrs {
		if name, ok := strings.CutPrefix(k, "counters."); ok {
			out[name] = v.(int64)
		}
	}
	return out
}

// defectsOf reads the summary's defects.
func defectsOf(r capturedRecord) map[string]int {
	out := map[string]int{}
	for k, v := range r.attrs {
		if kind, ok := strings.CutPrefix(k, "defects."); ok {
			out[kind] = int(v.(int64))
		}
	}
	return out
}

// Every batch logs its composition at debug level, and the run closes with an
// INFO summary: rows, distinct CVEs, the calls, per question too, the
// asks-again and splits, and each counter that is not zero.
func TestGenerator_LogsBatchCompositionAndRunSummary(t *testing.T) {
	g := newGen(t, Opts{LLM: &fakeLLM{}, BatchSize: 2})

	logs := withCapturedLogs(t)
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(4), nil))

	batches := logs.find(slog.LevelDebug, "scoring batch")
	require.Len(t, batches, 2, "one debug line per batch")
	require.Equal(t, int64(2), batches[0].attrs["cves"])
	require.Equal(t, "CVE-2024-0000,CVE-2024-0001", batches[0].attrs["vulns"])
	require.Equal(t, int64(2), batches[1].attrs["cves"])
	require.Equal(t, "CVE-2024-0002,CVE-2024-0003", batches[1].attrs["vulns"])

	summary := runSummary(t, logs)
	require.Equal(t, int64(4), summary.attrs["rows"])
	require.Equal(t, int64(4), summary.attrs["cves"])
	require.Equal(t, int64(14), summary.attrs["llm_calls"])
	require.Equal(t, int64(0), summary.attrs["asked_again"])
	require.Equal(t, int64(0), summary.attrs["splits"])
	require.Equal(t, false, summary.attrs["failed"])
	for _, f := range questionsUndeclared {
		require.Equal(t, int64(2), summary.attrs["calls."+f], "question %s", f)
	}
	require.NotContains(t, summary.attrs, "calls.ID")
	require.NotContains(t, summary.attrs, "calls."+adjustmentCall)
	require.Equal(t, map[string]int64{
		"cvss_v3_missing": 4, "data_subjects_missing": 4, "detection_undeclared": 4, "traceability_missing": 4,
	}, countersOf(summary), "testVulns carry no vector; testConfig declares no optional field")
}

// A failed run still logs its summary, marked failed: it is the run one
// usually debugs.
func TestGenerator_LogsRunSummaryWhenTheRunFails(t *testing.T) {
	m := &fakeLLM{skip: func(_ fakeCall, id string) bool { return id == "CVE-2024-0000" }}
	g := newGen(t, Opts{LLM: m, BatchSize: 2})

	logs := withCapturedLogs(t)
	require.Error(t, g.GenerateRiskScore(context.Background(), testVulns(4), nil))

	summary := runSummary(t, logs)
	require.Equal(t, true, summary.attrs["failed"])
	require.Equal(t, int64(4), summary.attrs["rows"])
	require.Equal(t, int64(4), summary.attrs["cves"])
	require.Equal(t, int64(2), summary.attrs["llm_calls"], "Motive's call and its ask-again; the run stops there")
	require.Equal(t, int64(2), summary.attrs["calls.M"])
	require.Equal(t, int64(1), summary.attrs["asked_again"])
	require.Equal(t, int64(0), summary.attrs["splits"])
	require.Empty(t, countersOf(summary), "no CVE was rated")
}

// A row without a vulnerability ID is a row, not a CVE.
func TestGenerator_RunSummaryCVECountSkipsRowsWithoutID(t *testing.T) {
	g := newGen(t, Opts{LLM: &fakeLLM{}, BatchSize: 10})

	logs := withCapturedLogs(t)
	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "pkg-a", Description: "d", BOMRef: "a"},
		{PkgName: "pkg-b", Description: "d", BOMRef: "b"},
		{VulnID: "CVE-2024-0001", PkgName: "pkg-c", Description: "d", BOMRef: "c"},
	}
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))

	summary := runSummary(t, logs)
	require.Equal(t, int64(3), summary.attrs["rows"])
	require.Equal(t, int64(2), summary.attrs["cves"])
}

// A split names both halves at debug level. The fake is deterministic, so the
// summary's counts are exact. Each question's call over the nine CVEs
// truncates, then its first five and its last four do: 7 calls, 3 splits.
// Motive's first answer leaves CVE-2024-0100 out, asked again once: 8 calls.
func TestGenerator_LogsSplitAndSummaryCounts(t *testing.T) {
	m := &fakeLLM{
		fail: truncateAbove(3),
		skip: func(c fakeCall, id string) bool {
			return c.factor == contract.M && id == "CVE-2024-0100" && len(c.ids) > 1
		},
	}
	g := newGen(t, Opts{LLM: m, BatchSize: 10})

	logs := withCapturedLogs(t)
	vulns := testVulns(10)
	vulns[1].VulnID, vulns[1].BOMRef = "CVE-2024-0100", "x1"
	vulns[7].VulnID, vulns[7].BOMRef = "CVE-2024-0100", "x2"
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))

	splits := logs.find(slog.LevelDebug, "splitting truncated call")
	for _, r := range splits {
		require.NotEmpty(t, r.attrs["first_half"], "the split must name the CVEs each half keeps")
		require.NotEmpty(t, r.attrs["second_half"], "the split must name the CVEs each half keeps")
	}
	require.Len(t, splits, 3*len(questionsUndeclared))

	summary := runSummary(t, logs)
	require.Equal(t, int64(10), summary.attrs["rows"])
	require.Equal(t, int64(9), summary.attrs["cves"])
	require.Equal(t, int64(8), summary.attrs["calls.M"])
	require.Equal(t, int64(7), summary.attrs["calls.O"])
	require.Equal(t, int64(8+7*(len(questionsUndeclared)-1)), summary.attrs["llm_calls"])
	require.Equal(t, int64(len(m.calls)), summary.attrs["llm_calls"])
	require.Equal(t, int64(1), summary.attrs["asked_again"])
	require.Equal(t, int64(3*len(questionsUndeclared)), summary.attrs["splits"])
	require.Equal(t, false, summary.attrs["failed"])
}
