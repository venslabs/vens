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
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/internal/testutil"
	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// A call the provider truncates is split in half and each half asked, until
// each fits; every CVE is rated exactly once.
func TestGenerator_AutoSplitsOnTruncation(t *testing.T) {
	m := &fakeLLM{fail: truncateAbove(3)}
	g := newGen(t, Opts{LLM: m, BatchSize: 10})

	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(10), collect(&emitted)))

	counts := map[string]int{}
	for _, r := range emitted {
		counts[r.VulnID]++
	}
	require.Len(t, emitted, 10)
	require.Len(t, counts, 10, "every CVE must be rated")
	// Each question: the 10, then 5 (truncated) as 3 and 2, twice.
	for _, f := range questionsUndeclared {
		assert.Equal(t, []int{10, 5, 3, 2, 5, 3, 2}, sizes(m.of(contract.Factor(f))), "question %s", f)
	}
}

// When even a single CVE truncates, the run surfaces the error instead of
// looping forever.
func TestGenerator_TruncationOnSingleCVEFails(t *testing.T) {
	g := newGen(t, Opts{LLM: &fakeLLM{fail: truncateAbove(0)}, BatchSize: 10})
	err := g.GenerateRiskScore(context.Background(), testVulns(2), nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, llm.ErrTruncated))
}

// A CVE never answered stops the run inside a split half of the second batch,
// before any other question of that batch is asked.
func TestGenerator_FailsFastInSplitOfLaterBatch(t *testing.T) {
	m := &fakeLLM{
		fail: truncateAbove(2),
		skip: func(_ fakeCall, id string) bool { return id == "CVE-2024-0005" },
	}
	g := newGen(t, Opts{LLM: m, BatchSize: 4})

	err := g.GenerateRiskScore(context.Background(), testVulns(8), nil)
	require.EqualError(t, err, "model returned no answer to Motive (M) for CVE-2024-0005 after asking again; stopping the run")
	assert.Equal(t, []int{4, 2, 2, 4, 2, 2, 1}, sizes(m.of(contract.M)), "batch 1 in halves, batch 2 in halves and the ask-again")
	assert.Equal(t, []int{4, 2, 2}, sizes(m.of(contract.O)), "batch 2 never gets to Opportunity")
	last := m.calls[len(m.calls)-1]
	assert.Equal(t, []string{"CVE-2024-0005"}, last.ids)
}

// One evidence entry is recorded per call that returned.
func TestGenerator_Attestor_OneEvidencePerCall(t *testing.T) {
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	m := &fakeLLM{}
	g := newGen(t, Opts{LLM: m, BatchSize: 10})
	g.SetAttestor(at)

	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(15), nil))
	require.Len(t, m.calls, 20, "two batches, ten questions each")
	require.Equal(t, 20, at.BatchCount())
}

type failingLLM struct{}

func (failingLLM) Generate(context.Context, llm.Request) (string, error) {
	return "", errors.New("llm down")
}

// A failed LLM call must not record evidence, or the attestation would carry
// empty/garbage batches.
func TestGenerator_Attestor_NoEvidenceOnLLMError(t *testing.T) {
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	g := newGen(t, Opts{LLM: failingLLM{}})
	g.SetAttestor(at)

	err := g.GenerateRiskScore(context.Background(), testVulns(3), nil)
	require.ErrorContains(t, err, "LLM evaluation failed: llm down")
	require.Equal(t, 0, at.BatchCount())
}

// CVEs a reply leaves out are asked again together, once, and each is rated
// once.
func TestGenerator_AsksAgainForSkippedVulnerabilities(t *testing.T) {
	m := &fakeLLM{skip: func(c fakeCall, id string) bool {
		return c.n == 1 && (id == "CVE-2024-0001" || id == "CVE-2024-0003")
	}}
	g := newGen(t, Opts{LLM: m, BatchSize: 10})

	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(5), collect(&emitted)))
	require.Len(t, byID(emitted), 5)
	require.Len(t, emitted, 5, "each CVE rated once")
	require.Equal(t, []int{5, 2}, sizes(m.of(contract.M)), "the ask-again carries only the two skipped CVEs")
	require.Equal(t, []string{"CVE-2024-0001", "CVE-2024-0003"}, m.calls[1].ids)
}

// A CVE the model never answers fails the run, naming it and the question,
// instead of going missing at exit code 0. No other batch holds the CVE, so
// the run stops right after the ask-again, before rating anything.
func TestGenerator_FailsWhenASkippedVulnerabilityNeverComesBack(t *testing.T) {
	m := &fakeLLM{skip: func(c fakeCall, id string) bool { return c.factor == contract.O && id == "CVE-2024-0002" }}
	g := newGen(t, Opts{LLM: m, BatchSize: 10})

	var emitted []outputhandler.VulnRating
	err := g.GenerateRiskScore(context.Background(), testVulns(4), collect(&emitted))
	require.EqualError(t, err, "model returned no answer to Opportunity (O) for CVE-2024-0002 after asking again; stopping the run")
	require.Empty(t, emitted, "the batch fails before it is rated; the failed run commits no VEX")
	require.Equal(t, []string{"M", "O", "O"}, m.log(), "asked once, asked again, then gives up")
	require.Equal(t, []int{4, 1}, sizes(m.of(contract.O)))
}

// An unanswered CVE stops the run before the next batches are paid for.
func TestGenerator_FailsFastWithoutScoringLaterBatches(t *testing.T) {
	m := &fakeLLM{skip: func(_ fakeCall, id string) bool { return id == "CVE-2024-0000" }}
	g := newGen(t, Opts{LLM: m, BatchSize: 2})

	err := g.GenerateRiskScore(context.Background(), testVulns(4), nil)
	require.EqualError(t, err, "model returned no answer to Motive (M) for CVE-2024-0000 after asking again; stopping the run")
	require.Equal(t, []int{2, 1}, sizes(m.calls), "the second batch must never be asked about")
}

// A CVE hitting several components is one entry of each call, asked again
// once, and lands on every component.
func TestGenerator_AsksOncePerSkippedVulnerability(t *testing.T) {
	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0001", PkgName: "pkg-a", Description: "d", BOMRef: "a"},
		{VulnID: "CVE-2024-0001", PkgName: "pkg-b", Description: "d", BOMRef: "b"},
		{VulnID: "CVE-2024-0002", PkgName: "pkg-c", Description: "d", BOMRef: "c"},
	}
	m := &fakeLLM{skip: func(c fakeCall, id string) bool { return c.n == 1 && id == "CVE-2024-0001" }}
	g := newGen(t, Opts{LLM: m, BatchSize: 10})

	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, collect(&emitted)))
	require.Equal(t, []int{2, 1}, sizes(m.of(contract.M)), "each ask carries the CVE once, not once per component")

	got := make([]string, 0, len(emitted))
	for _, r := range emitted {
		got = append(got, r.VulnID+"@"+r.BOMRef)
	}
	require.Equal(t, []string{"CVE-2024-0001@a", "CVE-2024-0001@b", "CVE-2024-0002@c"}, got,
		"a CVE recovered on the ask-again lands on every component it affects, in scanner order")
}

// A claim cites every call that answered for its CVE: the ask-again that
// recovered it, not the call that left it out.
func TestGenerator_Attestor_ClaimsCiteTheCallsThatAnswered(t *testing.T) {
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	m := &fakeLLM{skip: func(c fakeCall, id string) bool { return c.n == 1 && id == "CVE-2024-0001" }}
	g := newGen(t, Opts{LLM: m, BatchSize: 10})
	g.SetAttestor(at)

	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0001", PkgName: "pkg", Description: "d", BOMRef: "a"},
		{VulnID: "CVE-2024-0002", PkgName: "pkg", Description: "d", BOMRef: "b"},
	}
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))
	require.Equal(t, len(m.calls), at.BatchCount())

	// Call 1 is Motive's, call 2 its ask-again, then one call per question.
	others := []string{}
	for n := 3; n <= len(m.calls); n++ {
		others = append(others, fmt.Sprintf("evidence-batch-%d", n))
	}
	cited := map[string][]string{}
	for _, c := range claims(t, at) {
		cited[c.Target] = c.Evidence
	}
	assert.Equal(t, append([]string{"evidence-batch-2"}, others...), cited["a"], "answered on the ask-again")
	assert.Equal(t, append([]string{"evidence-batch-1"}, others...), cited["b"], "answered on the first ask")
}

// An answer for a CVE the call did not ask about is ignored: the CVE keeps
// the answer to its own question when its batch comes.
func TestGenerator_IgnoresAnswersForCVEsNotInThePrompt(t *testing.T) {
	m := &fakeLLM{
		answer: func(c fakeCall, _ string) any {
			if c.factor == contract.M {
				return "high_reward"
			}
			return nil
		},
		extra: func(c fakeCall) []map[string]any {
			if c.factor != contract.M || c.n != 1 {
				return nil
			}
			return []map[string]any{{"vulnId": "CVE-2024-0001", "reasoning": "stale", "answer": "low_or_no_reward"}}
		},
	}
	g := newGen(t, Opts{LLM: m, BatchSize: 1})

	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), collect(&emitted)))
	require.Len(t, m.of(contract.M), 2, "the volunteered CVE is still asked in its own batch")
	require.Equal(t, 9, vectorLevel(t, byID(emitted)["CVE-2024-0001"].Rating.Vector, "M"),
		"CVE-2024-0001 carries the answer to its own question, not the volunteered one")
}

// The ask-again drops answers for CVEs it did not ask about too.
func TestGenerator_IgnoresAnswersForCVEsNotAskedOnRetry(t *testing.T) {
	m := &fakeLLM{
		answer: func(c fakeCall, _ string) any {
			if c.factor == contract.M {
				return "high_reward"
			}
			return nil
		},
		skip: func(c fakeCall, _ string) bool { return c.n == 1 },
		extra: func(c fakeCall) []map[string]any {
			if c.n != 2 {
				return nil
			}
			return []map[string]any{{"vulnId": "CVE-2024-0001", "reasoning": "not asked", "answer": "low_or_no_reward"}}
		},
	}
	g := newGen(t, Opts{LLM: m, BatchSize: 1})

	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), collect(&emitted)))
	require.Equal(t, 9, vectorLevel(t, byID(emitted)["CVE-2024-0001"].Rating.Vector, "M"),
		"CVE-2024-0001 carries the answer to its own question, not the one volunteered on the ask-again")
}

// A reply answering a CVE twice keeps the first answer.
func TestGenerator_AnswerGivenTwiceKeepsTheFirst(t *testing.T) {
	m := &fakeLLM{
		answer: func(c fakeCall, _ string) any {
			if c.factor == contract.M {
				return "low_or_no_reward"
			}
			return nil
		},
		extra: func(c fakeCall) []map[string]any {
			if c.factor != contract.M {
				return nil
			}
			return []map[string]any{{"vulnId": "CVE-2024-0000", "reasoning": "again", "answer": "high_reward"}}
		},
	}
	g := newGen(t, Opts{LLM: m})

	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(1), collect(&emitted)))
	require.Equal(t, 1, vectorLevel(t, emitted[0].Rating.Vector, "M"))
}

// --llm-temperature must reach every request exactly as passed, and stay
// absent (nil) when the flag wasn't given.
func TestGenerator_TemperatureReachesRequest(t *testing.T) {
	zero, warm := 0.0, 0.7
	for _, tt := range []struct {
		name string
		temp *float64
	}{
		{"explicit temperature is forwarded", &warm},
		{"explicit zero is forwarded, not confused with unset", &zero},
		{"nil when the flag was not passed", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := &fakeLLM{}
			g := newGen(t, Opts{LLM: m, Temperature: tt.temp})
			require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), nil))
			require.NotEmpty(t, m.calls)
			for _, c := range m.calls {
				require.Equal(t, tt.temp, c.req.Temperature)
			}
		})
	}
}

// Every published rating recomputes from its own vector: likelihood and the
// two impacts are the averages of their levels, the impact the larger, the
// severity OWASP's matrix cell, never info, and the score likelihood ×
// impact.
func TestGenerator_ScoreRecomputesFromItsVector(t *testing.T) {
	cfg := testConfig()
	cfg.Context.ComplianceRequirements = []string{"PCI-DSS"}
	cfg.Context.Detection = &riskconfig.DetectionCoverage{Network: "logged", Host: "not_logged", Application: "active_in_application"}
	traceability, subjects := "per_request", "thousands"
	cfg.Context.Traceability, cfg.Context.DataSubjects = &traceability, &subjects
	vulns := testVulns(40)
	for i := range vulns {
		vulns[i].CVSS = []cvss.Vector{v31("nvd", fmt.Sprintf("AV:N/AC:L/PR:N/UI:N/S:U/C:%s/I:%s/A:%s",
			[]string{"N", "L", "H"}[i%3], []string{"N", "H"}[i%2], []string{"H", "N", "L", "N"}[i%4]))}
	}
	g := newGen(t, Opts{LLM: testutil.NewMockLLM(), Config: cfg})

	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, collect(&emitted)))
	require.Len(t, emitted, 40)
	severities := map[string]bool{}
	for _, r := range emitted {
		severity, score := recompute(t, r.Rating.Vector)
		require.Equal(t, severity, string(r.Rating.Severity), r.Rating.Vector)
		require.Equal(t, score, *r.Rating.Score, r.Rating.Vector)
		require.NotEqual(t, "info", severity)
		severities[severity] = true
	}
	require.Greater(t, len(severities), 1, "the mock's answers rate CVEs apart")
}

// recompute rates a written vector by OWASP's method, impact the larger of
// the technical and business impacts.
func recompute(t *testing.T, vector string) (string, float64) {
	t.Helper()
	parts := strings.Split(vector, "/")
	require.Len(t, parts, 16)
	var likelihood, technical, business float64
	for i, part := range parts {
		_, digit, _ := strings.Cut(part, ":")
		level, err := strconv.Atoi(digit)
		require.NoError(t, err)
		switch {
		case i < 8:
			likelihood += float64(level)
		case i < 12:
			technical += float64(level)
		default:
			business += float64(level)
		}
	}
	likelihood, impact := likelihood/8, max(technical, business)/4
	band := func(x float64) int {
		switch {
		case x < 3:
			return 0
		case x < 6:
			return 1
		}
		return 2
	}
	matrix := [3][3]string{{"info", "low", "medium"}, {"low", "medium", "high"}, {"medium", "high", "critical"}}
	return matrix[band(likelihood)][band(impact)], likelihood * impact
}

// A multi-component CVE keeps one row and one attestation claim per
// component, in scanner order: it is one entry of each call, which lists
// every package.
func TestGenerator_MultiComponentCVEOneRowAndClaimPerComponent(t *testing.T) {
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	m := &fakeLLM{}
	g := newGen(t, Opts{LLM: m, BatchSize: 2})
	g.SetAttestor(at)

	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "pkg-a", Description: "d", BOMRef: "a"},
		{VulnID: "CVE-2024-0000", PkgName: "pkg-b", Description: "d", BOMRef: "b"},
		{VulnID: "CVE-2024-0000", PkgName: "pkg-c", Description: "d", BOMRef: "c"},
	}
	var rows []string
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, func(group []outputhandler.VulnRating) error {
		for _, r := range group {
			rows = append(rows, r.BOMRef)
		}
		return nil
	}))
	require.Equal(t, len(questionsUndeclared), len(m.calls), "the CVE is grouped before batching: one call per question")
	require.Equal(t, []string{"a", "b", "c"}, rows)

	var targets []string
	for _, c := range claims(t, at) {
		targets = append(targets, c.Target)
	}
	require.Equal(t, []string{"a", "b", "c"}, targets)
}

// Rows are grouped by CVE before batching, so a multi-component CVE is one
// entry of each call however the rows would have been batched, and the entry
// lists every affected package with its versions, in scanner order.
func TestGenerator_MultiComponentCVEAskedOnceRegardlessOfBatchSize(t *testing.T) {
	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "pkg-b", InstalledVersion: "2.0", FixedVersion: "2.1", Description: "d", BOMRef: "b"},
		{VulnID: "CVE-2024-1111", PkgName: "other", InstalledVersion: "1.0", Description: "d", BOMRef: "other"},
		{VulnID: "CVE-2024-0000", PkgName: "pkg-a", InstalledVersion: "1.0", FixedVersion: "1.2", Description: "d", BOMRef: "a"},
	}
	for batchSize, want := range map[int][]int{1: {1, 1}, 10: {2}} {
		m := &fakeLLM{}
		g := newGen(t, Opts{LLM: m, BatchSize: batchSize})
		var emitted []outputhandler.VulnRating
		require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, collect(&emitted)))
		require.Equal(t, want, sizes(m.of(contract.M)), "batch size %d", batchSize)
		require.Len(t, emitted, 3)

		entry := requestEntries(t, m.of(contract.M)[0].req.Human)[0]
		require.Equal(t, "CVE-2024-0000", entry["vulnId"])
		require.Equal(t, []any{
			map[string]any{"name": "pkg-b", "installedVersion": "2.0", "fixedVersion": "2.1"},
			map[string]any{"name": "pkg-a", "installedVersion": "1.0", "fixedVersion": "1.2"},
		}, entry["packages"], "batch size %d", batchSize)
	}
}

// The fail-fast error names each unanswered CVE once, sorted, never once per
// row.
func TestGenerator_ErrorNamesEachUnansweredCVEOnce(t *testing.T) {
	m := &fakeLLM{skip: func(_ fakeCall, id string) bool { return id == "CVE-2024-0000" || id == "CVE-2024-0002" }}
	g := newGen(t, Opts{LLM: m, BatchSize: 10})

	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0002", PkgName: "pkg-a", Description: "d"},
		{VulnID: "CVE-2024-0000", PkgName: "pkg-b", Description: "d"},
		{VulnID: "CVE-2024-0001", PkgName: "pkg-c", Description: "d"},
		{VulnID: "CVE-2024-0000", PkgName: "pkg-d", Description: "d"},
	}
	err := g.GenerateRiskScore(context.Background(), vulns, nil)
	require.EqualError(t, err, "model returned no answer to Motive (M) for CVE-2024-0000, CVE-2024-0002 after asking again; stopping the run")
}

// A claim's reasoning joins each answer's sentence as "factor (answer):
// sentence", in call order, the adjustment's last; its predicate keeps the
// score and the severity.
func TestGenerator_ClaimReasoningJoinsEachAnswer(t *testing.T) {
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	m := &fakeLLM{answer: func(c fakeCall, _ string) any {
		if c.factor == contract.ID {
			return []string{"network", "host"}
		}
		return nil
	}}
	cfg := testConfig()
	cfg.Context.Detection = &riskconfig.DetectionCoverage{Network: "logged", Host: "logged_and_reviewed", Application: "not_logged"}
	g := newGen(t, Opts{LLM: m, Config: cfg})
	g.SetAttestor(at)

	vulns := testVulns(1)
	vulns[0].Description = "This issue is disputed by the vendor. It needs a local account."
	vulns[0].Flags = Flags{MaintainerDisputed: true}
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, collect(&emitted)))

	got := claims(t, at)
	require.Len(t, got, 1)
	lines := strings.Split(got[0].Reasoning, "\n")
	require.Equal(t, []string{
		"M (low_or_no_reward): because of CVE-2024-0000",
		"O (no_access_or_resources_required): because of CVE-2024-0000",
		"EE (theoretical): because of CVE-2024-0000",
		"ID (network, host): because of CVE-2024-0000",
		"LC (minimal): because of CVE-2024-0000",
		"LI (minimal_slightly_corrupt): because of CVE-2024-0000",
		"LAV (minimal_secondary_interrupted): because of CVE-2024-0000",
		"LAC (identified): because of CVE-2024-0000",
		"FD (less_than_cost_to_fix): because of CVE-2024-0000",
		"RD (minimal_damage): because of CVE-2024-0000",
		"PV (none): because of CVE-2024-0000",
		"adjustment (opportunity: keep, confidentiality: affected, integrity: affected, availability: affected): the evidence",
	}, lines)
	score := *emitted[0].Rating.Score
	assert.Equal(t, fmt.Sprintf("CVE-2024-0000 on pkg  assessed at OWASP risk %.2f (%s)", score, emitted[0].Rating.Severity), got[0].Predicate)
	assert.Len(t, got[0].Evidence, len(m.calls), "every call answered for the one CVE")
}

// A reasoning written over several lines, or with runs of spaces, takes one
// line of the claim's reasoning, the adjustment's too.
func TestGenerator_ClaimReasoningKeepsOneLinePerAnswer(t *testing.T) {
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	m := &fakeLLM{
		edit: func(c fakeCall, entry map[string]any) {
			if c.factor == contract.M {
				entry["reasoning"] = "It holds the keys.\nAn attacker wants them.\u2028\t Enough."
			}
		},
		adjust: func(fakeCall) map[string]any {
			return map[string]any{"reasoning": "\nThe dispute\r\nstands.  ", "opportunity": "keep",
				"confidentiality": "affected", "integrity": "affected", "availability": "affected"}
		},
	}
	g := newGen(t, Opts{LLM: m})
	g.SetAttestor(at)
	require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{disputedRow(testVulns(1)[0])}, nil))

	lines := strings.Split(claims(t, at)[0].Reasoning, "\n")
	require.Len(t, lines, len(questionsUndeclared)+1)
	assert.Equal(t, "M (low_or_no_reward): It holds the keys. An attacker wants them. Enough.", lines[0])
	assert.Equal(t, "adjustment (opportunity: keep, confidentiality: affected, integrity: affected, availability: affected): The dispute stands.", lines[len(lines)-1])
}
