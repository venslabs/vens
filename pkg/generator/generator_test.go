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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/internal/testutil"
	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// truncatingLLM returns llm.ErrTruncated whenever a batch carries more than
// maxPerCall vulnerabilities; smaller batches score normally. It records how it
// was called so a test can assert the batch was actually split.
type truncatingLLM struct {
	maxPerCall  int
	calls       int // successful (non-truncated) scoring calls
	truncations int
	maxSeen     int // largest batch it was asked to score, truncated or not
}

func (m *truncatingLLM) Generate(_ context.Context, req llm.Request) (string, error) {
	var in []struct {
		VulnID string `json:"vulnId"`
	}
	if err := json.Unmarshal([]byte(req.Human), &in); err != nil {
		return "", err
	}
	if len(in) > m.maxSeen {
		m.maxSeen = len(in)
	}
	if len(in) > m.maxPerCall {
		m.truncations++
		return "", fmt.Errorf("mock truncated: %w", llm.ErrTruncated)
	}
	m.calls++

	out := llmOutput{Results: make([]llmOutputEntry, 0, len(in))}
	for _, v := range in {
		out.Results = append(out.Results, llmOutputEntry{
			VulnID:             v.VulnID,
			ThreatAgentScore:   5,
			VulnerabilityScore: 5,
			TechnicalImpact:    5,
			BusinessImpact:     5,
			Reasoning:          "mock",
		})
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// An oversized batch that the provider truncates is split and retried until it
// fits; every CVE is scored exactly once (no gaps, no duplicate emission).
func TestGenerator_AutoSplitsOnTruncation(t *testing.T) {
	m := &truncatingLLM{maxPerCall: 3}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	// Collect into a slice (not a set) so a duplicate emission is visible.
	var emitted []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		emitted = append(emitted, group...)
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(10), h))

	counts := map[string]int{}
	for _, r := range emitted {
		counts[r.VulnID]++
	}
	require.Len(t, emitted, 10, "expected exactly 10 ratings")
	require.Len(t, counts, 10, "every CVE must be scored")
	for id, n := range counts {
		require.Equalf(t, 1, n, "CVE %s emitted %d times", id, n)
	}

	// The split path was actually exercised, not a lucky single call.
	require.Equal(t, 10, m.maxSeen, "the full 10-CVE batch must be attempted first")
	require.Greater(t, m.truncations, 0, "a truncation must trigger the split")
	require.Greater(t, m.calls, 1, "the batch must be scored across several sub-batches")
}

// When even a single CVE truncates, the run surfaces the error instead of
// looping forever.
func TestGenerator_TruncationOnSingleCVEFails(t *testing.T) {
	m := &truncatingLLM{maxPerCall: 0}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	err = g.GenerateRiskScore(context.Background(), testVulns(2), nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, llm.ErrTruncated))
}

func testVulns(n int) []Vulnerability {
	v := make([]Vulnerability, n)
	for i := range v {
		v[i] = Vulnerability{VulnID: fmt.Sprintf("CVE-2024-%04d", i), PkgName: "pkg", Title: "t"}
	}
	return v
}

// One evidence batch is recorded per LLM call, so BatchCount tracks the batching.
func TestGenerator_Attestor_OneBatchPerLLMCall(t *testing.T) {
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	g, err := New(Opts{LLM: testutil.NewMockLLM(), Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)
	g.SetAttestor(at)

	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(15), nil))
	require.Equal(t, 2, at.BatchCount()) // 15 vulns / batch size 10 -> 2 batches
}

type failingLLM struct{}

func (failingLLM) Generate(context.Context, llm.Request) (string, error) {
	return "", errors.New("llm down")
}

// A failed LLM call must not record evidence, or the attestation would carry
// empty/garbage batches.
func TestGenerator_Attestor_NoBatchOnLLMError(t *testing.T) {
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	g, err := New(Opts{LLM: failingLLM{}, Config: &riskconfig.Config{}})
	require.NoError(t, err)
	g.SetAttestor(at)

	require.Error(t, g.GenerateRiskScore(context.Background(), testVulns(3), nil))
	require.Equal(t, 0, at.BatchCount())
}

// droppingLLM leaves the ids in drop out of its answer, with no error and no
// mention. Unless always is set, it answers them the second time it is asked.
type droppingLLM struct {
	drop    map[string]bool
	always  bool
	asked   map[string]int
	batches []int // size of every batch it was asked to score, in order
}

func newDroppingLLM(always bool, drop ...string) *droppingLLM {
	m := &droppingLLM{always: always, drop: map[string]bool{}, asked: map[string]int{}}
	for _, id := range drop {
		m.drop[id] = true
	}
	return m
}

func (m *droppingLLM) Generate(_ context.Context, req llm.Request) (string, error) {
	var in []struct {
		VulnID string `json:"vulnId"`
	}
	if err := json.Unmarshal([]byte(req.Human), &in); err != nil {
		return "", err
	}
	m.batches = append(m.batches, len(in))

	// One ask per call, not per occurrence: a CVE can be listed several times.
	counted := map[string]bool{}
	for _, v := range in {
		if !counted[v.VulnID] {
			counted[v.VulnID] = true
			m.asked[v.VulnID]++
		}
	}

	out := llmOutput{Results: make([]llmOutputEntry, 0, len(in))}
	answered := map[string]bool{}
	for _, v := range in {
		if m.drop[v.VulnID] && (m.always || m.asked[v.VulnID] == 1) {
			continue
		}
		if answered[v.VulnID] {
			continue // a model answers each CVE once, however often it is listed
		}
		answered[v.VulnID] = true
		out.Results = append(out.Results, llmOutputEntry{
			VulnID:             v.VulnID,
			ThreatAgentScore:   5,
			VulnerabilityScore: 5,
			TechnicalImpact:    5,
			BusinessImpact:     5,
			Reasoning:          "mock",
		})
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// CVEs left out of a batch are asked for again on their own, each scored once.
func TestGenerator_AsksAgainForSkippedVulnerabilities(t *testing.T) {
	m := newDroppingLLM(false, "CVE-2024-0001", "CVE-2024-0003")
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	var emitted []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		emitted = append(emitted, group...)
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(5), h))

	counts := map[string]int{}
	for _, r := range emitted {
		counts[r.VulnID]++
	}
	require.Len(t, counts, 5, "every CVE must be scored")
	for id, n := range counts {
		require.Equalf(t, 1, n, "CVE %s emitted %d times", id, n)
	}
	require.Equal(t, []int{5, 2}, m.batches, "the second ask must carry only the two skipped CVEs")
}

// A CVE the model never returns fails the run and is named, instead of going
// missing at exit code 0. The check happens once, at the end of the run: the
// scored CVEs are still handed to the handler, but the failed run commits no
// VEX.
func TestGenerator_FailsWhenASkippedVulnerabilityNeverComesBack(t *testing.T) {
	m := newDroppingLLM(true, "CVE-2024-0002")
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	var emitted []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		emitted = append(emitted, group...)
		return nil
	}

	err = g.GenerateRiskScore(context.Background(), testVulns(4), h)
	require.Error(t, err)
	require.Contains(t, err.Error(), "CVE-2024-0002")
	require.Contains(t, err.Error(), "returned no score for 1")
	require.Contains(t, err.Error(), "1 of 4", "both sides count distinct CVEs")
	require.Len(t, emitted, 3, "scored CVEs are emitted; the failed run commits no VEX")
	require.Len(t, m.batches, 2, "asked once, asked again, then gives up")
}

// A CVE hitting several components is asked for once, and lands on all of them.
func TestGenerator_AsksOncePerSkippedVulnerability(t *testing.T) {
	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0001", PkgName: "pkg", BOMRef: "a"},
		{VulnID: "CVE-2024-0001", PkgName: "pkg", BOMRef: "b"},
		{VulnID: "CVE-2024-0002", PkgName: "pkg", BOMRef: "c"},
	}
	m := newDroppingLLM(false, "CVE-2024-0001")
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	var emitted []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		emitted = append(emitted, group...)
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, h))
	require.Equal(t, []int{3, 1}, m.batches, "the second ask must carry the CVE once, not once per component")

	got := make([]string, 0, len(emitted))
	for _, r := range emitted {
		got = append(got, r.VulnID+"@"+r.BOMRef)
	}
	require.ElementsMatch(t, []string{"CVE-2024-0001@a", "CVE-2024-0001@b", "CVE-2024-0002@c"}, got,
		"a CVE recovered on the second ask must land on every component it affects")
}

// The second ask is another LLM call, so its claims must cite its own bundle.
func TestGenerator_Attestor_RetryClaimsCiteTheRetryBatch(t *testing.T) {
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	m := newDroppingLLM(false, "CVE-2024-0001")
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)
	g.SetAttestor(at)

	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0001", PkgName: "pkg", BOMRef: "a"},
		{VulnID: "CVE-2024-0002", PkgName: "pkg", BOMRef: "b"},
	}
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))
	require.Equal(t, 2, at.BatchCount())

	var buf bytes.Buffer
	require.NoError(t, at.Write(&buf))

	var doc struct {
		Declarations struct {
			Claims []struct {
				Predicate string   `json:"predicate"`
				Evidence  []string `json:"evidence"`
			} `json:"claims"`
		} `json:"declarations"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	cited := map[string]string{}
	for _, c := range doc.Declarations.Claims {
		require.Len(t, c.Evidence, 1)
		switch {
		case strings.Contains(c.Predicate, "CVE-2024-0001"):
			cited["CVE-2024-0001"] = c.Evidence[0]
		case strings.Contains(c.Predicate, "CVE-2024-0002"):
			cited["CVE-2024-0002"] = c.Evidence[0]
		}
	}
	require.Equal(t, "evidence-batch-1", cited["CVE-2024-0002"], "answered on the first ask")
	require.Equal(t, "evidence-batch-2", cited["CVE-2024-0001"], "answered on the second")
}

// scriptedLLM answers per vulnerability per call, so tests can decline first
// and score later, decline forever, or return genuine low scores.
type scriptedLLM struct {
	calls  int
	answer func(call int, vulnID string) llmOutputEntry
}

func (m *scriptedLLM) Generate(_ context.Context, req llm.Request) (string, error) {
	var in []struct {
		VulnID string `json:"vulnId"`
	}
	if err := json.Unmarshal([]byte(req.Human), &in); err != nil {
		return "", err
	}
	m.calls++

	out := llmOutput{Results: make([]llmOutputEntry, 0, len(in))}
	for _, v := range in {
		e := m.answer(m.calls, v.VulnID)
		e.VulnID = v.VulnID
		out.Results = append(out.Results, e)
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// declinedEntry is the declined-assessment shape from
// https://github.com/venslabs/vens/issues/337: zeros everywhere except a token
// business impact, which still computes to a zero score.
func declinedEntry() llmOutputEntry {
	return llmOutputEntry{ThreatAgentScore: 0, VulnerabilityScore: 0, TechnicalImpact: 0, BusinessImpact: 1, Reasoning: "mock declined assessment"}
}

func scoredEntry() llmOutputEntry {
	return llmOutputEntry{ThreatAgentScore: 5, VulnerabilityScore: 5, TechnicalImpact: 5, BusinessImpact: 5, Reasoning: "mock scored"}
}

// A declined assessment is the same as no answer: it is asked for again, and a
// real score on the second ask lets the run succeed.
func TestGenerator_DeclinedAssessmentAskedAgainThenSucceeds(t *testing.T) {
	m := &scriptedLLM{answer: func(call int, _ string) llmOutputEntry {
		if call == 1 {
			return declinedEntry()
		}
		return scoredEntry()
	}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	var got []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		got = append(got, group...)
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(3), h))
	require.Equal(t, 2, m.calls, "declined CVEs must be asked for again, like skipped ones")
	require.Len(t, got, 3, "all vulnerabilities scored on the second ask")
}

// Still declined after asking again: the run fails instead of publishing
// severity info, naming the CVEs and the run total (#337).
func TestGenerator_DeclinedAssessmentTwiceFailsRun(t *testing.T) {
	m := &scriptedLLM{answer: func(_ int, _ string) llmOutputEntry { return declinedEntry() }}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	called := false
	h := func(group []outputhandler.VulnRating) error {
		called = true
		return nil
	}

	err = g.GenerateRiskScore(context.Background(), testVulns(3), h)
	require.Error(t, err)
	require.Contains(t, err.Error(), "declined to assess")
	require.Contains(t, err.Error(), "3 of 3", "denominator must be the run total, not the batch")
	require.Contains(t, err.Error(), "CVE-2024-0000")
	require.False(t, called, "no ratings must be emitted when the run fails")
	require.Equal(t, 2, m.calls, "one retry before failing")
}

// A zero reached through a non-zero axis is a genuine low score, not a
// declined assessment: CVE-2019-9192's [0 1 0 0] is zero via the impact axis.
func TestGenerator_GenuineZeroViaImpactAxisIsNotDeclined(t *testing.T) {
	m := &scriptedLLM{answer: func(_ int, _ string) llmOutputEntry {
		return llmOutputEntry{ThreatAgentScore: 0, VulnerabilityScore: 1, TechnicalImpact: 0, BusinessImpact: 0, Reasoning: "genuine low"}
	}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), nil))
	require.Equal(t, 1, m.calls, "genuine zeros are published, never re-asked")
}

// One batch's declined answer must not kill the run when an earlier batch
// already scored the same CVE.
func TestGenerator_DeclinedAfterEarlierBatchScoredDoesNotFailRun(t *testing.T) {
	m := &scriptedLLM{answer: func(call int, _ string) llmOutputEntry {
		// Batch 1 (call 1) scores CVE-2024-0000 fine; batch 2 declines it.
		if call == 1 {
			return scoredEntry()
		}
		return declinedEntry()
	}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 1})
	require.NoError(t, err)

	// Same CVE on two components straddling two batches.
	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "pkg-a", Title: "t"},
		{VulnID: "CVE-2024-0000", PkgName: "pkg-b", Title: "t"},
	}

	var got []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		got = append(got, group...)
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, h))
	require.Len(t, got, 2, "both components keep their rows: the second batch reuses the first score")
}

// A CVE in two batches reuses the first batch's score: the second batch's
// components keep their rows in the VEX instead of disappearing silently.
func TestGenerator_DupCVEReusesFirstScore(t *testing.T) {
	m := &scriptedLLM{answer: func(call int, _ string) llmOutputEntry {
		if call == 1 {
			return llmOutputEntry{ThreatAgentScore: 5, VulnerabilityScore: 5, TechnicalImpact: 5, BusinessImpact: 5, Reasoning: "first"}
		}
		return llmOutputEntry{ThreatAgentScore: 9, VulnerabilityScore: 9, TechnicalImpact: 9, BusinessImpact: 9, Reasoning: "second"}
	}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 1})
	require.NoError(t, err)

	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "openssl", Title: "t"},
		{VulnID: "CVE-2024-0000", PkgName: "libssl3", Title: "t"},
	}

	var got []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		got = append(got, group...)
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, h))
	require.Len(t, got, 2, "both components must keep their VEX rows")
	pkgs := map[string]bool{}
	for _, r := range got {
		pkgs[r.BOMRef] = true
	}
	require.True(t, pkgs[""], "both ratings are emitted") // BOMRef unset in unit vulns
	require.Equal(t, got[0].Rating.Score, got[1].Rating.Score, "second batch reuses the first score, not its own")
}

// Batch order must not decide the run: a batch that declines first must not
// fail the run before a later batch can score the same CVE.
func TestGenerator_DeclinedBatchFirstScoringBatchSecondSucceeds(t *testing.T) {
	m := &scriptedLLM{answer: func(call int, _ string) llmOutputEntry {
		// Batch 1 (call 1) declines; the retry (call 2) declines again; batch 2
		// (call 3) scores.
		if call <= 2 {
			return declinedEntry()
		}
		return scoredEntry()
	}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 1})
	require.NoError(t, err)

	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "pkg-a", Title: "t"},
		{VulnID: "CVE-2024-0000", PkgName: "pkg-b", Title: "t"},
	}

	var got []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		got = append(got, group...)
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, h),
		"the declining batch must not fail the run before the next batch scores the CVE")
	require.Len(t, got, 1, "the later batch's component is rated from its score")
}

// [0 0 1 1] and [0 0 0 1] with the same "not reachable" reason mean the same
// thing: token values on the impact axes don't make a decline genuine.
func TestGenerator_TokenImpactValuesAreDeclined(t *testing.T) {
	for _, shape := range [][4]float64{{0, 0, 1, 1}, {0, 0, 0, 1}, {0, 0, 0, 0}} {
		e := llmOutputEntry{ThreatAgentScore: shape[0], VulnerabilityScore: shape[1], TechnicalImpact: shape[2], BusinessImpact: shape[3]}
		require.True(t, declinedAssessment(e), "shape %v must count as declined", shape)
	}
	// A zero via a likelihood axis stays a genuine low score.
	require.False(t, declinedAssessment(llmOutputEntry{ThreatAgentScore: 0, VulnerabilityScore: 1, TechnicalImpact: 0, BusinessImpact: 0}))

	m := &scriptedLLM{answer: func(_ int, _ string) llmOutputEntry {
		return llmOutputEntry{ThreatAgentScore: 0, VulnerabilityScore: 0, TechnicalImpact: 1, BusinessImpact: 1, Reasoning: "not reachable here"}
	}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	err = g.GenerateRiskScore(context.Background(), testVulns(2), nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "declined to assess")
}

// When a run has both declined and unanswered CVEs, the error lists both,
// and both sides of the count are distinct CVEs — never package rows.
func TestGenerator_ErrorListsDeclinedAndMissingWithCVECounts(t *testing.T) {
	g, err := New(Opts{LLM: &declineAndDropLLM{}, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	// One declined CVE on two components (two rows), one scored CVE, one
	// unanswered CVE: 4 rows, 3 distinct CVEs.
	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "pkg-a", Title: "t"},
		{VulnID: "CVE-2024-0000", PkgName: "pkg-b", Title: "t"},
		{VulnID: "CVE-2024-0001", PkgName: "pkg-c", Title: "t"},
		{VulnID: "CVE-2024-0002", PkgName: "pkg-d", Title: "t"},
	}

	err = g.GenerateRiskScore(context.Background(), vulns, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "CVE-2024-0000", "declined CVE must be listed")
	require.Contains(t, err.Error(), "CVE-2024-0002", "unanswered CVE must be listed")
	require.Contains(t, err.Error(), "declined to assess 1")
	require.Contains(t, err.Error(), "returned no score for 1")
	require.Contains(t, err.Error(), "2 of 3", "2 failed of 3 distinct CVEs, not 4 rows")
}

// declineAndDropLLM declines CVE-2024-0000 and never answers CVE-2024-0002,
// scoring everything else.
type declineAndDropLLM struct{}

func (declineAndDropLLM) Generate(_ context.Context, req llm.Request) (string, error) {
	var in []struct {
		VulnID string `json:"vulnId"`
	}
	if err := json.Unmarshal([]byte(req.Human), &in); err != nil {
		return "", err
	}
	out := llmOutput{Results: make([]llmOutputEntry, 0, len(in))}
	for _, v := range in {
		var e llmOutputEntry
		switch v.VulnID {
		case "CVE-2024-0000":
			e = declinedEntry()
		case "CVE-2024-0002":
			continue // never answered
		default:
			e = scoredEntry()
		}
		e.VulnID = v.VulnID
		out.Results = append(out.Results, e)
	}
	b, err := json.Marshal(out)
	return string(b), err
}
