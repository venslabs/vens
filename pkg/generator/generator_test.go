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
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/internal/testutil"
	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// truncatingLLM returns llm.ErrTruncated whenever a batch carries more than
// maxPerCall vulnerabilities; smaller batches score normally, except that a CVE
// in skip is left out of its first skip[id] answers. It records how it was
// called so a test can assert the batch was actually split.
type truncatingLLM struct {
	maxPerCall  int
	skip        map[string]int
	asked       map[string]int
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
	if m.asked == nil {
		m.asked = map[string]int{}
	}
	counted := map[string]bool{} // one ask per call, however often a CVE is listed
	for _, v := range in {
		if !counted[v.VulnID] {
			counted[v.VulnID] = true
			m.asked[v.VulnID]++
		}
	}

	out := llmOutput{Results: make([]llmOutputEntry, 0, len(in))}
	for _, v := range in {
		if m.asked[v.VulnID] <= m.skip[v.VulnID] {
			continue
		}
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

// A CVE that can't be scored still stops the run inside a split half of the
// second batch: the half's end is counted from the start of the run.
func TestGenerator_FailsFastInSplitOfLaterBatch(t *testing.T) {
	m := &truncatingLLM{maxPerCall: 2, skip: map[string]int{"CVE-2024-0005": 99}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 4})
	require.NoError(t, err)

	err = g.GenerateRiskScore(context.Background(), testVulns(8), nil)
	require.EqualError(t, err, "model returned no score for CVE-2024-0005 after asking again; stopping the run")
	require.Equal(t, 4, m.calls, "rows 0-3 in two halves, rows 4-5 and the retry; rows 6-7 never asked")
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
// missing at exit code 0. Grouping puts the CVE in exactly one batch, so the
// run fails right after the ask-again, before emitting anything: the failed
// run commits no VEX.
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
	require.EqualError(t, err, "model returned no score for CVE-2024-0002 after asking again; stopping the run")
	require.Empty(t, emitted, "the batch fails before emitting; the failed run commits no VEX")
	require.Equal(t, []int{4, 1}, m.batches, "asked once, asked again, then gives up")
}

// An unanswered CVE with no later row stops the run before the next batches
// are paid for.
func TestGenerator_FailsFastWithoutScoringLaterBatches(t *testing.T) {
	m := newDroppingLLM(true, "CVE-2024-0000")
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 2})
	require.NoError(t, err)

	err = g.GenerateRiskScore(context.Background(), testVulns(4), nil)
	require.EqualError(t, err, "model returned no score for CVE-2024-0000 after asking again; stopping the run")
	require.Equal(t, []int{2, 1}, m.batches, "the second batch must never be asked about")
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
	require.Equal(t, []int{2, 1}, m.batches, "each ask must carry the CVE once, not once per component")

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

// scriptedLLM answers per vulnerability per call, so a test can change the
// answer from one call to the next or leave a CVE out of it entirely (skip).
type scriptedLLM struct {
	calls  int
	answer func(call int, vulnID string) llmOutputEntry
	skip   func(call int, vulnID string) bool
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
		if m.skip != nil && m.skip(m.calls, v.VulnID) {
			continue
		}
		e := m.answer(m.calls, v.VulnID)
		e.VulnID = v.VulnID
		out.Results = append(out.Results, e)
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// captureHandler records slog records so tests can assert on levels and attrs.
type captureHandler struct {
	mu      sync.Mutex
	records []capturedRecord
}

type capturedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	rec := capturedRecord{level: r.Level, msg: r.Message, attrs: map[string]any{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.Any()
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, rec)
	h.mu.Unlock()
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// withCapturedLogs swaps in a capturing slog handler for the test.
func withCapturedLogs(t *testing.T) *captureHandler {
	t.Helper()
	h := &captureHandler{}
	old := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(old) })
	return h
}

// zeroLikelihoodEntry is the shape from
// https://github.com/venslabs/vens/issues/337: zero likelihood and a token
// business impact, which computes to a zero score.
func zeroLikelihoodEntry() llmOutputEntry {
	return llmOutputEntry{ThreatAgentScore: 0, VulnerabilityScore: 0, TechnicalImpact: 0, BusinessImpact: 1, Reasoning: "mock not reachable here"}
}

func scoredEntry() llmOutputEntry {
	return llmOutputEntry{ThreatAgentScore: 5, VulnerabilityScore: 5, TechnicalImpact: 5, BusinessImpact: 5, Reasoning: "mock scored"}
}

// A zero-likelihood answer ("not reachable here") is a real verdict, not a
// refusal: it is published as-is and the run succeeds.
func TestGenerator_ZeroLikelihoodPublishedAsIs(t *testing.T) {
	m := &scriptedLLM{answer: func(_ int, _ string) llmOutputEntry { return zeroLikelihoodEntry() }}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	var got []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		got = append(got, group...)
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(3), h))
	require.Len(t, got, 3, "every vulnerability keeps its VEX row")
	for _, r := range got {
		require.NotNil(t, r.Rating.Score)
		require.Equal(t, 0.0, *r.Rating.Score, "zero likelihood computes to a zero score")
		require.Equal(t, "info", string(r.Rating.Severity))
	}
}

// Every zero-likelihood answer lands as info, so its reasoning is logged at
// WARN in place of the INFO line, whatever impact the model gave.
func TestGenerator_ZeroLikelihoodLogsReasoningAtWarn(t *testing.T) {
	for _, shape := range [][4]float64{{0, 0, 0, 1}, {0, 0, 8, 8}} {
		t.Run(fmt.Sprint(shape), func(t *testing.T) {
			m := &scriptedLLM{answer: func(_ int, _ string) llmOutputEntry {
				return llmOutputEntry{ThreatAgentScore: shape[0], VulnerabilityScore: shape[1],
					TechnicalImpact: shape[2], BusinessImpact: shape[3], Reasoning: "not reachable here"}
			}}
			g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
			require.NoError(t, err)

			logs := withCapturedLogs(t)

			var got []outputhandler.VulnRating
			h := func(group []outputhandler.VulnRating) error {
				got = append(got, group...)
				return nil
			}
			require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(1), h))
			require.Len(t, got, 1)
			require.Equal(t, 0.0, *got[0].Rating.Score)
			require.Equal(t, "info", string(got[0].Rating.Severity))

			warns, infos := 0, 0
			for _, r := range logs.records {
				switch {
				case r.level == slog.LevelWarn && r.attrs["vuln"] == "CVE-2024-0000":
					warns++
					require.Equal(t, "not reachable here", r.attrs["reasoning"], "the model's reasoning must be logged at WARN")
				case r.msg == "Scored vulnerability":
					infos++
				}
			}
			require.Equal(t, 1, warns)
			require.Zero(t, infos, "the WARN replaces the INFO line")
		})
	}
}

// A zero-likelihood verdict is logged once, by the batch that publishes it.
// With grouping, a CVE's components are one group in one batch, so there is
// exactly one ask and one WARN, however many components the CVE hits.
func TestGenerator_ZeroLikelihoodLogsOnceAcrossBatches(t *testing.T) {
	m := &scriptedLLM{answer: func(_ int, _ string) llmOutputEntry { return zeroLikelihoodEntry() }}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 1})
	require.NoError(t, err)

	logs := withCapturedLogs(t)

	// Same CVE on two components: grouped before batching, asked about once.
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
	require.Equal(t, 1, m.calls, "one group, one batch, one ask")
	require.Len(t, got, 2, "both components keep their VEX rows")

	verdicts := 0
	for _, r := range logs.records {
		if r.level == slog.LevelWarn && strings.Contains(r.msg, "not reachable here") {
			verdicts++
		}
	}
	require.Equal(t, 1, verdicts, "the verdict must be logged once, not again in the batch that reuses the answer")
}

// leakingLLM answers every CVE in the prompt, but its first call smuggles in
// an extra entry for a CVE it was never asked about — the way a model answers
// from another batch's context.
type leakingLLM struct {
	calls int
}

func (m *leakingLLM) Generate(_ context.Context, req llm.Request) (string, error) {
	var in []struct {
		VulnID string `json:"vulnId"`
	}
	if err := json.Unmarshal([]byte(req.Human), &in); err != nil {
		return "", err
	}
	m.calls++

	out := llmOutput{}
	for _, v := range in {
		out.Results = append(out.Results, llmOutputEntry{
			VulnID:             v.VulnID,
			ThreatAgentScore:   5,
			VulnerabilityScore: 5,
			TechnicalImpact:    5,
			BusinessImpact:     5,
			Reasoning:          "real answer",
		})
	}
	if m.calls == 1 {
		out.Results = append(out.Results, llmOutputEntry{
			VulnID:             "CVE-2024-0001",
			ThreatAgentScore:   5,
			VulnerabilityScore: 5,
			TechnicalImpact:    5,
			BusinessImpact:     1,
			Reasoning:          "leaked stale answer for a CVE that wasn't asked about",
		})
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// An answer for a CVE that wasn't in this call's prompt is ignored: the CVE
// is still asked about when its own batch arrives, instead of the later batch
// reusing the leaked entry (in a test, a critical CVE came out as info).
func TestGenerator_IgnoresAnswersForCVEsNotInThePrompt(t *testing.T) {
	m := &leakingLLM{}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 1})
	require.NoError(t, err)

	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "pkg-a", Title: "t"},
		{VulnID: "CVE-2024-0001", PkgName: "pkg-b", Title: "t"},
	}

	var got []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		got = append(got, group...)
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, h))
	require.Equal(t, 2, m.calls, "the leaked CVE must still be asked about in its own batch")
	require.Len(t, got, 2)

	for _, r := range got {
		if r.VulnID == "CVE-2024-0001" {
			require.NotNil(t, r.Rating.Score)
			// Fresh score: ((5+5)/2) * ((5+5)/2) = 25. The leaked entry would
			// have scored ((5+5)/2) * ((5+1)/2) = 15.
			require.Equal(t, 25.0, *r.Rating.Score,
				"CVE-2024-0001 must carry the score from its own ask, not the leaked entry")
		}
	}
}

// A zero reached with a non-zero likelihood is a genuine low score, logged
// like any other: CVE-2019-9192's [0 1 0 0] is zero via the impact axis.
func TestGenerator_GenuineZeroIsNotZeroLikelihood(t *testing.T) {
	m := &scriptedLLM{answer: func(_ int, _ string) llmOutputEntry {
		return llmOutputEntry{ThreatAgentScore: 0, VulnerabilityScore: 1, TechnicalImpact: 0, BusinessImpact: 0, Reasoning: "genuine low"}
	}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	logs := withCapturedLogs(t)
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), nil))
	infos := 0
	for _, r := range logs.records {
		require.False(t, r.level == slog.LevelWarn && strings.Contains(r.msg, "not reachable here"),
			"a genuine low score is not logged as a not-reachable verdict")
		if r.msg == "Scored vulnerability" {
			infos++
		}
	}
	require.Equal(t, 2, infos)
}

// A CVE in two batches is asked about once: the second batch leaves it out of
// its prompt and reuses the first score, so its component keeps its VEX row.
// A multi-component CVE keeps one row and one attestation claim per component,
// in scanner order, even when its rows would previously have spanned batches:
// the CVE is grouped before batching and asked about exactly once.
func TestGenerator_MultiComponentCVEOneRowAndClaimPerComponent(t *testing.T) {
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	m := &scriptedLLM{
		answer: func(_ int, _ string) llmOutputEntry { return scoredEntry() },
	}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 2})
	require.NoError(t, err)
	g.SetAttestor(at)

	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "pkg-a", Title: "t", BOMRef: "a"},
		{VulnID: "CVE-2024-0000", PkgName: "pkg-b", Title: "t", BOMRef: "b"},
		{VulnID: "CVE-2024-0000", PkgName: "pkg-c", Title: "t", BOMRef: "c"},
	}

	var rows []string
	h := func(group []outputhandler.VulnRating) error {
		for _, r := range group {
			rows = append(rows, r.BOMRef)
		}
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, h))
	require.Equal(t, 1, m.calls, "the CVE is grouped before batching: one call, one prompt entry")
	require.Equal(t, []string{"a", "b", "c"}, rows)

	var buf bytes.Buffer
	require.NoError(t, at.Write(&buf))
	var doc struct {
		Declarations struct {
			Claims []struct {
				Target string `json:"target"`
			} `json:"claims"`
		} `json:"declarations"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	var targets []string
	for _, c := range doc.Declarations.Claims {
		targets = append(targets, c.Target)
	}
	require.Equal(t, []string{"a", "b", "c"}, targets)
}

// promptEntry mirrors the JSON shape of one LLM prompt entry, so a test can
// assert what the model was shown for a CVE.
type promptEntry struct {
	VulnID   string `json:"vulnId"`
	Packages []struct {
		PkgName          string `json:"pkgName"`
		InstalledVersion string `json:"installedVersion"`
		FixedVersion     string `json:"fixedVersion"`
	} `json:"packages"`
}

// countingLLM records every prompt's entries, so a test can assert a
// multi-component CVE occupies exactly one prompt entry and that the entry
// carries every affected package.
type countingLLM struct {
	scriptedLLM
	sizes   []int
	prompts [][]promptEntry
}

func (m *countingLLM) Generate(ctx context.Context, req llm.Request) (string, error) {
	var in []promptEntry
	if err := json.Unmarshal([]byte(req.Human), &in); err != nil {
		return "", err
	}
	m.sizes = append(m.sizes, len(in))
	m.prompts = append(m.prompts, in)
	return m.scriptedLLM.Generate(ctx, req)
}

// Rows are grouped by CVE before batching, so a multi-component CVE is asked
// about exactly once however the rows would have been batched. The answers
// differ per call, so the published score proves the CVE was scored from its
// single prompt entry, not from first-answer-wins across scattered asks; the
// entry carries every affected package (name, version, fixed version each),
// in deterministic sorted order, not just the first row's package in scanner
// order.
func TestGenerator_MultiComponentCVEAskedOnceRegardlessOfBatchSize(t *testing.T) {
	first := llmOutputEntry{ThreatAgentScore: 5, VulnerabilityScore: 5, TechnicalImpact: 5, BusinessImpact: 5, Reasoning: "first"}
	second := llmOutputEntry{ThreatAgentScore: 9, VulnerabilityScore: 9, TechnicalImpact: 9, BusinessImpact: 9, Reasoning: "second"}

	run := func(batchSize int) ([]outputhandler.VulnRating, *countingLLM) {
		m := &countingLLM{scriptedLLM: scriptedLLM{
			answer: func(call int, _ string) llmOutputEntry {
				if call == 1 {
					return first
				}
				return second
			},
		}}
		g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: batchSize})
		require.NoError(t, err)

		vulns := []Vulnerability{
			{VulnID: "CVE-2024-0000", PkgName: "pkg-b", InstalledVersion: "2.0", FixedVersion: "2.1", Title: "t", BOMRef: "b"},
			{VulnID: "CVE-2024-1111", PkgName: "other", InstalledVersion: "1.0", Title: "t", BOMRef: "other"},
			{VulnID: "CVE-2024-0000", PkgName: "pkg-a", InstalledVersion: "1.0", FixedVersion: "1.2", Title: "t", BOMRef: "a"},
		}

		var got []outputhandler.VulnRating
		h := func(group []outputhandler.VulnRating) error {
			got = append(got, group...)
			return nil
		}
		require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, h))
		return got, m
	}

	got1, m1 := run(1)
	got10, m10 := run(10)

	// Two distinct CVEs: batch size 1 scores them in two calls, batch size 10
	// in one call, but CVE-2024-0000 is a single prompt entry either way.
	require.Equal(t, []int{1, 1}, m1.sizes)
	require.Equal(t, []int{2}, m10.sizes)

	// The single entry for CVE-2024-0000 carries every affected package with
	// its versions, in deterministic sorted order: the scanner order here is
	// pkg-b then pkg-a, so sorted order proves the prompt never depends on it.
	pkgsOf := func(prompts [][]promptEntry, vulnID string) [][3]string {
		for _, p := range prompts {
			for _, e := range p {
				if e.VulnID == vulnID {
					var out [][3]string
					for _, pkg := range e.Packages {
						out = append(out, [3]string{pkg.PkgName, pkg.InstalledVersion, pkg.FixedVersion})
					}
					return out
				}
			}
		}
		return nil
	}
	wantPkgs := [][3]string{{"pkg-a", "1.0", "1.2"}, {"pkg-b", "2.0", "2.1"}}
	require.Equal(t, wantPkgs, pkgsOf(m1.prompts, "CVE-2024-0000"))
	require.Equal(t, wantPkgs, pkgsOf(m10.prompts, "CVE-2024-0000"))

	// The CVE is asked once, so its score comes from that call's answer at
	// either batch size (the "first" answer: 25.0), identical on every
	// component row. The per-call answers genuinely differ: CVE-2024-1111
	// scores 81.0 at batch size 1 (second call) and 25.0 at batch size 10
	// (first call), which is expected and unrelated to the CVE under test.
	for _, rs := range [][]outputhandler.VulnRating{got1, got10} {
		require.Len(t, rs, 3)
		for _, r := range rs {
			if r.VulnID == "CVE-2024-0000" {
				require.Equal(t, 25.0, *r.Rating.Score, "the CVE's single ask decides its score")
			}
		}
	}
	byID := func(rs []outputhandler.VulnRating) map[string]float64 {
		out := map[string]float64{}
		for _, r := range rs {
			out[r.VulnID] = *r.Rating.Score
		}
		return out
	}
	require.Equal(t, 81.0, byID(got1)["CVE-2024-1111"], "per-call answers must actually differ")
	require.Equal(t, 25.0, byID(got10)["CVE-2024-1111"])

	// The VEX rows stay in scanner order (pkg-b, pkg-a, then other) even
	// though the prompt's package list is sorted.
	refs := func(rs []outputhandler.VulnRating) []string {
		var out []string
		for _, r := range rs {
			out = append(out, r.BOMRef)
		}
		return out
	}
	require.Equal(t, []string{"b", "a", "other"}, refs(got1))
	require.Equal(t, []string{"b", "a", "other"}, refs(got10))
}

// Zero likelihood is what makes a verdict "not reachable here", whatever impact
// the model gave; a zero reached with a non-zero likelihood is a genuine low
// score.
func TestZeroLikelihood(t *testing.T) {
	for _, tc := range []struct {
		shape [4]float64
		want  bool
	}{
		{[4]float64{0, 0, 0, 0}, true},
		{[4]float64{0, 0, 0, 1}, true},
		{[4]float64{0, 0, 1, 1}, true},
		{[4]float64{0, 0, 8, 8}, true},
		{[4]float64{0, 1, 0, 0}, false},
		{[4]float64{1, 0, 9, 9}, false},
	} {
		e := llmOutputEntry{ThreatAgentScore: tc.shape[0], VulnerabilityScore: tc.shape[1], TechnicalImpact: tc.shape[2], BusinessImpact: tc.shape[3]}
		require.Equal(t, tc.want, zeroLikelihood(e), "shape %v", tc.shape)
	}
}

// The fail-fast error names each unanswered CVE once, sorted, never once per row.
func TestGenerator_ErrorNamesEachUnansweredCVEOnce(t *testing.T) {
	m := newDroppingLLM(true, "CVE-2024-0000", "CVE-2024-0002")
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0002", PkgName: "pkg-a", Title: "t"},
		{VulnID: "CVE-2024-0000", PkgName: "pkg-b", Title: "t"},
		{VulnID: "CVE-2024-0001", PkgName: "pkg-c", Title: "t"},
		{VulnID: "CVE-2024-0000", PkgName: "pkg-d", Title: "t"},
	}
	err = g.GenerateRiskScore(context.Background(), vulns, nil)
	require.EqualError(t, err, "model returned no score for CVE-2024-0000, CVE-2024-0002 after asking again; stopping the run")
}

// recordingLLM records the temperature of every request it receives and
// scores each CVE deterministically, so tests can assert what the generator
// forwarded to the provider.
type recordingLLM struct {
	temperatures []*float64
}

func (m *recordingLLM) Generate(_ context.Context, req llm.Request) (string, error) {
	m.temperatures = append(m.temperatures, req.Temperature)
	var in []struct {
		VulnID string `json:"vulnId"`
	}
	if err := json.Unmarshal([]byte(req.Human), &in); err != nil {
		return "", err
	}
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

// --llm-temperature must reach the provider request exactly as passed, and
// stay absent (nil) when the flag wasn't given.
func TestGenerator_TemperatureReachesRequest(t *testing.T) {
	t.Run("explicit temperature is forwarded", func(t *testing.T) {
		m := &recordingLLM{}
		temp := 0.7
		g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, Temperature: &temp, BatchSize: 10})
		require.NoError(t, err)

		require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), nil))
		require.NotEmpty(t, m.temperatures, "expected at least one LLM call")
		for _, got := range m.temperatures {
			require.NotNil(t, got, "request must carry the explicit temperature")
			require.Equal(t, 0.7, *got)
		}
	})

	t.Run("explicit zero is forwarded, not confused with unset", func(t *testing.T) {
		m := &recordingLLM{}
		temp := 0.0 // --llm-temperature=0 explicitly passed
		g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, Temperature: &temp, BatchSize: 10})
		require.NoError(t, err)

		require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), nil))
		require.NotEmpty(t, m.temperatures, "expected at least one LLM call")
		for _, got := range m.temperatures {
			require.NotNil(t, got, "an explicit 0 must stay non-nil: it was the user's choice, not the default")
			require.Equal(t, 0.0, *got)
		}
	})

	t.Run("nil when the flag was not passed", func(t *testing.T) {
		m := &recordingLLM{}
		g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
		require.NoError(t, err)

		require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), nil))
		require.NotEmpty(t, m.temperatures, "expected at least one LLM call")
		for _, got := range m.temperatures {
			require.Nil(t, got, "request must not carry a temperature when the flag was not passed")
		}
	})
}

// retryVolunteerLLM leaves its first question unanswered, then answers the
// retry and volunteers a low score for CVE-2024-0001, which it wasn't asked.
type retryVolunteerLLM struct{ calls int }

func (m *retryVolunteerLLM) Generate(_ context.Context, req llm.Request) (string, error) {
	var in []struct {
		VulnID string `json:"vulnId"`
	}
	if err := json.Unmarshal([]byte(req.Human), &in); err != nil {
		return "", err
	}
	m.calls++
	out := llmOutput{Results: []llmOutputEntry{}}
	if m.calls > 1 {
		for _, v := range in {
			out.Results = append(out.Results, llmOutputEntry{VulnID: v.VulnID, ThreatAgentScore: 9, VulnerabilityScore: 9,
				TechnicalImpact: 9, BusinessImpact: 9, Reasoning: "asked"})
		}
	}
	if m.calls == 2 {
		out.Results = append(out.Results, llmOutputEntry{VulnID: "CVE-2024-0001", ThreatAgentScore: 1, VulnerabilityScore: 1,
			TechnicalImpact: 1, BusinessImpact: 1, Reasoning: "not asked"})
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// The retry drops answers for CVEs it didn't ask about too.
func TestGenerator_IgnoresAnswersForCVEsNotAskedOnRetry(t *testing.T) {
	m := &retryVolunteerLLM{}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 1})
	require.NoError(t, err)

	byID := map[string]outputhandler.VulnRating{}
	h := func(group []outputhandler.VulnRating) error {
		for _, r := range group {
			byID[r.VulnID] = r
		}
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), h))
	require.Equal(t, 3, m.calls, "batch 1, its retry, then CVE-2024-0001 in its own batch")
	require.Equal(t, *byID["CVE-2024-0000"].Rating.Score, *byID["CVE-2024-0001"].Rating.Score,
		"CVE-2024-0001 must carry the answer to its own question, not the one volunteered on the retry")
}

// truncatedRetryLLM gives CVE-2024-0000 zero likelihood and leaves
// CVE-2024-0001 out on its first call, truncates the retry, then scores
// whatever it is asked.
type truncatedRetryLLM struct{ calls int }

func (m *truncatedRetryLLM) Generate(_ context.Context, req llm.Request) (string, error) {
	var in []struct {
		VulnID string `json:"vulnId"`
	}
	if err := json.Unmarshal([]byte(req.Human), &in); err != nil {
		return "", err
	}
	m.calls++
	if m.calls == 2 {
		return "", fmt.Errorf("mock truncated: %w", llm.ErrTruncated)
	}
	out := llmOutput{Results: []llmOutputEntry{}}
	for _, v := range in {
		if m.calls == 1 && v.VulnID == "CVE-2024-0001" {
			continue
		}
		e := scoredEntry()
		if v.VulnID == "CVE-2024-0000" {
			e = zeroLikelihoodEntry()
		}
		e.VulnID = v.VulnID
		out.Results = append(out.Results, e)
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// The zero-likelihood WARN still fires once when the retry truncates: the split
// halves re-ask their own CVE groups, and the half that publishes the verdict
// logs it.
func TestGenerator_ZeroLikelihoodWarnSurvivesTruncatedRetry(t *testing.T) {
	m := &truncatedRetryLLM{}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 2})
	require.NoError(t, err)

	logs := withCapturedLogs(t)
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), nil))

	warns := 0
	for _, r := range logs.records {
		if r.level == slog.LevelWarn && r.attrs["vuln"] == "CVE-2024-0000" {
			warns++
		}
	}
	require.Equal(t, 1, warns, "the verdict is logged once, even when the retry truncates")
}
