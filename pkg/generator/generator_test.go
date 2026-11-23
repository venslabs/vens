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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/internal/testutil"
	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/owasp"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// Test vectors, every level one of its factor's: midVector rates 27.3125
// (likelihood 38/8, technical 23/4), lowVector 1.75, highVector 81.
var (
	midVector  = owasp.Vector{SL: 5, M: 4, O: 4, S: 5, ED: 3, EE: 5, A: 4, ID: 8, LC: 6, LI: 5, LAV: 5, LAC: 7, FD: 3, RD: 5, NC: 5, PV: 5}
	lowVector  = owasp.Vector{SL: 1, M: 1, O: 0, S: 2, ED: 1, EE: 1, A: 1, ID: 1, LC: 2, LI: 1, LAV: 1, LAC: 1, FD: 1, RD: 1, NC: 2, PV: 3}
	highVector = owasp.Vector{SL: 9, M: 9, O: 9, S: 9, ED: 9, EE: 9, A: 9, ID: 9, LC: 9, LI: 9, LAV: 9, LAC: 9, FD: 9, RD: 9, NC: 7, PV: 9}
)

// levelsOf lists v's 16 levels in factors' order, vectorOf's inverse.
func levelsOf(v owasp.Vector) []int {
	return []int{int(v.SL), int(v.M), int(v.O), int(v.S), int(v.ED), int(v.EE), int(v.A), int(v.ID),
		int(v.LC), int(v.LI), int(v.LAV), int(v.LAC), int(v.FD), int(v.RD), int(v.NC), int(v.PV)}
}

// MarshalJSON writes an entry as the schema asks for it, vulnId, the 16
// factor keys in order, then reasoning, so the fake models answer like one.
func (e llmOutputEntry) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	id, err := json.Marshal(e.VulnID)
	if err != nil {
		return nil, err
	}
	b.WriteString(`{"vulnId":`)
	b.Write(id)
	for i, l := range levelsOf(e.Levels) {
		fmt.Fprintf(&b, `,%q:%d`, factors[i].key, l)
	}
	reasoning, err := json.Marshal(e.Reasoning)
	if err != nil {
		return nil, err
	}
	b.WriteString(`,"reasoning":`)
	b.Write(reasoning)
	b.WriteString("}")
	return b.Bytes(), nil
}

// scoreOf is v's score as owasp.Vector.Rate gives it.
func scoreOf(t *testing.T, v owasp.Vector) float64 {
	t.Helper()
	r, err := v.Rate()
	require.NoError(t, err)
	return r.Score
}

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
			VulnID:    v.VulnID,
			Levels:    midVector,
			Reasoning: "mock",
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

// A split half still sees the rows after it. CVE-2024-0100 sits on rows 1 and
// 7 of one batch of 10, split twice; the model skips it until its third ask.
// The row-7 half scores it, so the run must not fail in the row-1 half.
func TestGenerator_SplitHalfSeesLaterRows(t *testing.T) {
	m := &truncatingLLM{maxPerCall: 3, skip: map[string]int{"CVE-2024-0100": 2}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	vulns := testVulns(10)
	vulns[1].VulnID, vulns[1].BOMRef = "CVE-2024-0100", "x1"
	vulns[7].VulnID, vulns[7].BOMRef = "CVE-2024-0100", "x2"
	var emitted []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		emitted = append(emitted, group...)
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, h))
	require.Len(t, emitted, 10, "every row is emitted, both CVE-2024-0100 rows included")
	require.Equal(t, 3, m.asked["CVE-2024-0100"], "skipped, asked again, then scored with row 7")
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
			VulnID:    v.VulnID,
			Levels:    midVector,
			Reasoning: "mock",
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
// missing at exit code 0. No later row has it, so the batch fails right after
// the retry, before emitting anything.
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
	require.EqualError(t, err, "model returned no score for CVE-2024-0002 after asking again; stopping the run")
	require.Len(t, emitted, 0, "the batch fails before emitting; the failed run commits no VEX")
	require.Len(t, m.batches, 2, "asked once, asked again, then gives up")
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

// A CVE on two rows that is never answered waits for its last row, then stops
// the run there: the row after it is never asked.
func TestGenerator_FailsFastAtLastRowOfCVE(t *testing.T) {
	m := newDroppingLLM(true, "CVE-2024-0000")
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 1})
	require.NoError(t, err)

	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "openssl", Title: "t"},
		{VulnID: "CVE-2024-0000", PkgName: "libssl3", Title: "t"},
		{VulnID: "CVE-2024-0001", PkgName: "curl", Title: "t"},
	}
	err = g.GenerateRiskScore(context.Background(), vulns, nil)
	require.EqualError(t, err, "model returned no score for CVE-2024-0000 after asking again; stopping the run")
	require.Equal(t, []int{1, 1, 1, 1}, m.batches, "asked and asked again at both rows, curl never asked")
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

func scoredEntry() llmOutputEntry {
	return llmOutputEntry{Levels: midVector, Reasoning: "mock scored"}
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
			VulnID:    v.VulnID,
			Levels:    midVector,
			Reasoning: "real answer",
		})
	}
	if m.calls == 1 {
		out.Results = append(out.Results, llmOutputEntry{
			VulnID:    "CVE-2024-0001",
			Levels:    lowVector,
			Reasoning: "leaked stale answer for a CVE that wasn't asked about",
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
			// Fresh score: midVector's. The leaked entry would have scored
			// lowVector's.
			require.NotEqual(t, scoreOf(t, midVector), scoreOf(t, lowVector))
			require.Equal(t, scoreOf(t, midVector), *r.Rating.Score,
				"CVE-2024-0001 must carry the score from its own ask, not the leaked entry")
		}
	}
}

// A CVE in two batches is asked about once: the second batch leaves it out of
// its prompt and reuses the first score, so its component keeps its VEX row.
func TestGenerator_DupCVEReusesFirstScore(t *testing.T) {
	m := &scriptedLLM{answer: func(call int, _ string) llmOutputEntry {
		if call == 1 {
			return llmOutputEntry{Levels: midVector, Reasoning: "first"}
		}
		return llmOutputEntry{Levels: highVector, Reasoning: "second"}
	}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 1})
	require.NoError(t, err)

	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "openssl", Title: "t", BOMRef: "openssl"},
		{VulnID: "CVE-2024-0000", PkgName: "libssl3", Title: "t", BOMRef: "libssl3"},
	}

	var got []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		got = append(got, group...)
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, h))
	require.Equal(t, 1, m.calls, "the second batch must not ask about an already-scored CVE")
	require.Len(t, got, 2, "both components must keep their VEX rows")
	require.Equal(t, "openssl", got[0].BOMRef)
	require.Equal(t, "libssl3", got[1].BOMRef)
	for _, r := range got {
		require.Equal(t, scoreOf(t, midVector), *r.Rating.Score, "both rows carry the first score")
	}
}

// When a later batch reuses an earlier batch's score for a CVE, the
// attestation claim for that batch's package must be marked as reused:
// its cited evidence bundle is the first call's, whose prompt never
// mentioned this package.
func TestGenerator_Attestor_ReusedScoreMarksClaim(t *testing.T) {
	m := &scriptedLLM{
		answer: func(_ int, _ string) llmOutputEntry { return scoredEntry() },
	}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 1})
	require.NoError(t, err)
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	g.SetAttestor(at)

	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "openssl", Title: "t", BOMRef: "openssl"},
		{VulnID: "CVE-2024-0000", PkgName: "libssl3", Title: "t", BOMRef: "libssl3"},
	}
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))
	require.Equal(t, 1, m.calls, "the second batch must not ask about an already-scored CVE")

	var buf bytes.Buffer
	require.NoError(t, at.Write(&buf))
	var got struct {
		Declarations struct {
			Claims []struct {
				Target    string   `json:"target"`
				Predicate string   `json:"predicate"`
				Evidence  []string `json:"evidence"`
			} `json:"claims"`
		} `json:"declarations"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got), "output:\n%s", buf.String())
	require.Len(t, got.Declarations.Claims, 2, "both components must keep their attestation claims")

	byTarget := map[string]struct {
		Predicate string
		Evidence  []string
	}{}
	for _, c := range got.Declarations.Claims {
		byTarget[c.Target] = struct {
			Predicate string
			Evidence  []string
		}{c.Predicate, c.Evidence}
	}

	assert.NotContains(t, byTarget["openssl"].Predicate, "this package was not in the cited batch's prompt",
		"the first package was in the prompt behind the cited evidence")
	assert.Contains(t, byTarget["libssl3"].Predicate, "this package was not in the cited batch's prompt")
	assert.Equal(t, byTarget["openssl"].Evidence, byTarget["libssl3"].Evidence,
		"the reused claim cites the first call's evidence bundle")
}

// Score reuse works in both directions: a batch that gets no answer for a CVE
// holds its components back, and when a later batch scores the CVE those rows
// are filled in with that score instead of dropping out of the VEX.
func TestGenerator_LaterBatchScoreBackfillsEarlierBatchRows(t *testing.T) {
	m := &scriptedLLM{
		answer: func(_ int, _ string) llmOutputEntry { return scoredEntry() },
		// Batch 1 (call 1) and its retry (call 2) get no answer; batch 2
		// (call 3) scores the CVE.
		skip: func(call int, id string) bool {
			return id == "CVE-2024-0000" && call <= 2
		},
	}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 1})
	require.NoError(t, err)

	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "pkg-a", Title: "t", BOMRef: "a"},
		{VulnID: "CVE-2024-0000", PkgName: "pkg-b", Title: "t", BOMRef: "b"},
	}

	var got []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		got = append(got, group...)
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, h))
	require.Equal(t, 3, m.calls, "batch 1, its retry, then batch 2")
	require.Len(t, got, 2, "the earlier batch's component row is kept and filled in once the CVE is scored")
	refs := map[string]bool{}
	for _, r := range got {
		refs[r.BOMRef] = true
		require.NotNil(t, r.Rating.Score)
		require.Greater(t, *r.Rating.Score, 0.0, "rows carry the later batch's real score")
	}
	require.True(t, refs["a"] && refs["b"], "both components keep their VEX rows")
	require.Equal(t, *got[0].Rating.Score, *got[1].Rating.Score, "both rows carry the same score")
}

// A CVE held back on two components, because neither the batch nor its retry
// answered it, is filled in once a later batch scores it: one row and one
// claim per component, in scanner order.
func TestGenerator_HeldBackCVEOnTwoComponentsFilledInOnce(t *testing.T) {
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	m := &scriptedLLM{
		answer: func(_ int, _ string) llmOutputEntry { return scoredEntry() },
		// Batch 1 (call 1) and its retry (call 2) get no answer; batch 2
		// (call 3) scores the CVE.
		skip: func(call int, _ string) bool { return call <= 2 },
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
	require.Equal(t, 3, m.calls, "batch 1, its retry, then batch 2")
	require.Equal(t, []string{"a", "b", "c"}, rows)

	var buf bytes.Buffer
	require.NoError(t, at.Write(&buf))
	var doc struct {
		Declarations struct {
			Claims []struct {
				Target    string   `json:"target"`
				Predicate string   `json:"predicate"`
				Evidence  []string `json:"evidence"`
			} `json:"claims"`
		} `json:"declarations"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))
	var targets []string
	byTarget := map[string]struct {
		Predicate string
		Evidence  []string
	}{}
	for _, c := range doc.Declarations.Claims {
		targets = append(targets, c.Target)
		byTarget[c.Target] = struct {
			Predicate string
			Evidence  []string
		}{c.Predicate, c.Evidence}
	}
	require.Equal(t, []string{"a", "b", "c"}, targets)

	// The held-back rows were filled in by batch 2, whose prompt never had
	// their packages: their claims cite that later call's evidence and must
	// say so. Row c was in that prompt, so its claim stays clean.
	for _, target := range []string{"a", "b"} {
		assert.Contains(t, byTarget[target].Predicate, "this package was not in the cited batch's prompt",
			"target %s was held back and filled in by a later batch", target)
	}
	assert.NotContains(t, byTarget["c"].Predicate, "this package was not in the cited batch's prompt")
	assert.Equal(t, byTarget["a"].Evidence, byTarget["b"].Evidence)
	assert.Equal(t, byTarget["b"].Evidence, byTarget["c"].Evidence,
		"all three rows cite the later batch's evidence bundle")
	assert.Equal(t, []string{"evidence-batch-3"}, byTarget["c"].Evidence)
}

// The error names each unanswered CVE once, in order, never once per row.
func TestGenerator_ErrorNamesEachMissingCVEOnce(t *testing.T) {
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

// checkUnassessed, the end-of-run safety net, counts distinct CVEs, not rows.
func TestScoringRun_CheckUnassessed(t *testing.T) {
	require.NoError(t, (&scoringRun{scored: map[string]bool{"CVE-2024-0001": true}, missing: map[string]bool{}}).checkUnassessed())

	run := &scoringRun{
		scored:  map[string]bool{"CVE-2024-0001": true},
		missing: map[string]bool{"CVE-2024-0002": true, "CVE-2024-0000": true},
	}
	require.EqualError(t, run.checkUnassessed(),
		"model returned no score for 2 of 3 vulnerabilities, after asking again: CVE-2024-0000, CVE-2024-0002")
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
			VulnID:    v.VulnID,
			Levels:    midVector,
			Reasoning: "mock",
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
			out.Results = append(out.Results, llmOutputEntry{VulnID: v.VulnID, Levels: highVector, Reasoning: "asked"})
		}
	}
	if m.calls == 2 {
		out.Results = append(out.Results, llmOutputEntry{VulnID: "CVE-2024-0001", Levels: lowVector, Reasoning: "not asked"})
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

// truncatedRetryLLM gives CVE-2024-0000 lowVector and leaves CVE-2024-0001
// out on its first call, truncates the retry, then scores whatever it is asked.
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
			e = llmOutputEntry{Levels: lowVector, Reasoning: "mock low"}
		}
		e.VulnID = v.VulnID
		out.Results = append(out.Results, e)
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// When the retry truncates, the split batch reuses the first answer, which no
// batch had published yet. The sub-batch's rows were all in the first call's
// prompt, so neither claim may say its package was missing from the cited
// batch's prompt.
func TestGenerator_ClaimsSurviveTruncatedRetry(t *testing.T) {
	m := &truncatedRetryLLM{}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 2})
	require.NoError(t, err)
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	g.SetAttestor(at)

	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "pkg-a", Title: "t", BOMRef: "a"},
		{VulnID: "CVE-2024-0001", PkgName: "pkg-b", Title: "t", BOMRef: "b"},
	}
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))

	var buf bytes.Buffer
	require.NoError(t, at.Write(&buf))
	var got struct {
		Declarations struct {
			Claims []struct {
				Target    string   `json:"target"`
				Predicate string   `json:"predicate"`
				Evidence  []string `json:"evidence"`
			} `json:"claims"`
		} `json:"declarations"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got), "output:\n%s", buf.String())
	require.Len(t, got.Declarations.Claims, 2)
	for _, c := range got.Declarations.Claims {
		assert.NotContains(t, c.Predicate, "this package was not in the cited batch's prompt",
			"target %s: the row was in the first call's prompt, so the claim must not say otherwise", c.Target)
	}
	byTarget := map[string][]string{}
	for _, c := range got.Declarations.Claims {
		byTarget[c.Target] = c.Evidence
	}
	assert.Equal(t, []string{"evidence-batch-1"}, byTarget["a"],
		"the reused answer keeps citing the first call's evidence bundle")
}

// runDirs lists the run-* directories under a --debug-dir.
func runDirs(t *testing.T, parent string) []string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join(parent, "run-*"))
	require.NoError(t, err)
	return dirs
}

func fileNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names
}

func debugFile(t *testing.T, dir string, call int, ext string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("batch-%05d.%s", call, ext)))
	require.NoError(t, err)
	return string(b)
}

// Runs sharing a --debug-dir, here two in parallel, each write into their own
// run-* directory and log it once, so neither overwrites the other's
// batch-00001 files (#359).
func TestDebugDir_OneDirectoryPerRun(t *testing.T) {
	logs := withCapturedLogs(t)
	parent := t.TempDir()

	ids := []string{"CVE-2024-1111", "CVE-2024-2222"}
	gens := make([]*Generator, len(ids))
	for i := range ids {
		g, err := New(Opts{LLM: testutil.NewMockLLM(), Config: &riskconfig.Config{}, DebugDir: parent})
		require.NoError(t, err)
		gens[i] = g
	}
	errs := make([]error, len(gens))
	var wg sync.WaitGroup
	for i, g := range gens {
		wg.Go(func() {
			errs[i] = g.GenerateRiskScore(context.Background(), []Vulnerability{{VulnID: ids[i], PkgName: "pkg", Title: "t"}}, nil)
		})
	}
	wg.Wait()
	require.NoError(t, errors.Join(errs...))

	dirs := runDirs(t, parent)
	require.Len(t, dirs, 2, "one directory per run")

	var logged []string
	for _, r := range logs.records {
		if r.msg == "Writing debug files" {
			require.Equal(t, slog.LevelInfo, r.level)
			logged = append(logged, fmt.Sprint(r.attrs["dir"]))
		}
	}
	require.ElementsMatch(t, dirs, logged, "each run logs its directory once")

	got := map[string]bool{}
	for _, dir := range dirs {
		require.Equal(t, []string{"batch-00001.human.prompt", "batch-00001.response", "batch-00001.system.prompt"}, fileNames(t, dir))
		var asked []LLMVulnerability
		require.NoError(t, json.Unmarshal([]byte(debugFile(t, dir, 1, "human.prompt")), &asked))
		require.Len(t, asked, 1)
		require.Contains(t, debugFile(t, dir, 1, "response"), asked[0].VulnID, "the response sits beside its own prompt")
		got[asked[0].VulnID] = true
	}
	require.Equal(t, map[string]bool{"CVE-2024-1111": true, "CVE-2024-2222": true}, got, "each run kept its own prompt")
}

type attestedCall struct {
	promptHash  string
	rawResponse string
}

// attestedCalls returns the prompt_hash and the decoded raw_response of every
// evidence entry, in order.
func attestedCalls(t *testing.T, at *attestation.Builder) []attestedCall {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, at.Write(&buf))
	var doc struct {
		Declarations struct {
			Evidence []struct {
				Data []struct {
					Name     string `json:"name"`
					Contents struct {
						Attachment struct {
							Content string `json:"content"`
						} `json:"attachment"`
					} `json:"contents"`
				} `json:"data"`
			} `json:"evidence"`
		} `json:"declarations"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	calls := make([]attestedCall, 0, len(doc.Declarations.Evidence))
	for _, e := range doc.Declarations.Evidence {
		var c attestedCall
		for _, d := range e.Data {
			switch d.Name {
			case "prompt_hash":
				c.promptHash = d.Contents.Attachment.Content
			case "raw_response":
				raw, err := base64.StdEncoding.DecodeString(d.Contents.Attachment.Content)
				require.NoError(t, err)
				c.rawResponse = string(raw)
			}
		}
		calls = append(calls, c)
	}
	return calls
}

// Files are numbered per LLM call, not per batch: the two-CVE batch truncates
// and keeps its prompts without a response, then the model skips CVE-2024-0001
// in its half, so the ask-again is a call of its own. The attestation records
// only the calls that returned, so batch-00002 is evidence-batch-1 and a file
// set is found there by prompt_hash.
func TestDebugDir_WritesOneFileSetPerCall(t *testing.T) {
	parent := t.TempDir()
	m := &truncatingLLM{maxPerCall: 1, skip: map[string]int{"CVE-2024-0001": 1}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 2, DebugDir: parent})
	require.NoError(t, err)
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	g.SetAttestor(at)

	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), nil))

	dirs := runDirs(t, parent)
	require.Len(t, dirs, 1)
	dir := dirs[0]
	require.Equal(t, []string{
		"batch-00001.human.prompt", "batch-00001.system.prompt",
		"batch-00002.human.prompt", "batch-00002.response", "batch-00002.system.prompt",
		"batch-00003.human.prompt", "batch-00003.response", "batch-00003.system.prompt",
		"batch-00004.human.prompt", "batch-00004.response", "batch-00004.system.prompt",
	}, fileNames(t, dir), "the truncated call returned nothing, so it has no response")

	asked := func(call int) []string {
		var in []LLMVulnerability
		require.NoError(t, json.Unmarshal([]byte(debugFile(t, dir, call, "human.prompt")), &in))
		return vulnIDs(in)
	}
	answered := func(call int) []string {
		var out llmOutput
		require.NoError(t, json.Unmarshal([]byte(debugFile(t, dir, call, "response")), &out))
		ids := []string{}
		for _, e := range out.Results {
			ids = append(ids, e.VulnID)
		}
		return ids
	}
	require.Equal(t, []string{"CVE-2024-0000", "CVE-2024-0001"}, asked(1), "the batch the provider truncated")
	require.Equal(t, []string{"CVE-2024-0000"}, asked(2))
	require.Equal(t, []string{"CVE-2024-0000"}, answered(2))
	require.Equal(t, []string{"CVE-2024-0001"}, asked(3))
	require.Empty(t, answered(3), "the model skipped it")
	require.Equal(t, []string{"CVE-2024-0001"}, asked(4), "asked again on its own")
	require.Equal(t, []string{"CVE-2024-0001"}, answered(4))

	promptHash := func(call int) string {
		sum := sha256.Sum256([]byte(debugFile(t, dir, call, "system.prompt") + "\n\n" + debugFile(t, dir, call, "human.prompt")))
		return hex.EncodeToString(sum[:])
	}
	require.Equal(t, promptHash(3), promptHash(4), "the ask-again repeats its prompt word for word")
	calls := attestedCalls(t, at)
	require.Len(t, calls, 3, "the truncated call is not attested")
	for i, call := range []int{2, 3, 4} {
		require.Equalf(t, promptHash(call), calls[i].promptHash, "batch-%05d is evidence-batch-%d", call, i+1)
		require.Equalf(t, debugFile(t, dir, call, "response"), calls[i].rawResponse, "batch-%05d.response is the raw reply", call)
	}
}

type unparsableLLM struct{}

func (unparsableLLM) Generate(context.Context, llm.Request) (string, error) {
	return "not json", nil
}

// The response is written before it is parsed, so the reply behind an
// "unable to parse LLM output" error is on disk.
func TestDebugDir_KeepsAReplyThatFailsToParse(t *testing.T) {
	parent := t.TempDir()
	g, err := New(Opts{LLM: unparsableLLM{}, Config: &riskconfig.Config{}, DebugDir: parent})
	require.NoError(t, err)

	require.ErrorContains(t, g.GenerateRiskScore(context.Background(), testVulns(1), nil), "unable to parse LLM output")
	dirs := runDirs(t, parent)
	require.Len(t, dirs, 1)
	require.Equal(t, "not json", debugFile(t, dirs[0], 1, "response"))
}

// The files hold the deployment context and the CVE inventory, so the run
// directory and every file in it are for the user only.
func TestDebugDir_FilesArePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	parent := t.TempDir()
	g, err := New(Opts{LLM: testutil.NewMockLLM(), Config: &riskconfig.Config{}, DebugDir: parent})
	require.NoError(t, err)
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(1), nil))

	dirs := runDirs(t, parent)
	require.Len(t, dirs, 1)
	info, err := os.Stat(dirs[0])
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o700), info.Mode().Perm(), "run directory")

	entries, err := os.ReadDir(dirs[0])
	require.NoError(t, err)
	require.Len(t, entries, 3)
	for _, e := range entries {
		info, err := e.Info()
		require.NoError(t, err)
		require.Equalf(t, fs.FileMode(0o600), info.Mode().Perm(), "%s", e.Name())
	}
}

// A debug file that can't be written is logged under one constant message
// naming the file, and the run goes on.
func TestDebugDir_WriteFailureLogsTheFile(t *testing.T) {
	logs := withCapturedLogs(t)
	parent := t.TempDir()
	g, err := New(Opts{LLM: testutil.NewMockLLM(), Config: &riskconfig.Config{}, DebugDir: parent})
	require.NoError(t, err)
	dirs := runDirs(t, parent)
	require.Len(t, dirs, 1)
	require.NoError(t, os.RemoveAll(dirs[0]))

	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(1), func(group []outputhandler.VulnRating) error {
		emitted = append(emitted, group...)
		return nil
	}))
	require.Len(t, emitted, 1, "a debug file is no reason to fail the run")

	var failed []string
	for _, r := range logs.records {
		if r.msg == "failed to write a debug file" {
			require.Equal(t, slog.LevelError, r.level)
			failed = append(failed, fmt.Sprint(r.attrs["file"]))
		}
	}
	require.Equal(t, []string{
		filepath.Join(dirs[0], "batch-00001.system.prompt"),
		filepath.Join(dirs[0], "batch-00001.human.prompt"),
		filepath.Join(dirs[0], "batch-00001.response"),
	}, failed)
}

// runSummary returns the run's one INFO summary.
func runSummary(t *testing.T, logs *captureHandler) capturedRecord {
	t.Helper()
	var found []capturedRecord
	for _, r := range logs.records {
		if r.level == slog.LevelInfo && r.msg == "Scoring run finished" {
			found = append(found, r)
		}
	}
	require.Len(t, found, 1, "one summary per run")
	return found[0]
}

// Every batch logs its composition at debug level, and the run closes with an
// INFO summary of rows, distinct CVEs, LLM calls, asks-again and splits.
func TestGenerator_LogsBatchCompositionAndRunSummary(t *testing.T) {
	m := &scriptedLLM{answer: func(_ int, _ string) llmOutputEntry { return scoredEntry() }}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 2})
	require.NoError(t, err)

	logs := withCapturedLogs(t)
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(4), nil))

	var batches []capturedRecord
	for _, r := range logs.records {
		if r.level == slog.LevelDebug && r.msg == "scoring batch" {
			batches = append(batches, r)
		}
	}
	require.Len(t, batches, 2, "one debug line per batch")
	require.Equal(t, int64(2), batches[0].attrs["rows"])
	require.Equal(t, "CVE-2024-0000,CVE-2024-0001", batches[0].attrs["vulns"])
	require.Equal(t, int64(2), batches[1].attrs["rows"])
	require.Equal(t, "CVE-2024-0002,CVE-2024-0003", batches[1].attrs["vulns"])

	summary := runSummary(t, logs)
	require.Equal(t, int64(4), summary.attrs["rows"])
	require.Equal(t, int64(4), summary.attrs["cves"])
	require.Equal(t, int64(2), summary.attrs["llm_calls"])
	require.Equal(t, int64(0), summary.attrs["asked_again"])
	require.Equal(t, int64(0), summary.attrs["splits"])
	require.Equal(t, false, summary.attrs["failed"])
}

// A failed run still logs its summary, marked failed: it is the run one
// usually debugs.
func TestGenerator_LogsRunSummaryWhenTheRunFails(t *testing.T) {
	m := newDroppingLLM(true, "CVE-2024-0000")
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 2})
	require.NoError(t, err)

	logs := withCapturedLogs(t)
	require.Error(t, g.GenerateRiskScore(context.Background(), testVulns(4), nil))

	summary := runSummary(t, logs)
	require.Equal(t, true, summary.attrs["failed"])
	require.Equal(t, int64(4), summary.attrs["rows"])
	require.Equal(t, int64(4), summary.attrs["cves"])
	require.Equal(t, int64(2), summary.attrs["llm_calls"], "batch 1 and its ask-again; the run stops before batch 2")
	require.Equal(t, int64(1), summary.attrs["asked_again"])
	require.Equal(t, int64(0), summary.attrs["splits"])
}

// A row without a vulnerability ID is a row, not a CVE.
func TestGenerator_RunSummaryCVECountSkipsRowsWithoutID(t *testing.T) {
	m := &scriptedLLM{answer: func(_ int, _ string) llmOutputEntry { return scoredEntry() }}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	logs := withCapturedLogs(t)
	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "pkg-a", Title: "t", BOMRef: "a"},
		{PkgName: "pkg-b", Title: "t", BOMRef: "b"},
		{VulnID: "CVE-2024-0001", PkgName: "pkg-c", Title: "t", BOMRef: "c"},
	}
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))

	summary := runSummary(t, logs)
	require.Equal(t, int64(3), summary.attrs["rows"])
	require.Equal(t, int64(2), summary.attrs["cves"])
}

// Leaving a scored CVE out of the prompt and reusing its first score is one
// decision: one debug line per CVE, naming the bundle the reused score cites.
func TestGenerator_LogsScoreReuseFromEarlierBatch(t *testing.T) {
	m := &scriptedLLM{answer: func(_ int, _ string) llmOutputEntry { return scoredEntry() }}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 1})
	require.NoError(t, err)
	g.SetAttestor(attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"}))

	logs := withCapturedLogs(t)
	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0000", PkgName: "pkg-a", Title: "t", BOMRef: "a"},
		{VulnID: "CVE-2024-0000", PkgName: "pkg-b", Title: "t", BOMRef: "b"},
	}
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))

	// The debug lines of the second batch, after its composition line.
	var second []capturedRecord
	batches := 0
	for _, r := range logs.records {
		if r.level != slog.LevelDebug {
			continue
		}
		if r.msg == "scoring batch" {
			batches++
			continue
		}
		if batches == 2 {
			second = append(second, r)
		}
	}
	require.Len(t, second, 1, "one decision, one line")
	require.Equal(t, "reusing an earlier batch's first score", second[0].msg)
	require.Equal(t, "CVE-2024-0000", second[0].attrs["vuln"])
	require.Equal(t, "evidence-batch-1", second[0].attrs["evidence_ref"])
}

// A split names both halves at debug level; a CVE the model skips in both the
// ask and the ask-again waits for a later row instead of failing. The fake is
// deterministic, so the summary's counts are exact: 8 LLM calls, 3 of them
// truncated (rows 0-9, 0-4 and 5-9), 1 ask-again (rows 0-2) and 3 splits.
func TestGenerator_LogsSplitHoldBackAndSummaryCounts(t *testing.T) {
	m := &truncatingLLM{maxPerCall: 3, skip: map[string]int{"CVE-2024-0100": 2}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	logs := withCapturedLogs(t)
	vulns := testVulns(10)
	vulns[1].VulnID, vulns[1].BOMRef = "CVE-2024-0100", "x1"
	vulns[7].VulnID, vulns[7].BOMRef = "CVE-2024-0100", "x2"
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))

	var splits, holdBacks int
	for _, r := range logs.records {
		switch {
		case r.level == slog.LevelDebug && r.msg == "splitting truncated batch":
			splits++
			require.NotEmpty(t, r.attrs["first_half"], "the split must name the rows each half keeps")
			require.NotEmpty(t, r.attrs["second_half"], "the split must name the rows each half keeps")
		case r.level == slog.LevelDebug && r.msg == "holding back rows until a later batch scores the CVE":
			if r.attrs["vuln"] == "CVE-2024-0100" {
				holdBacks++
			}
		}
	}
	require.Equal(t, 3, splits, "rows 0-9, then rows 0-4 and 5-9")
	require.Equal(t, 1, holdBacks, "CVE-2024-0100 waits for its later row once")

	summary := runSummary(t, logs)
	require.Equal(t, int64(10), summary.attrs["rows"])
	require.Equal(t, int64(9), summary.attrs["cves"])
	require.Equal(t, int64(8), summary.attrs["llm_calls"])
	require.Equal(t, int64(1), summary.attrs["asked_again"])
	require.Equal(t, int64(3), summary.attrs["splits"])
	require.Equal(t, false, summary.attrs["failed"])
}

// pkg/owasp is 5f797bf's, file for file and byte for byte.
func TestOwaspIsByteIdenticalTo5f797bf(t *testing.T) {
	want := map[string]string{
		"levels.go":      "db7ecc89d8044f339784e57363599ed285c9ec35443c377643052c368afa5eb4",
		"rate.go":        "82735a718163ee58ecb28602b218dc89a4436c05e2b96193138454539fc42e1b",
		"vector.go":      "749189985512f9ecd67b8da08dd9a17a9c228e286fd55752c120aec1a09afe99",
		"mirror_test.go": "2d7303235238f29c9b5a8eb9e6837f51c59116cee92b6e9264230aa37bf8f18c",
		"rate_test.go":   "747a00138ec1dd1caa3b10f1d04aaaa4eeffa82feaa7ac6c4f2342758d23bcde",
		"vector_test.go": "090166e711af3b16c5af62089f2d1da9aec9cd606d935de46e975fb4179676e8",
	}
	entries, err := os.ReadDir(filepath.Join("..", "owasp"))
	require.NoError(t, err)
	got := map[string]string{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join("..", "owasp", e.Name()))
		require.NoError(t, err)
		sum := sha256.Sum256(b)
		got[e.Name()] = hex.EncodeToString(sum[:])
	}
	require.Equal(t, want, got)
}

// recompute rates a published vector from its own 16 levels: OWASP's
// averages, impact the larger of technical and business, score their product.
func recompute(t *testing.T, vector string) (severity string, score float64) {
	t.Helper()
	parts := strings.Split(vector, "/")
	require.Len(t, parts, 16)
	l := make([]float64, 16)
	for i, p := range parts {
		key, level, ok := strings.Cut(p, ":")
		require.True(t, ok)
		require.Equal(t, factors[i].key, key)
		_, err := fmt.Sscan(level, &l[i])
		require.NoError(t, err)
	}
	sum := func(xs []float64) float64 {
		s := 0.0
		for _, x := range xs {
			s += x
		}
		return s
	}
	likelihood, impact := sum(l[0:8])/8, max(sum(l[8:12])/4, sum(l[12:16])/4)
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

// A fixed 16-level reply is published with the vector, severity and score
// 5f797bf's Vector.Rate gives, and the score recomputes from the vector.
func TestGenerator_FixedReplyRatedAs5f797bf(t *testing.T) {
	for _, tc := range []struct {
		levels   owasp.Vector
		vector   string
		severity string
		score    float64
	}{
		// Likelihood 61/8, technical 25/4 above business 19/4.
		{owasp.Vector{SL: 9, M: 4, O: 7, S: 9, ED: 9, EE: 5, A: 9, ID: 9, LC: 6, LI: 5, LAV: 7, LAC: 7, FD: 3, RD: 4, NC: 5, PV: 7},
			"SL:9/M:4/O:7/S:9/ED:9/EE:5/A:9/ID:9/LC:6/LI:5/LAV:7/LAC:7/FD:3/RD:4/NC:5/PV:7", "critical", 47.65625},
		// Likelihood 1, business 7/4 above technical 5/4.
		{lowVector, "SL:1/M:1/O:0/S:2/ED:1/EE:1/A:1/ID:1/LC:2/LI:1/LAV:1/LAC:1/FD:1/RD:1/NC:2/PV:3", "info", 1.75},
		{midVector, "SL:5/M:4/O:4/S:5/ED:3/EE:5/A:4/ID:8/LC:6/LI:5/LAV:5/LAC:7/FD:3/RD:5/NC:5/PV:5", "medium", 27.3125},
	} {
		t.Run(tc.vector, func(t *testing.T) {
			want, err := tc.levels.Rate()
			require.NoError(t, err)
			require.Equal(t, owasp.Rating{Vector: tc.vector, Severity: tc.severity, Score: tc.score}, want)

			m := &scriptedLLM{answer: func(_ int, _ string) llmOutputEntry {
				return llmOutputEntry{Levels: tc.levels, Reasoning: "fixed"}
			}}
			g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
			require.NoError(t, err)
			logs := withCapturedLogs(t)
			var got []outputhandler.VulnRating
			require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(1), func(group []outputhandler.VulnRating) error {
				got = append(got, group...)
				return nil
			}))
			require.Len(t, got, 1)
			r := got[0].Rating
			require.Equal(t, cyclonedx.ScoringMethodOWASP, r.Method)
			require.Equal(t, want.Vector, r.Vector)
			require.Equal(t, cyclonedx.Severity(want.Severity), r.Severity)
			require.NotNil(t, r.Score)
			require.Equal(t, want.Score, *r.Score)

			severity, score := recompute(t, r.Vector)
			require.Equal(t, *r.Score, score, "the score recomputes from its own vector")
			require.Equal(t, string(r.Severity), severity)

			infos := 0
			for _, rec := range logs.records {
				if rec.msg == "Scored vulnerability" {
					infos++
					require.Equal(t, slog.LevelInfo, rec.level)
				}
			}
			require.Equal(t, 1, infos, "every scored row logs its INFO line")
		})
	}
}

// rawLLM answers each call with the raw reply its function gives.
type rawLLM struct {
	calls int
	reply func(call int, ids []string) string
}

func (m *rawLLM) Generate(_ context.Context, req llm.Request) (string, error) {
	var in []struct {
		VulnID string `json:"vulnId"`
	}
	if err := json.Unmarshal([]byte(req.Human), &in); err != nil {
		return "", err
	}
	m.calls++
	ids := make([]string, len(in))
	for i, v := range in {
		ids[i] = v.VulnID
	}
	return m.reply(m.calls, ids), nil
}

// entryWith is midVector's entry for id with field set to the raw JSON value,
// or left out when value is "".
func entryWith(id, field, value string) string {
	b, err := json.Marshal(llmOutputEntry{VulnID: id, Levels: midVector, Reasoning: "mock"})
	if err != nil {
		panic(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		panic(err)
	}
	if value == "" {
		delete(m, field)
	} else {
		m[field] = json.RawMessage(value)
	}
	out, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(out)
}

var invalidLevelCases = []struct {
	name, field, value string
}{
	{"missing", "SL", ""},
	{"null", "SL", "null"},
	{"off its enum", "SL", "2"},
	{"off its enum, out of range", "O", "10"},
	{"off its enum, negative", "LAC", "-1"},
	{"off its enum, a level of another factor", "NC", "9"},
	{"off its enum, an integral decimal", "NC", "6.0"},
	{"off its enum, an integral exponent", "SL", "1e1"},
	{"off its enum, a huge exponent", "LAV", "1e400"},
	{"non-integer", "LI", "5.5"},
	{"non-integer, a fraction just under a level", "EE", "4.9999999999999999"},
	{"non-integer, a fraction just over a level", "EE", "5.0000000000000001"},
	{"non-integer, a fractional exponent form", "EE", "51e-1"},
	{"non-integer, a tiny exponent", "PV", "5e-400"},
	{"non-integer, a string", "PV", `"5"`},
	{"non-integer, a boolean", "FD", "true"},
	{"non-integer, an object", "RD", `{"level":4}`},
}

// An integer-valued JSON number on its factor's enum is that level, whatever
// its decimal or exponent form; nothing is rounded to get there.
func TestGenerator_IntegralNumberFormsAreTheirLevel(t *testing.T) {
	for _, tc := range []struct {
		field, value string
		level        int
	}{
		{"EE", "5.0", 5}, {"EE", "5.000", 5}, {"EE", "5e0", 5}, {"EE", "5E+0", 5}, {"EE", "50e-1", 5},
		{"EE", "0.5e1", 5}, {"EE", "0.00005e5", 5}, {"O", "-0", 0}, {"O", "0.0", 0}, {"O", "0e5", 0},
		{"O", "-0.0e-3", 0}, {"O", "0e99999999999", 0}, {"ID", "8.0", 8}, {"ID", "80E-1", 8},
	} {
		t.Run(tc.field+"="+tc.value, func(t *testing.T) {
			l := levelsOf(midVector)
			i := slices.IndexFunc(factors, func(f factor) bool { return f.key == tc.field })
			l[i] = tc.level
			want := vectorOf(l)
			require.NoError(t, want.Check())

			logs := withCapturedLogs(t)
			entries, err := parseReply(context.Background(), `{"results":[`+entryWith("CVE-2024-0000", tc.field, tc.value)+`]}`)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			require.Equal(t, want, entries[0].Levels)
			for _, r := range logs.records {
				require.NotEqual(t, slog.LevelWarn, r.level)
			}
		})
	}
}

// exactLevel reads a JSON number's exact value, never through a float.
func TestExactLevel(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		level int
		whole bool
	}{
		{"5", 5, true}, {"5.0", 5, true}, {"5e0", 5, true}, {"50e-1", 5, true}, {"0.5e1", 5, true},
		{"0", 0, true}, {"-0", 0, true}, {"0.000", 0, true}, {"0e-7", 0, true}, {"9", 9, true}, {"9.00e0", 9, true},
		{"10", -1, true}, {"1e1", -1, true}, {"-1", -1, true}, {"-5.0", -1, true}, {"90e-1", 9, true},
		{"1e400", -1, true}, {"1e99999999999", -1, true}, {"123456789012345678901234567890", -1, true},
		{"5.5", 0, false}, {"4.9999999999999999", 0, false}, {"5.0000000000000001", 0, false},
		{"49999999999999999e-16", 0, false}, {"5e-1", 0, false}, {"5e-99999999999", 0, false},
		{`"5"`, 0, false}, {"true", 0, false}, {"null", 0, false}, {"05", 0, false}, {"+5", 0, false},
		{".5", 0, false}, {"5.", 0, false}, {"0x5", 0, false}, {"NaN", 0, false}, {"Infinity", 0, false},
	} {
		level, whole := exactLevel([]byte(tc.raw))
		require.Equal(t, tc.whole, whole, tc.raw)
		if whole {
			require.Equal(t, tc.level, level, tc.raw)
		}
	}
}

// Whitespace around a level in the reply's text does not change it.
func TestGenerator_LevelWithWhitespace(t *testing.T) {
	entry := strings.Replace(entryWith("CVE-2024-0000", "SL", "5"), `"SL":5`, "\"SL\" :\n\t 5.0 \n", 1)
	require.Contains(t, entry, "5.0 \n")
	entries, err := parseReply(context.Background(), `{"results":[`+entry+`]}`)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, midVector, entries[0].Levels)
}

// The first entry for a CVE decides: once it is dropped, a later valid entry
// for the same CVE in the reply is skipped, and the CVE is asked again.
func TestGenerator_DroppedFirstEntryDecidesItsCVE(t *testing.T) {
	m := &rawLLM{reply: func(call int, ids []string) string {
		if call == 1 {
			return `{"results":[` + entryWith(ids[0], "SL", "2") + `,` + entryWith(ids[0], "SL", "5") + `]}`
		}
		b, _ := json.Marshal(llmOutput{Results: []llmOutputEntry{{VulnID: ids[0], Levels: highVector, Reasoning: "again"}}})
		return string(b)
	}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)
	logs := withCapturedLogs(t)

	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(1), func(group []outputhandler.VulnRating) error {
		emitted = append(emitted, group...)
		return nil
	}))
	require.Equal(t, 2, m.calls, "the reply's later valid entry does not answer the CVE: it is asked again")
	require.Len(t, emitted, 1)
	require.Equal(t, scoreOf(t, highVector), *emitted[0].Rating.Score, "published from the ask-again")
	drops := 0
	for _, r := range logs.records {
		if strings.HasPrefix(r.msg, "Dropping an answer") {
			drops++
		}
	}
	require.Equal(t, 1, drops, "the skipped entry logs nothing more")
}

// A first entry that passes keeps deciding, as on main, when a later entry
// for the same CVE in the reply is invalid.
func TestGenerator_ValidFirstEntryKeepsItsCVE(t *testing.T) {
	m := &rawLLM{reply: func(_ int, ids []string) string {
		return `{"results":[` + entryWith(ids[0], "SL", "5") + `,` + entryWith(ids[0], "SL", "2") + `]}`
	}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(1), func(group []outputhandler.VulnRating) error {
		emitted = append(emitted, group...)
		return nil
	}))
	require.Equal(t, 1, m.calls)
	require.Len(t, emitted, 1)
	require.Equal(t, scoreOf(t, midVector), *emitted[0].Rating.Score)
}

// An entry whose level is missing, null, off its enum or not an integer is
// dropped at parse and logged at WARN with its CVE and field, nothing
// rounded or snapped; its CVE is asked again once, then fails the run.
func TestGenerator_InvalidLevelDroppedAskedAgainThenFails(t *testing.T) {
	for _, tc := range invalidLevelCases {
		t.Run(tc.name, func(t *testing.T) {
			m := &rawLLM{reply: func(_ int, ids []string) string {
				return `{"results":[` + entryWith(ids[0], tc.field, tc.value) + `]}`
			}}
			g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
			require.NoError(t, err)
			logs := withCapturedLogs(t)

			var emitted []outputhandler.VulnRating
			err = g.GenerateRiskScore(context.Background(), testVulns(1), func(group []outputhandler.VulnRating) error {
				emitted = append(emitted, group...)
				return nil
			})
			require.EqualError(t, err, "model returned no score for CVE-2024-0000 after asking again; stopping the run")
			require.Equal(t, 2, m.calls, "asked once, asked again, then the run fails")
			require.Empty(t, emitted)

			var drops []capturedRecord
			for _, r := range logs.records {
				if strings.HasPrefix(r.msg, "Dropping an answer") {
					drops = append(drops, r)
				}
			}
			require.Len(t, drops, 2, "one WARN per dropped answer")
			for _, r := range drops {
				require.Equal(t, slog.LevelWarn, r.level)
				require.Equal(t, "CVE-2024-0000", r.attrs["vuln"])
				require.Equal(t, tc.field, r.attrs["field"])
			}
		})
	}
}

// A dropped entry's CVE answered validly on the ask-again is published with
// that answer's rating.
func TestGenerator_InvalidLevelThenAnsweredOnTheAskAgain(t *testing.T) {
	for _, tc := range invalidLevelCases {
		t.Run(tc.name, func(t *testing.T) {
			m := &rawLLM{reply: func(call int, ids []string) string {
				if call == 1 {
					return `{"results":[` + entryWith(ids[0], tc.field, tc.value) + `]}`
				}
				b, _ := json.Marshal(llmOutput{Results: []llmOutputEntry{{VulnID: ids[0], Levels: highVector, Reasoning: "again"}}})
				return string(b)
			}}
			g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
			require.NoError(t, err)

			var emitted []outputhandler.VulnRating
			require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(1), func(group []outputhandler.VulnRating) error {
				emitted = append(emitted, group...)
				return nil
			}))
			require.Equal(t, 2, m.calls)
			require.Len(t, emitted, 1)
			require.Equal(t, scoreOf(t, highVector), *emitted[0].Rating.Score)
		})
	}
}

// Only the invalid entry is dropped: the reply's valid entries are kept.
func TestGenerator_InvalidLevelDropsOnlyItsEntry(t *testing.T) {
	m := &rawLLM{reply: func(call int, ids []string) string {
		parts := make([]string, len(ids))
		for i, id := range ids {
			if call == 1 && id == "CVE-2024-0001" {
				parts[i] = entryWith(id, "ID", "4")
				continue
			}
			parts[i] = entryWith(id, "SL", "5")
		}
		return `{"results":[` + strings.Join(parts, ",") + `]}`
	}}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(3), func(group []outputhandler.VulnRating) error {
		emitted = append(emitted, group...)
		return nil
	}))
	require.Equal(t, 2, m.calls, "the batch, then CVE-2024-0001 alone")
	require.Len(t, emitted, 3)
}

// The mock gives every CVE 16 levels, each one of its factor's, the same on
// every call, so a mock run parses with nothing dropped.
func TestMockLLM_SixteenDeterministicLevels(t *testing.T) {
	for i, f := range factors {
		require.Equal(t, f.levels, testutil.FactorLevels[i], f.key)
	}
	mock := testutil.NewMockLLM()
	ids := []string{"CVE-2024-0000", "CVE-2023-44487", "GHSA-xxxx-yyyy-zzzz", "CVE-2019-9192", "CVE-2024-1234"}
	human, err := json.Marshal(func() []LLMVulnerability {
		v := make([]LLMVulnerability, len(ids))
		for i, id := range ids {
			v[i] = LLMVulnerability{VulnID: id}
		}
		return v
	}())
	require.NoError(t, err)
	first, err := mock.Generate(context.Background(), llm.Request{Human: string(human)})
	require.NoError(t, err)
	again, err := mock.Generate(context.Background(), llm.Request{Human: string(human)})
	require.NoError(t, err)
	require.Equal(t, first, again)

	logs := withCapturedLogs(t)
	entries, err := parseReply(context.Background(), first)
	require.NoError(t, err)
	require.Len(t, entries, len(ids))
	distinct := map[owasp.Vector]bool{}
	for i, e := range entries {
		require.Equal(t, ids[i], e.VulnID)
		require.NoError(t, e.Levels.Check())
		want := testutil.DeterministicLevels(ids[i])
		require.Equal(t, want[:], levelsOf(e.Levels))
		require.Equal(t, "Mock LLM: deterministic scores for testing", e.Reasoning)
		distinct[e.Levels] = true
	}
	require.Greater(t, len(distinct), 1, "the levels depend on the vulnId")
	for _, r := range logs.records {
		require.NotEqual(t, slog.LevelWarn, r.level, "nothing dropped")
	}
}

// demoContexts holds the demo scan's three contexts, the YAML of vens-demo's
// contexts/ byte for byte as step 5's runs read them (step-5.md's sha256 in
// TestDemoContextsAreStep5s).
var demoContexts = map[string]string{
	"internet-facing": `# Service A : la MEME image, deployee en frontal internet.
schema_version: 2

project:
  name: "checkout-api"
  description: "Public checkout API handling card payments for the storefront"

context:
  exposure: "internet"
  data_sensitivity: "critical"
  business_criticality: "critical"
  availability_requirement: "critical"

  compliance_requirements:
    - "PCI-DSS"
    - "GDPR"

  audit_requirement: "high"

  # Ce qu un service dans le perimetre PCI-DSS a reellement devant lui.
  controls:
    waf: true
    ddos_protection: true
    ids: true
    siem: true
    edr: true
    antivirus: false
    segmentation: true
    zero_trust: false
  notes: "Accepts unauthenticated traffic on the payment initiation route and parses attacker-controlled JSON."

  # Schema 2. listener vient des notes ci-dessus. Le reste est declare pour la demo (services
  # fictifs), fixe le 18/11/2026 avant de lire un score : ni les notes ni les controles ne l etablissent.
  listener: "present"
  data_subjects: "millions"
  detection:
    network: "logged"
    host: "logged"
    application: "not_logged"
  traceability: "per_request"
`,
	"internal": `# Service B : la MEME image, deployee en batch interne.
schema_version: 2

project:
  name: "nightly-report"
  description: "Internal batch job producing an aggregated sales report"

context:
  exposure: "internal"
  data_sensitivity: "low"
  business_criticality: "low"
  availability_requirement: "low"

  compliance_requirements: []

  audit_requirement: "low"

  # Pas de WAF ni d anti-DDoS : ce job n ecoute sur aucun port.
  controls:
    waf: false
    ddos_protection: false
    ids: true
    siem: true
    edr: true
    antivirus: false
    segmentation: true
    zero_trust: false
  notes: "No ingress and no listening socket. Runs once a night, reads a pre-validated CSV from an internal bucket, writes an aggregate to a private database, then exits."

  # Schema 2. listener vient des notes ci-dessus. Le reste est declare pour la demo (services
  # fictifs), fixe le 18/11/2026 avant de lire un score : ni les notes ni les controles ne l etablissent.
  listener: "absent"
  data_subjects: "none"
  detection:
    network: "logged"
    host: "logged"
    application: "not_logged"
  traceability: "none"
`,
	"internal-api": `# Service C : la MEME image, deployee en API interne.
schema_version: 2

project:
  name: "stock-api"
  description: "Internal REST API that warehouse and support tools query for stock levels"

context:
  exposure: "internal"
  data_sensitivity: "medium"
  business_criticality: "medium"
  availability_requirement: "medium"

  compliance_requirements: []

  audit_requirement: "medium"

  # Pas de WAF ni d anti-DDoS : le service n est joignable que depuis le reseau interne.
  controls:
    waf: false
    ddos_protection: false
    ids: true
    siem: true
    edr: true
    antivirus: false
    segmentation: true
    zero_trust: false
  notes: "Listens on HTTP on the corporate network only: reachable from every employee workstation and internal service, no route from the internet. Callers are not authenticated, so any host on the corporate network can send requests, and the service parses their JSON."

  # Schema 2. listener vient des notes ci-dessus. Le reste est declare pour la demo (services
  # fictifs), fixe le 18/11/2026 avant de lire un score : ni les notes ni les controles ne l etablissent.
  listener: "present"
  data_subjects: "none"
  detection:
    network: "logged"
    host: "logged"
    application: "not_logged"
  traceability: "per_request"
`,
}

// demoContextNames orders demoContexts as the campaign reads them.
var demoContextNames = []string{"internet-facing", "internal", "internal-api"}

func TestDemoContextsAreStep5s(t *testing.T) {
	want := map[string]string{
		"internet-facing": "87040dd9320e83a8c33f55cb35cecb655b61b07f48c7fad86e2af97468a6f49a",
		"internal":        "d23b39a67f72dbbd27082610eb8547d246d1f4890101e40ac903ac052a9062e6",
		"internal-api":    "fd2bd031c8a7de8ef00066d12e45d7b6c647e3a6c3334b8a06bcc34dddc49e80",
	}
	require.Len(t, demoContexts, len(want))
	require.Len(t, demoContextNames, len(want))
	for _, name := range demoContextNames {
		sum := sha256.Sum256([]byte(demoContexts[name]))
		require.Equal(t, want[name], hex.EncodeToString(sum[:]), name)
	}
}
