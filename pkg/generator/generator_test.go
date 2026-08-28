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
// missing at exit code 0.
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
	require.Empty(t, emitted, "an incomplete batch must not reach the VEX")
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
