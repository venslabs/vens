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
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// truncatingLLM returns llm.ErrTruncated whenever a batch carries more than
// maxPerCall vulnerabilities; smaller batches score normally. maxOK records the
// largest batch that was actually scored, so a test can assert the batch shrank.
type truncatingLLM struct {
	maxPerCall int
	maxOK      int
}

func (m *truncatingLLM) Generate(_ context.Context, req llm.Request) (string, error) {
	var in []struct {
		VulnID string `json:"vulnId"`
	}
	if err := json.Unmarshal([]byte(req.Human), &in); err != nil {
		return "", err
	}
	if len(in) > m.maxPerCall {
		return "", fmt.Errorf("mock truncated: %w", llm.ErrTruncated)
	}
	if len(in) > m.maxOK {
		m.maxOK = len(in)
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

// An oversized batch that the provider truncates is halved and retried until it
// fits, and every CVE still gets scored.
func TestGenerator_AutoSplitsOnTruncation(t *testing.T) {
	m := &truncatingLLM{maxPerCall: 3}
	g, err := New(Opts{LLM: m, Config: &riskconfig.Config{}, BatchSize: 10})
	require.NoError(t, err)

	scored := map[string]bool{}
	h := func(group []outputhandler.VulnRating) error {
		for _, r := range group {
			scored[r.VulnID] = true
		}
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(10), h))

	require.Len(t, scored, 10, "every CVE must be scored after splitting")
	require.LessOrEqual(t, m.maxOK, m.maxPerCall, "successful batches must fit the provider limit")
	require.Greater(t, m.maxOK, 0)
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
