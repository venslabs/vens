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
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/internal/testutil"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// A budget below the cost of a single call stops the run before the first
// LLM call: no output is emitted and the error states the spend and the cap.
func TestGenerator_MaxSpendStopsRun(t *testing.T) {
	m := testutil.NewMockLLM()
	g, err := New(Opts{
		LLM:      m,
		Config:   &riskconfig.Config{},
		Provider: llm.OpenAI,
		Model:    "gpt-5.4-mini",
		MaxSpend: 0.000000001,
	})
	require.NoError(t, err)

	var emitted []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		emitted = append(emitted, group...)
		return nil
	}

	err = g.GenerateRiskScore(context.Background(), testVulns(5), h)
	require.Error(t, err)

	var budgetErr *BudgetExceededError
	require.True(t, errors.As(err, &budgetErr), "expected a *BudgetExceededError, got: %v", err)
	require.Equal(t, 0.000000001, budgetErr.Limit)
	require.Equal(t, 0.0, budgetErr.Spent)
	require.Contains(t, err.Error(), "LLM spend budget exceeded")
	require.Empty(t, emitted, "no output must be emitted once the budget is hit")
}

// A budget comfortably above the run's cost lets the run finish unchanged.
func TestGenerator_MaxSpendAllowsRunWithinBudget(t *testing.T) {
	g, err := New(Opts{
		LLM:      testutil.NewMockLLM(),
		Config:   &riskconfig.Config{},
		Provider: llm.OpenAI,
		Model:    "gpt-5.4-mini",
		MaxSpend: 1000,
	})
	require.NoError(t, err)

	var emitted []outputhandler.VulnRating
	h := func(group []outputhandler.VulnRating) error {
		emitted = append(emitted, group...)
		return nil
	}

	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(3), h))
	require.Len(t, emitted, 3)
}

// Local and test backends are not metered: the gate stays inert however
// small the cap, so --max-spend never breaks ollama or mock runs.
func TestGenerator_MaxSpendIgnoresFreeBackends(t *testing.T) {
	for _, backend := range []string{llm.Ollama, llm.Mock} {
		g, err := New(Opts{
			LLM:      testutil.NewMockLLM(),
			Config:   &riskconfig.Config{},
			Provider: backend,
			MaxSpend: 0.000000001,
		})
		require.NoError(t, err)

		var emitted []outputhandler.VulnRating
		h := func(group []outputhandler.VulnRating) error {
			emitted = append(emitted, group...)
			return nil
		}
		require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(3), h), "backend %s", backend)
		require.Len(t, emitted, 3)
	}
}
