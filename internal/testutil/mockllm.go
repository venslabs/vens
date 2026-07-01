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

// Package testutil provides test utilities for vens integration tests.
package testutil

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"

	"github.com/venslabs/vens/pkg/llm"
)

type MockLLM struct{}

func NewMockLLM() *MockLLM {
	return &MockLLM{}
}

type llmOutputEntry struct {
	VulnID             string  `json:"vulnId"`
	ThreatAgentScore   float64 `json:"threat_agent_score"`
	VulnerabilityScore float64 `json:"vulnerability_score"`
	TechnicalImpact    float64 `json:"technical_impact"`
	BusinessImpact     float64 `json:"business_impact"`
	Reasoning          string  `json:"reasoning"`
}

type llmOutput struct {
	Results []llmOutputEntry `json:"results"`
}

// Generate returns deterministic scores for every vulnId found in the human
// prompt, so integration tests stay reproducible without a real provider.
func (m *MockLLM) Generate(ctx context.Context, req llm.Request) (string, error) {
	vulnIDs, err := extractVulnIDs(req.Human)
	if err != nil {
		return "", err
	}

	results := make([]llmOutputEntry, 0, len(vulnIDs))
	for _, vulnID := range vulnIDs {
		scores := deterministicScores(vulnID)
		results = append(results, llmOutputEntry{
			VulnID:             vulnID,
			ThreatAgentScore:   scores[0],
			VulnerabilityScore: scores[1],
			TechnicalImpact:    scores[2],
			BusinessImpact:     scores[3],
			Reasoning:          "Mock LLM: deterministic scores for testing",
		})
	}

	jsonBytes, err := json.Marshal(llmOutput{Results: results})
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

var numRegex = regexp.MustCompile(`\d+`)

// extractVulnIDs reads each vulnId from the human prompt. Decoding the JSON
// keeps the mock independent of the prompt's exact text layout.
func extractVulnIDs(human string) ([]string, error) {
	var vulns []struct {
		VulnID string `json:"vulnId"`
	}
	if err := json.Unmarshal([]byte(human), &vulns); err != nil {
		return nil, fmt.Errorf("mockllm: decode human prompt: %w", err)
	}
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		if v.VulnID != "" {
			ids = append(ids, v.VulnID)
		}
	}
	return ids, nil
}

func deterministicScores(vulnID string) [4]float64 {
	hash := 0
	for _, c := range vulnID {
		hash = hash*31 + int(c)
	}

	nums := numRegex.FindAllString(vulnID, -1)
	if len(nums) > 0 {
		if n, err := strconv.Atoi(nums[len(nums)-1]); err == nil {
			hash += n
		}
	}

	base := float64((hash % 6) + 3)
	return [4]float64{
		clamp(base),
		clamp(base + 1),
		clamp(base - 1),
		clamp(base),
	}
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 9 {
		return 9
	}
	return v
}
