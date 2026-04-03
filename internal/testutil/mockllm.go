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
	"regexp"
	"strconv"

	"github.com/tmc/langchaingo/llms"
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

func (m *MockLLM) GenerateContent(ctx context.Context, messages []llms.MessageContent, options ...llms.CallOption) (*llms.ContentResponse, error) {
	var vulnIDs []string
	for _, msg := range messages {
		if msg.Role == llms.ChatMessageTypeHuman {
			for _, part := range msg.Parts {
				if textPart, ok := part.(llms.TextContent); ok {
					vulnIDs = extractVulnIDs(textPart.Text)
				}
			}
		}
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

	output := llmOutput{Results: results}
	jsonBytes, err := json.Marshal(output)
	if err != nil {
		return nil, err
	}

	opts := llms.CallOptions{}
	for _, opt := range options {
		opt(&opts)
	}
	if opts.StreamingFunc != nil {
		if err := opts.StreamingFunc(ctx, jsonBytes); err != nil {
			return nil, err
		}
	}

	return &llms.ContentResponse{
		Choices: []*llms.ContentChoice{
			{
				Content: string(jsonBytes),
			},
		},
	}, nil
}

func (m *MockLLM) Call(ctx context.Context, prompt string, options ...llms.CallOption) (string, error) {
	resp, err := m.GenerateContent(ctx, []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeHuman, prompt),
	}, options...)
	if err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", nil
	}
	return resp.Choices[0].Content, nil
}

var vulnIDRegex = regexp.MustCompile(`"vulnId"\s*:\s*"([^"]+)"`)

func extractVulnIDs(text string) []string {
	matches := vulnIDRegex.FindAllStringSubmatch(text, -1)
	ids := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			ids = append(ids, match[1])
		}
	}
	return ids
}

func deterministicScores(vulnID string) [4]float64 {
	hash := 0
	for _, c := range vulnID {
		hash = hash*31 + int(c)
	}

	numRegex := regexp.MustCompile(`\d+`)
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
