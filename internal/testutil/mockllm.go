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
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/venslabs/vens/pkg/llm"
)

// FailEnv, when set to a non-empty value, makes Generate fail. Integration
// tests use it to exercise error paths that only surface during generation.
const FailEnv = "VENS_MOCK_LLM_FAIL"

// SkipEnv holds comma-separated CVE ids that Generate always leaves out of its
// answer, even when asked again, so integration tests can reach the failure
// for a CVE the model never scores.
const SkipEnv = "VENS_MOCK_LLM_SKIP"

type MockLLM struct{}

func NewMockLLM() *MockLLM {
	return &MockLLM{}
}

// llmOutputEntry is one result of the generator's schema: the vulnId, the 16
// factor levels in the vector's order, then the reasoning.
type llmOutputEntry struct {
	VulnID    string `json:"vulnId"`
	SL        int    `json:"SL"`
	M         int    `json:"M"`
	O         int    `json:"O"`
	S         int    `json:"S"`
	ED        int    `json:"ED"`
	EE        int    `json:"EE"`
	A         int    `json:"A"`
	ID        int    `json:"ID"`
	LC        int    `json:"LC"`
	LI        int    `json:"LI"`
	LAV       int    `json:"LAV"`
	LAC       int    `json:"LAC"`
	FD        int    `json:"FD"`
	RD        int    `json:"RD"`
	NC        int    `json:"NC"`
	PV        int    `json:"PV"`
	Reasoning string `json:"reasoning"`
}

// FactorLevels holds each factor's distinct levels in the vector's order
// (SL, M, O, S, ED, EE, A, ID, LC, LI, LAV, LAC, FD, RD, NC, PV): those of
// pkg/owasp's levels.go, the enums of the generator's schema.
var FactorLevels = [16][]int{
	{1, 3, 5, 6, 9},
	{1, 4, 9},
	{0, 4, 7, 9},
	{2, 4, 5, 6, 9},
	{1, 3, 7, 9},
	{1, 3, 5, 9},
	{1, 4, 6, 9},
	{1, 3, 8, 9},
	{2, 6, 7, 9},
	{1, 3, 5, 7, 9},
	{1, 5, 7, 9},
	{1, 7, 9},
	{1, 3, 7, 9},
	{1, 4, 5, 9},
	{2, 5, 7},
	{3, 5, 7, 9},
}

type llmOutput struct {
	Results []llmOutputEntry `json:"results"`
}

// Generate returns 16 deterministic levels for every vulnId found in the human
// prompt except those named in SkipEnv, so integration tests stay reproducible
// without a real provider.
func (m *MockLLM) Generate(ctx context.Context, req llm.Request) (string, error) {
	if os.Getenv(FailEnv) != "" {
		return "", errors.New("mockllm: forced failure (" + FailEnv + " is set)")
	}

	vulnIDs, err := extractVulnIDs(req.Human)
	if err != nil {
		return "", err
	}

	skip := map[string]bool{}
	for _, id := range strings.Split(os.Getenv(SkipEnv), ",") {
		skip[strings.TrimSpace(id)] = true
	}

	results := make([]llmOutputEntry, 0, len(vulnIDs))
	for _, vulnID := range vulnIDs {
		if skip[vulnID] {
			continue
		}
		l := DeterministicLevels(vulnID)
		results = append(results, llmOutputEntry{
			VulnID: vulnID,
			SL:     l[0], M: l[1], O: l[2], S: l[3],
			ED: l[4], EE: l[5], A: l[6], ID: l[7],
			LC: l[8], LI: l[9], LAV: l[10], LAC: l[11],
			FD: l[12], RD: l[13], NC: l[14], PV: l[15],
			Reasoning: "Mock LLM: deterministic scores for testing",
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

// DeterministicLevels gives a vulnId its 16 levels, each one of its factor's
// FactorLevels, picked from the same hash of the vulnId the mock has always used.
func DeterministicLevels(vulnID string) [16]int {
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

	// The hash can overflow to a negative value: keep each index in range.
	var out [16]int
	for i, levels := range FactorLevels {
		n := len(levels)
		out[i] = levels[((hash+i)%n+n)%n]
	}
	return out
}
