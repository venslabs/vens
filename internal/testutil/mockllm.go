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
	"hash/fnv"
	"os"
	"slices"
	"strings"

	"github.com/venslabs/vens/pkg/llm"
)

// FailEnv, when set to a non-empty value, makes Generate fail. Integration
// tests use it to exercise error paths that only surface during generation.
const FailEnv = "VENS_MOCK_LLM_FAIL"

// SkipEnv holds comma-separated CVE ids that Generate always leaves out of its
// answer, even when asked again, so integration tests can reach the failure
// for a CVE the model never answers.
const SkipEnv = "VENS_MOCK_LLM_SKIP"

// CannotTellEnv holds comma-separated answer ids: a question whose closed
// answers list one of them is answered cannot_tell for every vulnerability
// it asks about, so that strict-run tests can stop a run at a chosen
// question. cannot_tell itself names every question.
const CannotTellEnv = "VENS_MOCK_LLM_CANNOT_TELL"

const cannotTell = "cannot_tell"

type MockLLM struct{}

func NewMockLLM() *MockLLM {
	return &MockLLM{}
}

// schemaNode is the part of a JSON Schema the mock reads.
type schemaNode struct {
	Type       string                 `json:"type"`
	Properties map[string]*schemaNode `json:"properties"`
	Items      *schemaNode            `json:"items"`
	Enum       []string               `json:"enum"`
}

// Generate answers from the call's JSON Schema alone, deterministically: a
// question's schema lists the vulnerabilities asked and the closed answers,
// and the adjustment's lists each field's answers. It needs no knowledge of
// the prompt's text.
func (m *MockLLM) Generate(_ context.Context, req llm.Request) (string, error) {
	if os.Getenv(FailEnv) != "" {
		return "", errors.New("mockllm: forced failure (" + FailEnv + " is set)")
	}
	var schema schemaNode
	if err := json.Unmarshal(req.Schema, &schema); err != nil {
		return "", fmt.Errorf("mockllm: decode schema: %w", err)
	}
	var reply any
	if answers := schema.Properties["answers"]; answers != nil && answers.Items != nil {
		reply = answerQuestion(answers.Items)
	} else {
		reply = answerAdjustment(schema, req.Human)
	}
	b, err := json.Marshal(reply)
	return string(b), err
}

type answer struct {
	VulnID    string `json:"vulnId"`
	Reasoning string `json:"reasoning"`
	Answer    any    `json:"answer"`
}

// answerQuestion gives each vulnerability the schema asks about, but those
// SkipEnv names, an answer picked from the closed list by a hash of the
// vulnerability and the list: one id, or one or two for a set.
func answerQuestion(item *schemaNode) map[string][]answer {
	answerNode := item.Properties["answer"]
	set := answerNode.Type == "array"
	choices := answerNode.Enum
	if set {
		choices = answerNode.Items.Enum
	}
	skip, forcedIDs := listEnv(SkipEnv), listEnv(CannotTellEnv)
	forced := slices.ContainsFunc(choices, func(id string) bool { return slices.Contains(forcedIDs, id) })
	options := slices.DeleteFunc(slices.Clone(choices), func(id string) bool { return id == cannotTell })

	answers := []answer{}
	for _, id := range item.Properties["vulnId"].Enum {
		if slices.Contains(skip, id) {
			continue
		}
		a := answer{VulnID: id, Reasoning: "Mock LLM: deterministic answer for testing"}
		h := hash(id + "\x00" + strings.Join(choices, ","))
		switch {
		case forced && set:
			a.Answer = []string{cannotTell}
		case forced:
			a.Answer = cannotTell
		case set:
			picked := []string{options[h%uint32(len(options))]}
			if other := options[(h/7)%uint32(len(options))]; h%2 == 1 && other != picked[0] {
				picked = append(picked, other)
			}
			a.Answer = picked
		default:
			a.Answer = options[h%uint32(len(options))]
		}
		answers = append(answers, a)
	}
	return map[string][]answer{"answers": answers}
}

// answerAdjustment fills each field of the adjustment's schema with an
// answer picked from its list by a hash of the request and the field.
func answerAdjustment(schema schemaNode, request string) map[string]string {
	forcedIDs := listEnv(CannotTellEnv)
	out := map[string]string{}
	for name, p := range schema.Properties {
		if len(p.Enum) == 0 {
			out[name] = "Mock LLM: deterministic adjustment for testing"
			continue
		}
		if slices.ContainsFunc(p.Enum, func(id string) bool { return slices.Contains(forcedIDs, id) }) {
			out[name] = cannotTell
			continue
		}
		options := slices.DeleteFunc(slices.Clone(p.Enum), func(id string) bool { return id == cannotTell })
		out[name] = options[hash(request+"\x00"+name)%uint32(len(options))]
	}
	return out
}

func listEnv(name string) []string {
	var out []string
	for _, v := range strings.Split(os.Getenv(name), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func hash(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}
