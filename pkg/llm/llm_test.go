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

package llm

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveModel(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		env           map[string]string
		wantProvider  string
		wantModel     string
		wantDefaulted bool
	}{
		{name: "openai from env", input: OpenAI, env: map[string]string{"OPENAI_MODEL": "gpt-4o"}, wantProvider: OpenAI, wantModel: "gpt-4o"},
		{name: "auto resolves to openai from env", input: Auto, env: map[string]string{"OPENAI_MODEL": "gpt-4o"}, wantProvider: OpenAI, wantModel: "gpt-4o"},
		{name: "empty resolves to openai from env", input: "", env: map[string]string{"OPENAI_MODEL": "gpt-4o"}, wantProvider: OpenAI, wantModel: "gpt-4o"},
		{name: "openai unset falls back to default", input: OpenAI, wantProvider: OpenAI, wantModel: "gpt-5.4-mini", wantDefaulted: true},
		{name: "anthropic unset falls back to default", input: Anthropic, wantProvider: Anthropic, wantModel: "claude-sonnet-4-6", wantDefaulted: true},
		{name: "googleai unset falls back to default", input: GoogleAI, wantProvider: GoogleAI, wantModel: "gemini-2.5-flash", wantDefaulted: true},
		{name: "ollama from env", input: Ollama, env: map[string]string{"OLLAMA_MODEL": "llama3.1"}, wantProvider: Ollama, wantModel: "llama3.1"},
		{name: "ollama unset has no default", input: Ollama, wantProvider: Ollama, wantModel: "", wantDefaulted: true},
		{name: "mock", input: Mock, wantProvider: Mock, wantModel: "mock", wantDefaulted: true},
		{name: "unknown passes through with empty model", input: "bogus", wantProvider: "bogus", wantModel: "", wantDefaulted: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Isolate env: clear all model vars, then apply the case's.
			for _, k := range []string{"OPENAI_MODEL", "OLLAMA_MODEL", "ANTHROPIC_MODEL", "GOOGLE_MODEL"} {
				t.Setenv(k, "")
			}
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			provider, model, defaulted := ResolveModel(tt.input)
			assert.Equal(t, tt.wantProvider, provider)
			assert.Equal(t, tt.wantModel, model)
			assert.Equal(t, tt.wantDefaulted, defaulted)
		})
	}
}

func TestIsRateLimit(t *testing.T) {
	tests := []struct {
		name string
		err  string
		want bool
	}{
		{name: "openai 429", err: `POST "https://api.openai.com/v1/chat/completions": 429 Too Many Requests {"error":{"type":"rate_limit_exceeded"}}`, want: true},
		{name: "anthropic 429", err: `POST "https://api.anthropic.com/v1/messages": 429 {"type":"error","error":{"type":"rate_limit_error"}}`, want: true},
		{name: "gemini 429 resource exhausted", err: `Error 429, Message: Resource has been exhausted (e.g. check quota)., Status: 429 Too Many Requests, Details: []`, want: true},
		{name: "ollama 429 too many", err: `server busy: 429 too many requests`, want: true},
		{name: "500 is not a rate limit", err: `500 Internal Server Error`, want: false},
		{name: "401 is not a rate limit", err: `401 Unauthorized: invalid api key`, want: false},
		{name: "bare 429 in a vuln id is not enough", err: `failed parsing CVE-2024-429: missing field`, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isRateLimit(errors.New(tt.err)))
		})
	}
	assert.False(t, isRateLimit(nil))
}

func TestModelRefusesTemperature(t *testing.T) {
	tests := []struct {
		name  string
		model string
		want  bool
	}{
		{name: "sonnet-5", model: "claude-sonnet-5", want: true},
		{name: "opus-4-7", model: "claude-opus-4-7", want: true},
		{name: "opus-5", model: "claude-opus-5", want: true},
		{name: "aws opus-4-8", model: "us.anthropic.claude-opus-4-8-v1:0", want: true},
		{name: "opus-5-5", model: "claude-opus-5-5", want: true},
		{name: "fable-5-1", model: "claude-fable-5-1", want: true},
		{name: "uppercase sonnet-5", model: "CLAUDE-SONNET-5", want: true},
		{name: "sonnet-4-6", model: "claude-sonnet-4-6", want: false},
		{name: "dated opus-4-5", model: "claude-opus-4-5-20251101", want: false},
		// OpenAI reasoning models refuse an explicit temperature; the ids
		// match by prefix (#351).
		{name: "o1", model: "o1", want: true},
		{name: "o1-mini", model: "o1-mini", want: true},
		{name: "o3-mini", model: "o3-mini", want: true},
		{name: "o4-mini", model: "o4-mini", want: true},
		{name: "gpt-5", model: "gpt-5", want: true},
		{name: "gpt-5-mini", model: "gpt-5-mini", want: true},
		{name: "uppercase o1-mini", model: "O1-MINI", want: true},
		// Prefix, not substring: ollama's marco-o1 takes a temperature.
		{name: "ollama marco-o1", model: "marco-o1", want: false},
		{name: "gpt-4o", model: "gpt-4o", want: false},
		{name: "gpt-4.1", model: "gpt-4.1", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ModelRefusesTemperature(tt.model))
		})
	}
}
