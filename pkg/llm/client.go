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
	"context"
	"encoding/json"
)

// Request is a single structured-output LLM call.
type Request struct {
	System string
	Human  string
	// Schema is the JSON Schema the response must satisfy. Each provider
	// enforces it natively (OpenAI response_format, Anthropic output_config,
	// Gemini responseJsonSchema, Ollama format).
	Schema json.RawMessage
	// Temperature, including 0, is forwarded to keep scoring deterministic,
	// except where the provider rejects an explicit value (OpenAI reasoning models).
	Temperature float64
	// Seed is applied only when non-zero. Providers without a seed parameter
	// (e.g. Anthropic) ignore it.
	Seed int
}

// Client is the minimal LLM surface vens needs: one structured-output call
// returning the model's raw JSON response.
type Client interface {
	Generate(ctx context.Context, req Request) (string, error)
}
