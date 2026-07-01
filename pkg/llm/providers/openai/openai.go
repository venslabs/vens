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

// Package openai adapts the official OpenAI Go SDK to the vens llm.Client
// contract using native strict structured output (response_format json_schema).
package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/shared"

	"github.com/venslabs/vens/pkg/llm"
)

type Client struct {
	api   openai.Client
	model string
}

// New builds a client from OPENAI_API_KEY (required) and OPENAI_BASE_URL (optional).
func New(model string) (*Client, error) {
	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("openai: OPENAI_API_KEY is not set")
	}

	opts := []option.RequestOption{option.WithAPIKey(key)}
	if base := os.Getenv("OPENAI_BASE_URL"); base != "" {
		opts = append(opts, option.WithBaseURL(base))
	}

	return &Client{api: openai.NewClient(opts...), model: model}, nil
}

// Generate runs a chat completion with native strict structured output and
// returns the model's raw JSON text.
func (c *Client) Generate(ctx context.Context, req llm.Request) (string, error) {
	var schema map[string]any
	if err := json.Unmarshal(req.Schema, &schema); err != nil {
		return "", fmt.Errorf("openai: invalid schema: %w", err)
	}

	params := openai.ChatCompletionNewParams{
		Model: shared.ChatModel(c.model),
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage(req.System),
			openai.UserMessage(req.Human),
		},
		ResponseFormat: openai.ChatCompletionNewParamsResponseFormatUnion{
			OfJSONSchema: &openai.ResponseFormatJSONSchemaParam{
				JSONSchema: openai.ResponseFormatJSONSchemaJSONSchemaParam{
					Name:   "vens_response",
					Schema: schema,
					Strict: openai.Bool(true),
				},
			},
		},
	}
	// Reasoning models (o-series, gpt-5*) reject an explicit temperature and only
	// accept their default; every other model gets it, including 0 for
	// deterministic scoring.
	if !isReasoningModel(c.model) {
		params.Temperature = openai.Float(req.Temperature)
	}
	if req.Seed != 0 {
		params.Seed = openai.Int(int64(req.Seed))
	}

	resp, err := c.api.Chat.Completions.New(ctx, params)
	if err != nil {
		return "", fmt.Errorf("openai: chat completion failed: %w", err)
	}
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("openai: no choices returned")
	}

	choice := resp.Choices[0]
	if choice.Message.Refusal != "" {
		return "", fmt.Errorf("openai: model refused: %s", choice.Message.Refusal)
	}
	if choice.FinishReason == "length" {
		return "", fmt.Errorf("openai: response truncated (finish_reason=length): %w", llm.ErrTruncated)
	}
	if choice.Message.Content == "" {
		return "", fmt.Errorf("openai: empty content (finish_reason=%s)", choice.FinishReason)
	}

	return choice.Message.Content, nil
}

// isReasoningModel reports whether model is an OpenAI reasoning model (o-series or gpt-5*).
func isReasoningModel(model string) bool {
	m := strings.ToLower(model)
	return strings.HasPrefix(m, "o1") || strings.HasPrefix(m, "o3") ||
		strings.HasPrefix(m, "o4") || strings.HasPrefix(m, "gpt-5")
}
