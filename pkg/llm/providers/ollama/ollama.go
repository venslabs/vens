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

// Package ollama adapts the official Ollama Go API client to the vens llm.Client
// contract using native structured output (the ChatRequest.Format JSON Schema).
package ollama

import (
	"context"
	"fmt"
	"strings"

	"github.com/ollama/ollama/api"

	"github.com/venslabs/vens/pkg/llm"
)

type Client struct {
	api   *api.Client
	model string
}

// New builds a Client for the given model. The underlying api.Client is
// configured from the environment (OLLAMA_HOST, defaulting to
// http://127.0.0.1:11434).
func New(model string) (*Client, error) {
	if model == "" {
		return nil, fmt.Errorf("ollama: model must be non-empty")
	}
	c, err := api.ClientFromEnvironment()
	if err != nil {
		return nil, fmt.Errorf("ollama: client from environment: %w", err)
	}
	return &Client{api: c, model: model}, nil
}

// Generate runs a single chat turn with native structured output and returns
// the model's raw JSON text.
func (c *Client) Generate(ctx context.Context, req llm.Request) (string, error) {
	stream := false

	chatReq := &api.ChatRequest{
		Model: c.model,
		Messages: []api.Message{
			{Role: "system", Content: req.System},
			{Role: "user", Content: req.Human},
		},
		Stream: &stream,
	}
	if len(req.Schema) > 0 {
		chatReq.Format = req.Schema
	}

	chatReq.Options = map[string]any{"temperature": req.Temperature}
	if req.Seed != 0 {
		chatReq.Options["seed"] = req.Seed
	}

	var sb strings.Builder
	var doneReason string
	err := c.api.Chat(ctx, chatReq, func(resp api.ChatResponse) error {
		sb.WriteString(resp.Message.Content)
		if resp.Done {
			doneReason = resp.DoneReason
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("ollama: chat %q: %w", c.model, err)
	}
	if doneReason == "length" {
		return "", fmt.Errorf("ollama: response truncated (done_reason=length): %w", llm.ErrTruncated)
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("ollama: empty response from %q", c.model)
	}

	return sb.String(), nil
}
