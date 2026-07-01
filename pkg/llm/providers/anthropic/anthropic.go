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

// Package anthropic adapts the official Anthropic Go SDK to the vens llm.Client
// contract using native structured output (output_config.format, GA).
package anthropic

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	sdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/packages/param"

	"github.com/venslabs/vens/pkg/llm"
)

// Anthropic requires max_tokens. 16384 leaves headroom for a default batch of
// CVEs; if the model still stops at max_tokens, Generate errors so the caller
// can retry with a smaller batch.
const defaultMaxTokens = 16384

type Client struct {
	client sdk.Client
	model  string
}

// New builds a client from ANTHROPIC_API_KEY.
func New(model string) (*Client, error) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("anthropic: ANTHROPIC_API_KEY is not set")
	}
	return &Client{
		client: sdk.NewClient(option.WithAPIKey(key)),
		model:  model,
	}, nil
}

// Generate forces the response to conform to req.Schema using Anthropic's native
// structured output and returns the model's raw JSON text. Anthropic has no seed
// parameter, so req.Seed is ignored (vens still records it in its attestation).
func (c *Client) Generate(ctx context.Context, req llm.Request) (string, error) {
	var schema map[string]any
	if err := json.Unmarshal(req.Schema, &schema); err != nil {
		return "", fmt.Errorf("anthropic: invalid schema: %w", err)
	}

	params := sdk.MessageNewParams{
		Model:     sdk.Model(c.model),
		MaxTokens: defaultMaxTokens,
		System:    []sdk.TextBlockParam{{Text: req.System}},
		Messages: []sdk.MessageParam{
			sdk.NewUserMessage(sdk.NewTextBlock(req.Human)),
		},
		OutputConfig: sdk.OutputConfigParam{
			Format: sdk.JSONOutputFormatParam{Schema: schema},
		},
	}
	params.Temperature = param.NewOpt(req.Temperature)

	msg, err := c.client.Messages.New(ctx, params)
	if err != nil {
		return "", fmt.Errorf("anthropic: message failed: %w", err)
	}
	if msg.StopReason == sdk.StopReasonMaxTokens {
		return "", fmt.Errorf("anthropic: response truncated (stop_reason=max_tokens): %w", llm.ErrTruncated)
	}

	for _, block := range msg.Content {
		if block.Type == "text" {
			return block.Text, nil
		}
	}
	return "", fmt.Errorf("anthropic: no text content block in response")
}
