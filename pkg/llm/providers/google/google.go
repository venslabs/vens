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

// Package google adapts the official Google Gen AI SDK (google.golang.org/genai)
// to the vens llm.Client contract, forcing native structured output via the raw
// JSON Schema path (ResponseJsonSchema), which supports additionalProperties.
package google

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"google.golang.org/genai"

	"github.com/venslabs/vens/pkg/llm"
)

type Client struct {
	genai *genai.Client
	model string
}

// New builds a Client against the Gemini Developer API. It reads GOOGLE_API_KEY,
// falling back to GEMINI_API_KEY, and errors if neither is set.
func New(ctx context.Context, model string) (*Client, error) {
	apiKey := os.Getenv("GOOGLE_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("google: set GOOGLE_API_KEY or GEMINI_API_KEY")
	}

	gc, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return nil, fmt.Errorf("google: create client: %w", err)
	}

	return &Client{genai: gc, model: model}, nil
}

// Generate runs the request with native structured output and returns the
// model's raw JSON text.
func (c *Client) Generate(ctx context.Context, req llm.Request) (string, error) {
	cfg := &genai.GenerateContentConfig{
		ResponseMIMEType: "application/json",
	}

	if len(req.Schema) > 0 {
		var schema any
		if err := json.Unmarshal(req.Schema, &schema); err != nil {
			return "", fmt.Errorf("google: invalid schema: %w", err)
		}
		cfg.ResponseJsonSchema = schema
	}

	if req.System != "" {
		// SystemInstruction is a dedicated system turn; its role is ignored.
		cfg.SystemInstruction = genai.NewContentFromText(req.System, "")
	}
	cfg.Temperature = genai.Ptr(float32(req.Temperature))
	if req.Seed != 0 {
		cfg.Seed = genai.Ptr(int32(req.Seed))
	}

	resp, err := c.genai.Models.GenerateContent(ctx, c.model, genai.Text(req.Human), cfg)
	if err != nil {
		return "", fmt.Errorf("google: generate content: %w", err)
	}
	if len(resp.Candidates) > 0 && resp.Candidates[0].FinishReason == genai.FinishReasonMaxTokens {
		return "", fmt.Errorf("google: response truncated (finish_reason=MAX_TOKENS): %w", llm.ErrTruncated)
	}

	text := resp.Text()
	if text == "" {
		// No text: either the prompt was blocked (no candidate at all, reason in
		// PromptFeedback) or a candidate stopped early (reason in its finish_reason,
		// e.g. SAFETY). Report whichever applies.
		reason := "no candidates"
		switch {
		case resp.PromptFeedback != nil && resp.PromptFeedback.BlockReason != "":
			reason = "prompt_blocked=" + string(resp.PromptFeedback.BlockReason)
		case len(resp.Candidates) > 0 && resp.Candidates[0].FinishReason != "":
			reason = "finish_reason=" + string(resp.Candidates[0].FinishReason)
		}
		return "", fmt.Errorf("google: empty response (%s)", reason)
	}

	return text, nil
}
