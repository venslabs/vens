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
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

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

const defaultBaseURL = "https://api.anthropic.com/"

// New builds a client from ANTHROPIC_API_KEY.
func New(model string) (*Client, error) {
	return newClient(model)
}

// newClient applies extra options last so tests can observe the base URL the
// SDK ends up with.
func newClient(model string, extra ...option.RequestOption) (*Client, error) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("anthropic: ANTHROPIC_API_KEY is not set")
	}
	// The SDK reads ANTHROPIC_BASE_URL through LookupEnv, which reports a variable
	// set to the empty string as present, so anything exporting it unconditionally
	// sends requests to "/v1/messages" with no host. Always pass a base URL.
	opts := []option.RequestOption{
		option.WithAPIKey(key),
		option.WithBaseURL(resolveBaseURL(os.Getenv("ANTHROPIC_BASE_URL"))),
	}
	return &Client{
		client: sdk.NewClient(append(opts, extra...)...),
		model:  model,
	}, nil
}

func resolveBaseURL(env string) string {
	if env == "" {
		return defaultBaseURL
	}
	return env
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
	if req.Temperature != nil && modelRefusesTemperature(c.model) {
		return "", fmt.Errorf("anthropic: %q refuses an explicit temperature: omit --llm-temperature for this model", c.model)
	}
	if req.Temperature != nil {
		params.Temperature = param.NewOpt(*req.Temperature)
	}

	msg, err := c.client.Messages.New(ctx, params)
	if err != nil {
		if req.Temperature != nil && temperatureDeprecated(err) {
			// Unknown model, or a stale refuse-list: the API refused the
			// explicit temperature. Fail with a clear message instead of
			// retrying without it.
			return "", fmt.Errorf("anthropic: %q refused the explicit --llm-temperature: omit the flag for this model", c.model)
		}
		if detail, ok := unsupportedStructuredOutput(err); ok {
			return "", fmt.Errorf("anthropic: %q: %w, see docs/concepts/choosing-a-model.md (%s)",
				c.model, llm.ErrUnsupportedStructuredOutput, detail)
		}
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

// temperatureRefusingModels lists Anthropic model generations known to reject
// an explicit temperature parameter outright ("`temperature` is deprecated for
// this model."). Anthropic's capabilities object carries no temperature key,
// and adjacent generations (sonnet-4-6 vs sonnet-5) report identical
// capabilities while differing on temperature, so a best-effort list is the
// only way to fail fast. A model missing from the list still fails with a
// clear error after its first refused call instead of retrying.
var temperatureRefusingModels = []string{
	// Current generation; e.g. claude-sonnet-5. Extend as new generations
	// confirm they refuse an explicit temperature.
	"sonnet-5",
	"opus-4-7",
	"opus-4-8",
	"opus-5",
	"opus-5-5",
	"fable",
}

// modelRefusesTemperature reports whether model is a known temperature refuser.
//
// TODO: move this into a shared helper package so every provider can reuse the
// same model-refusal list (follow-up ticket).
func modelRefusesTemperature(model string) bool {
	m := strings.ToLower(model)
	for _, known := range temperatureRefusingModels {
		if strings.Contains(m, known) {
			return true
		}
	}
	return false
}

// temperatureDeprecated reports whether err is the API refusing an explicit
// temperature parameter. Current model generations (e.g. claude-sonnet-5)
// reject it with a 400 instead of ignoring it; the caller fails with a clear
// error rather than retrying with the parameter omitted.
func temperatureDeprecated(err error) bool {
	var apiErr *sdk.Error
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		return false
	}
	var body struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(apiErr.RawJSON()), &body) != nil {
		return false
	}
	return strings.Contains(body.Error.Message, "`temperature` is deprecated for this model.")
}

func unsupportedStructuredOutput(err error) (string, bool) {
	var apiErr *sdk.Error
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		return "", false
	}
	var body struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(apiErr.RawJSON()), &body) != nil {
		return "", false
	}
	for _, s := range []string{"output_config", "structured output"} {
		if strings.Contains(strings.ToLower(body.Error.Message), s) {
			return body.Error.Message, true
		}
	}
	return "", false
}
