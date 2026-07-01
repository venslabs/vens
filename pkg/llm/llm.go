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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// ErrTruncated reports that the model stopped at its output-token limit, leaving
// the structured JSON incomplete. Providers wrap it so the generator can halve
// the batch and retry instead of failing the whole run.
var ErrTruncated = errors.New("llm: response truncated at max output tokens")

// Supported LLM backends and selection helpers
const (
	Auto      = "auto"
	OpenAI    = "openai"
	Ollama    = "ollama"
	Anthropic = "anthropic"
	GoogleAI  = "googleai"
	Mock      = "mock" // For integration testing only
)

// Names lists the supported backend names for help text and validation.
var Names = []string{OpenAI, Ollama, Anthropic, GoogleAI}

func RetryOnRateLimit(ctx context.Context, interval time.Duration, maxRetry int, fn func(context.Context) error) error {
	var err error
	began := time.Now()
	for i := 0; i < maxRetry; i++ {
		err = fn(ctx)
		if !isRateLimit(err) {
			return err
		}
		slog.InfoContext(ctx, "Detected rate limit. Sleeping.", "interval", interval, "error", err)
		time.Sleep(interval)
	}
	elapsed := time.Since(began)
	return fmt.Errorf("still hitting rate limit, after retrying %d times in %v: %w", maxRetry, elapsed, err)
}

// isRateLimit reports whether err looks like a provider or HTTP rate limit.
func isRateLimit(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "429") {
		return false
	}

	// A 429 from any provider is a rate/quota limit, but the wording differs:
	// OpenAI/Anthropic say "rate limit"/"too many requests", Gemini reports
	// "resource_exhausted"/quota.
	return strings.Contains(msg, "rate") ||
		strings.Contains(msg, "quota") ||
		strings.Contains(msg, "exhausted") ||
		strings.Contains(msg, "too many")
}

// defaultModels are used when *_MODEL is unset. They must support native
// structured output (json_schema), since vens enforces a schema on every call.
// vens sets the model explicitly so it can record and log which one ran.
// Ollama has no default.
var defaultModels = map[string]string{
	OpenAI:    "gpt-4o",
	Anthropic: "claude-sonnet-4-5",
	GoogleAI:  "gemini-2.5-flash",
	Mock:      "mock",
}

// ResolveModel returns the provider and model for a backend name. Provider
// defaults to openai; model comes from the provider's *_MODEL env var, falling
// back to defaultModels. defaulted reports that fallback.
func ResolveModel(name string) (provider, model string, defaulted bool) {
	provider = name
	if provider == "" || provider == Auto {
		provider = OpenAI
	}
	switch provider {
	case OpenAI:
		model = os.Getenv("OPENAI_MODEL")
	case Ollama:
		model = os.Getenv("OLLAMA_MODEL")
	case Anthropic:
		model = os.Getenv("ANTHROPIC_MODEL")
	case GoogleAI:
		model = os.Getenv("GOOGLE_MODEL")
	}
	if model == "" {
		model = defaultModels[provider]
		defaulted = true
	}
	return
}
