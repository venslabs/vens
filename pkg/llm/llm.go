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
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Supported LLM backends and selection helpers
const (
	Auto      = "auto"
	OpenAI    = "openai"
	Ollama    = "ollama"
	Anthropic = "anthropic"
	GoogleAI  = "googleai"
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

// IsRateLimit returns true if the error looks like a provider or HTTP rate limit.
// TODO: Maybe add a check to langchaingo upstream so everyone can benefit from this mechanism.
func isRateLimit(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())

	if strings.Contains(msg, "status code: 429") || strings.Contains(msg, "Error 429:") {
		return true
	}

	// Heuristic: if it mentions 429 anywhere together with "rate",
	// consider it a rate limit.
	if strings.Contains(msg, "429") && (strings.Contains(msg, "rate")) {
		return true
	}

	return false
}
