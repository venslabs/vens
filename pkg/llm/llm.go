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
