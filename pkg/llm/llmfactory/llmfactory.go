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

// This implementation is adapted from github.com/AkihiroSuda/vexllm/pkg/llm/llmfactory

package llmfactory

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/anthropic"
	"github.com/tmc/langchaingo/llms/googleai"
	"github.com/tmc/langchaingo/llms/ollama"
	"github.com/tmc/langchaingo/llms/openai"
	"github.com/venslabs/vens/pkg/llm"
)

// New instantiates an LLM.
func New(ctx context.Context, name string) (llms.Model, error) {
	switch name {
	case "", llm.Auto:
		// TODO: add more sophisticated logic
		slog.DebugContext(ctx, "Automatically choosing model", "name", llm.OpenAI)
		name = llm.OpenAI
	}
	switch name {
	case llm.OpenAI:
		return openai.New()
	case llm.Ollama:
		var ollamaModel string
		ollamaModel = os.Getenv("OLLAMA_MODEL")
		return ollama.New(ollama.WithModel(ollamaModel))
	case llm.Anthropic:
		var anthropicModel string
		anthropicModel = os.Getenv("ANTHROPIC_MODEL")
		if anthropicModel != "" {
			return anthropic.New(anthropic.WithModel(anthropicModel))
		}
		return anthropic.New()
	case llm.GoogleAI:
		var defaultModel string
		defaultModel = os.Getenv("GOOGLE_MODEL")
		return googleai.New(ctx, googleai.WithDefaultModel(defaultModel))
	default:
		return nil, fmt.Errorf("unknown LLM %q, make sure to use one of %v", name, llm.Names)
	}
}
