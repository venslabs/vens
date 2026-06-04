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

	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/anthropic"
	"github.com/tmc/langchaingo/llms/googleai"
	"github.com/tmc/langchaingo/llms/ollama"
	"github.com/tmc/langchaingo/llms/openai"
	"github.com/venslabs/vens/internal/testutil"
	"github.com/venslabs/vens/pkg/llm"
)

// New instantiates an LLM client and returns the resolved provider and model,
// so callers can record what ran without resolving twice.
func New(ctx context.Context, name string) (client llms.Model, provider, model string, err error) {
	if name == "" || name == llm.Auto {
		// TODO: add more sophisticated logic
		slog.DebugContext(ctx, "Automatically choosing model", "name", llm.OpenAI)
	}
	var defaulted bool
	provider, model, defaulted = llm.ResolveModel(name)
	if provider == llm.Mock {
		slog.DebugContext(ctx, "Using mock LLM for testing")
		client = testutil.NewMockLLM()
		return
	}
	if defaulted && model != "" {
		slog.WarnContext(ctx, "no model env var set; using the provider default", "provider", provider, "model", model)
	}
	switch provider {
	case llm.OpenAI:
		client, err = openai.New(openai.WithModel(model))
	case llm.Ollama:
		if model == "" {
			err = fmt.Errorf("ollama: set the OLLAMA_MODEL environment variable")
			return
		}
		client, err = ollama.New(ollama.WithModel(model))
	case llm.Anthropic:
		client, err = anthropic.New(anthropic.WithModel(model))
	case llm.GoogleAI:
		client, err = googleai.New(ctx, googleai.WithDefaultModel(model))
	default:
		err = fmt.Errorf("unknown LLM %q, make sure to use one of %v", name, llm.Names)
	}
	return
}
