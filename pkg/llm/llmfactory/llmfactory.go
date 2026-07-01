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

package llmfactory

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/venslabs/vens/internal/testutil"
	"github.com/venslabs/vens/pkg/llm"
	anthropicprov "github.com/venslabs/vens/pkg/llm/providers/anthropic"
	googleprov "github.com/venslabs/vens/pkg/llm/providers/google"
	ollamaprov "github.com/venslabs/vens/pkg/llm/providers/ollama"
	openaiprov "github.com/venslabs/vens/pkg/llm/providers/openai"
)

// New instantiates an LLM client and returns the resolved provider and model,
// so callers can record what ran without resolving twice.
func New(ctx context.Context, name string) (client llm.Client, provider, model string, err error) {
	var defaulted bool
	provider, model, defaulted = llm.ResolveModel(name)
	if provider == llm.Mock {
		slog.DebugContext(ctx, "Using mock LLM for testing")
		return testutil.NewMockLLM(), provider, model, nil
	}
	if defaulted && model != "" {
		slog.WarnContext(ctx, "no model env var set; using the provider default", "provider", provider, "model", model)
	}
	switch provider {
	case llm.OpenAI:
		client, err = openaiprov.New(model)
	case llm.Ollama:
		if model == "" {
			err = fmt.Errorf("ollama: set the OLLAMA_MODEL environment variable")
			return
		}
		client, err = ollamaprov.New(model)
	case llm.Anthropic:
		client, err = anthropicprov.New(model)
	case llm.GoogleAI:
		client, err = googleprov.New(ctx, model)
	default:
		err = fmt.Errorf("unknown LLM %q, make sure to use one of %v", name, llm.Names)
	}
	return
}
