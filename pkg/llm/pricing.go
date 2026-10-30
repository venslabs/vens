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

// CharsPerToken is the rough character-to-token ratio used for cost
// estimation. Four characters per token is the common rule of thumb; it is
// only ever used to drive the --max-spend budget gate, never billing.
const CharsPerToken = 4

// EstimateInputTokens returns a rough input-token count for a prompt: one
// token per CharsPerToken characters. Deliberately an estimate — the point
// is a guardrail so a run can stop before draining a metered API key, not
// an exact bill.
func EstimateInputTokens(text string) int {
	tokens := len(text) / CharsPerToken
	if tokens == 0 && len(text) > 0 {
		tokens = 1
	}
	return tokens
}

// DefaultInputPricePer1K is the conservative fallback price (USD per 1,000
// input tokens) used when the provider/model is unknown.
const DefaultInputPricePer1K = 0.001

// inputPricePer1K holds rough published input prices (USD per 1,000 tokens)
// for each metered backend's typical small model. These are budgeting
// guardrails, not bills: prices move, so treat every value as approximate.
var inputPricePer1K = map[string]float64{
	OpenAI:    0.0006,
	Anthropic: 0.003,
	GoogleAI:  0.00075,
}

// PricePer1KInput returns the rough input price (USD per 1,000 tokens) for a
// provider/model pair. Local (ollama) and test (mock) backends cost nothing
// and return 0, which disables the --max-spend gate. Unknown providers fall
// back to DefaultInputPricePer1K. The model argument is accepted for future
// per-model prices; today pricing is per provider.
func PricePer1KInput(provider, model string) float64 {
	_ = model
	switch provider {
	case Ollama, Mock:
		return 0
	}
	if p, ok := inputPricePer1K[provider]; ok {
		return p
	}
	return DefaultInputPricePer1K
}
