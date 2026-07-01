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

package openai

import "testing"

func TestIsReasoningModel(t *testing.T) {
	cases := map[string]bool{
		// reasoning models reject an explicit temperature
		"o1":         true,
		"o1-mini":    true,
		"o3":         true,
		"o3-mini":    true,
		"o4-mini":    true,
		"gpt-5":      true,
		"gpt-5-mini": true,
		// chat models take temperature=0 for deterministic scoring
		"gpt-4o":        false,
		"gpt-4o-mini":   false,
		"gpt-4.1":       false,
		"gpt-4-turbo":   false,
		"gpt-3.5-turbo": false,
		"":              false,
	}
	for model, want := range cases {
		if got := isReasoningModel(model); got != want {
			t.Errorf("isReasoningModel(%q) = %v, want %v", model, got, want)
		}
	}
}
