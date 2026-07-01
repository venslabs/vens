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

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/venslabs/vens/pkg/llm"
)

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

const testSchema = `{"type":"object","properties":{"score":{"type":"number"}},"required":["score"],"additionalProperties":false}`

const successBody = `{"id":"cmpl-1","object":"chat.completion","created":0,"model":"gpt-4o",` +
	`"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"{\"score\":7}"}}]}`

// fakeServer serves one canned reply and captures the decoded request body,
// which is populated by the time Generate returns.
func fakeServer(t *testing.T, status int, respBody string) (url string, captured *map[string]any) {
	t.Helper()
	body := map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path = %s, want /chat/completions", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("request body not JSON: %v (%s)", err, raw)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &body
}

func newTestClient(t *testing.T, model, baseURL string) *Client {
	t.Helper()
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("OPENAI_BASE_URL", baseURL)
	c, err := New(model)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// A gpt-4o request carries the strict json_schema, the system/user split, and an
// explicit temperature=0 (the deterministic default) plus a non-zero seed.
func TestGenerate_RequestShape(t *testing.T) {
	url, captured := fakeServer(t, http.StatusOK, successBody)
	c := newTestClient(t, "gpt-4o", url)

	if _, err := c.Generate(context.Background(), llm.Request{
		System:      "you are a scorer",
		Human:       "score this",
		Schema:      json.RawMessage(testSchema),
		Temperature: 0,
		Seed:        42,
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	req := *captured

	if req["model"] != "gpt-4o" {
		t.Errorf("model = %v", req["model"])
	}

	msgs, _ := req["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("messages len = %d", len(msgs))
	}
	sys := msgs[0].(map[string]any)
	usr := msgs[1].(map[string]any)
	if sys["role"] != "system" || sys["content"] != "you are a scorer" {
		t.Errorf("system msg = %v", sys)
	}
	if usr["role"] != "user" || usr["content"] != "score this" {
		t.Errorf("user msg = %v", usr)
	}

	rf := req["response_format"].(map[string]any)
	if rf["type"] != "json_schema" {
		t.Errorf("response_format.type = %v", rf["type"])
	}
	js := rf["json_schema"].(map[string]any)
	if js["name"] != "vens_response" {
		t.Errorf("json_schema.name = %v", js["name"])
	}
	if js["strict"] != true {
		t.Errorf("json_schema.strict = %v", js["strict"])
	}
	var wantSchema map[string]any
	_ = json.Unmarshal([]byte(testSchema), &wantSchema)
	if !reflect.DeepEqual(js["schema"], wantSchema) {
		t.Errorf("schema mismatch:\n got %v\nwant %v", js["schema"], wantSchema)
	}

	// temperature 0 is sent explicitly for non-reasoning models (determinism).
	if temp, ok := req["temperature"]; !ok || temp.(float64) != 0 {
		t.Errorf("temperature = %v (present=%v), want 0", req["temperature"], ok)
	}
	if s, ok := req["seed"]; !ok || s.(float64) != 42 {
		t.Errorf("seed = %v (present=%v), want 42", req["seed"], ok)
	}
}

// Reasoning models must not receive an explicit temperature, and seed is omitted
// when zero.
func TestGenerate_OmitsTemperatureAndSeed(t *testing.T) {
	t.Run("reasoning model omits temperature", func(t *testing.T) {
		url, captured := fakeServer(t, http.StatusOK, successBody)
		c := newTestClient(t, "o3-mini", url)
		if _, err := c.Generate(context.Background(), llm.Request{
			Schema:      json.RawMessage(testSchema),
			Temperature: 0.7,
		}); err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if _, ok := (*captured)["temperature"]; ok {
			t.Error("reasoning model must omit temperature")
		}
	})

	t.Run("zero seed omitted", func(t *testing.T) {
		url, captured := fakeServer(t, http.StatusOK, successBody)
		c := newTestClient(t, "gpt-4o", url)
		if _, err := c.Generate(context.Background(), llm.Request{Schema: json.RawMessage(testSchema)}); err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if _, ok := (*captured)["seed"]; ok {
			t.Error("seed must be omitted when 0")
		}
	})
}

func TestGenerate_Branches(t *testing.T) {
	cases := []struct {
		name          string
		body          string
		wantOut       string
		wantErrSubstr string
		wantTruncated bool
	}{
		{name: "success", body: successBody, wantOut: `{"score":7}`},
		{
			name:          "truncation",
			body:          `{"choices":[{"index":0,"finish_reason":"length","message":{"role":"assistant","content":"{\"score\":7"}}]}`,
			wantErrSubstr: "finish_reason=length",
			wantTruncated: true,
		},
		{
			name:          "refusal",
			body:          `{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","refusal":"I cannot help with that","content":""}}]}`,
			wantErrSubstr: "model refused: I cannot help with that",
		},
		{
			name:          "empty content",
			body:          `{"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":""}}]}`,
			wantErrSubstr: "empty content (finish_reason=stop)",
		},
		{
			name:          "no choices",
			body:          `{"id":"cmpl-1","object":"chat.completion","choices":[]}`,
			wantErrSubstr: "no choices returned",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url, _ := fakeServer(t, http.StatusOK, tc.body)
			c := newTestClient(t, "gpt-4o", url)
			out, err := c.Generate(context.Background(), llm.Request{
				System: "s", Human: "h", Schema: json.RawMessage(testSchema),
			})
			if tc.wantErrSubstr == "" {
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if out != tc.wantOut {
					t.Errorf("out = %q, want %q", out, tc.wantOut)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErrSubstr)
			}
			if !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Errorf("err = %q, want substring %q", err.Error(), tc.wantErrSubstr)
			}
			if got := errors.Is(err, llm.ErrTruncated); got != tc.wantTruncated {
				t.Errorf("errors.Is(ErrTruncated) = %v, want %v", got, tc.wantTruncated)
			}
		})
	}
}
