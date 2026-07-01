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

package google

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

const testModel = "gemini-2.5-flash"

type recordedReq struct {
	path   string
	apiKey string
	body   map[string]any
}

func newTestServer(t *testing.T, status int, respBody string, rec *recordedReq) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rec != nil {
			rec.path = r.URL.Path
			rec.apiKey = r.Header.Get("x-goog-api-key")
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &rec.body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newTestClient points the genai SDK at the fake server via GOOGLE_GEMINI_BASE_URL.
// t.Setenv forbids t.Parallel in these tests.
func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	t.Setenv("GOOGLE_API_KEY", "test-key")
	t.Setenv("GOOGLE_GEMINI_BASE_URL", baseURL)
	c, err := New(context.Background(), testModel)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func firstPartText(content map[string]any) string {
	if content == nil {
		return ""
	}
	parts, _ := content["parts"].([]any)
	if len(parts) == 0 {
		return ""
	}
	p, _ := parts[0].(map[string]any)
	s, _ := p["text"].(string)
	return s
}

// The outgoing request carries the schema in responseJsonSchema, the system
// instruction, an explicit temperature=0 and a non-zero seed.
func TestGenerate_RequestShape(t *testing.T) {
	var rec recordedReq
	success := `{"candidates":[{"content":{"parts":[{"text":"{\"ok\":true}"}],"role":"model"},"finishReason":"STOP"}]}`
	srv := newTestServer(t, http.StatusOK, success, &rec)
	c := newTestClient(t, srv.URL)

	schema := json.RawMessage(`{"type":"object","properties":{"ok":{"type":"boolean"}},"additionalProperties":false}`)
	req := llm.Request{System: "you are a scanner", Human: "score CVE-2021-1234", Schema: schema, Temperature: 0, Seed: 42}

	got, err := c.Generate(context.Background(), req)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if got != `{"ok":true}` {
		t.Fatalf("got %q", got)
	}

	if !strings.HasSuffix(rec.path, ":generateContent") || !strings.Contains(rec.path, "models/"+testModel) {
		t.Fatalf("unexpected path %q", rec.path)
	}
	if rec.apiKey != "test-key" {
		t.Fatalf("x-goog-api-key = %q", rec.apiKey)
	}

	gen, _ := rec.body["generationConfig"].(map[string]any)
	if gen == nil {
		t.Fatal("missing generationConfig")
	}
	if gen["responseMimeType"] != "application/json" {
		t.Fatalf("responseMimeType = %v", gen["responseMimeType"])
	}
	var wantSchema any
	_ = json.Unmarshal(schema, &wantSchema)
	if !reflect.DeepEqual(gen["responseJsonSchema"], wantSchema) {
		t.Fatalf("responseJsonSchema = %#v", gen["responseJsonSchema"])
	}
	if gen["temperature"] != float64(0) {
		t.Fatalf("temperature = %v", gen["temperature"])
	}
	if gen["seed"] != float64(42) {
		t.Fatalf("seed = %v", gen["seed"])
	}

	sys, _ := rec.body["systemInstruction"].(map[string]any)
	if txt := firstPartText(sys); txt != "you are a scanner" {
		t.Fatalf("systemInstruction text = %q", txt)
	}
	contents, _ := rec.body["contents"].([]any)
	if len(contents) == 0 {
		t.Fatal("missing contents")
	}
	first, _ := contents[0].(map[string]any)
	if first["role"] != "user" {
		t.Fatalf("role = %v", first["role"])
	}
	if txt := firstPartText(first); txt != "score CVE-2021-1234" {
		t.Fatalf("human text = %q", txt)
	}
}

func TestGenerate_SeedOmittedWhenZero(t *testing.T) {
	var rec recordedReq
	srv := newTestServer(t, http.StatusOK, `{"candidates":[{"content":{"parts":[{"text":"{}"}]},"finishReason":"STOP"}]}`, &rec)
	c := newTestClient(t, srv.URL)
	if _, err := c.Generate(context.Background(), llm.Request{Human: "hi", Seed: 0}); err != nil {
		t.Fatal(err)
	}
	gen, _ := rec.body["generationConfig"].(map[string]any)
	if _, ok := gen["seed"]; ok {
		t.Fatal("seed must be omitted when req.Seed == 0")
	}
	if _, ok := gen["temperature"]; !ok {
		t.Fatal("temperature must be present even at 0")
	}
}

func TestGenerate_Branches(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		want      string
		wantErr   string
		wantTrunc bool
	}{
		{name: "success", status: 200, body: `{"candidates":[{"content":{"parts":[{"text":"{\"a\":1}"}]},"finishReason":"STOP"}]}`, want: `{"a":1}`},
		{name: "truncated", status: 200, body: `{"candidates":[{"finishReason":"MAX_TOKENS","content":{"parts":[{"text":"{\"a\":"}]}}]}`, wantTrunc: true},
		{name: "no candidates", status: 200, body: `{}`, wantErr: "no candidates"},
		{name: "prompt blocked", status: 200, body: `{"promptFeedback":{"blockReason":"SAFETY"}}`, wantErr: "prompt_blocked=SAFETY"},
		{name: "candidate safety empty", status: 200, body: `{"candidates":[{"finishReason":"SAFETY"}]}`, wantErr: "finish_reason=SAFETY"},
		{name: "api error", status: 500, body: `{"error":{"code":500,"message":"boom","status":"INTERNAL"}}`, wantErr: "generate content"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t, tt.status, tt.body, nil)
			c := newTestClient(t, srv.URL)
			got, err := c.Generate(context.Background(), llm.Request{Human: "x", Schema: json.RawMessage(`{"type":"object"}`)})
			switch {
			case tt.wantTrunc:
				if !errors.Is(err, llm.ErrTruncated) {
					t.Fatalf("want ErrTruncated, got %v", err)
				}
			case tt.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("want err containing %q, got %v", tt.wantErr, err)
				}
			default:
				if err != nil || got != tt.want {
					t.Fatalf("got (%q,%v) want %q", got, err, tt.want)
				}
			}
		})
	}
}
