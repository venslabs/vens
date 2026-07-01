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

package ollama

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	oapi "github.com/ollama/ollama/api"

	"github.com/venslabs/vens/pkg/llm"
)

// newFakeServer registers a POST /api/chat handler that records the decoded
// request and replies with the given NDJSON body (one or more JSON lines).
func newFakeServer(t *testing.T, status int, body string, captured *oapi.ChatRequest) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/chat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, captured); err != nil {
			t.Fatalf("decode request: %v (body=%s)", err, raw)
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ab, _ := json.Marshal(x)
	bb, _ := json.Marshal(y)
	return string(ab) == string(bb)
}

// The outgoing request carries the schema as Format, Stream=false, the
// system/user split, and Options with temperature=0 and a non-zero seed.
func TestGenerate_RequestShapeAndSuccess(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","properties":{"score":{"type":"integer"}}}`)
	var got oapi.ChatRequest
	srv := newFakeServer(t, 200,
		`{"model":"m","message":{"role":"assistant","content":"{\"score\":7}"},"done":true,"done_reason":"stop"}`,
		&got)

	t.Setenv("OLLAMA_HOST", srv.URL)
	c, err := New("m")
	if err != nil {
		t.Fatal(err)
	}

	out, err := c.Generate(context.Background(), llm.Request{
		System:      "sys",
		Human:       "hum",
		Schema:      schema,
		Temperature: 0,
		Seed:        42,
	})
	if err != nil {
		t.Fatalf("Generate err = %v", err)
	}
	if out != `{"score":7}` {
		t.Errorf("out = %q", out)
	}

	if got.Model != "m" {
		t.Errorf("model = %q", got.Model)
	}
	if len(got.Messages) != 2 ||
		got.Messages[0].Role != "system" || got.Messages[0].Content != "sys" ||
		got.Messages[1].Role != "user" || got.Messages[1].Content != "hum" {
		t.Errorf("messages = %+v", got.Messages)
	}
	if got.Stream == nil || *got.Stream != false {
		t.Errorf("stream = %v, want *false", got.Stream)
	}
	if !jsonEqual(got.Format, schema) {
		t.Errorf("format = %s, want %s", got.Format, schema)
	}
	if v, ok := got.Options["temperature"].(float64); !ok || v != 0 {
		t.Errorf("temperature = %v (%T)", got.Options["temperature"], got.Options["temperature"])
	}
	if v, ok := got.Options["seed"].(float64); !ok || v != 42 {
		t.Errorf("seed = %v, want 42", got.Options["seed"])
	}
}

func TestGenerate_SeedOmittedWhenZero(t *testing.T) {
	var got oapi.ChatRequest
	srv := newFakeServer(t, 200,
		`{"model":"m","message":{"content":"{}"},"done":true,"done_reason":"stop"}`, &got)
	t.Setenv("OLLAMA_HOST", srv.URL)
	c, _ := New("m")
	if _, err := c.Generate(context.Background(), llm.Request{Human: "h", Seed: 0}); err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Options["seed"]; ok {
		t.Errorf("seed present but Seed==0: %v", got.Options["seed"])
	}
}

func TestGenerate_Branches(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		wantOut   string
		wantErr   bool
		wantTrunc bool
		errSub    string
	}{
		{
			name:      "truncation_length",
			status:    200,
			body:      `{"message":{"content":"{\"score\":"},"done":true,"done_reason":"length"}`,
			wantErr:   true,
			wantTrunc: true,
		},
		{
			name:    "empty_response",
			status:  200,
			body:    `{"message":{"content":""},"done":true,"done_reason":"stop"}`,
			wantErr: true,
			errSub:  "empty response",
		},
		{
			name:    "multi_chunk_concat",
			status:  200,
			body:    "{\"message\":{\"content\":\"{\\\"score\\\":\"},\"done\":false}\n{\"message\":{\"content\":\"7}\"},\"done\":true,\"done_reason\":\"stop\"}",
			wantOut: `{"score":7}`,
		},
		{
			name:    "http_500",
			status:  500,
			body:    `{"error":"model not found"}`,
			wantErr: true,
			errSub:  "chat",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got oapi.ChatRequest
			srv := newFakeServer(t, tt.status, tt.body, &got)
			t.Setenv("OLLAMA_HOST", srv.URL)
			c, _ := New("m")
			out, err := c.Generate(context.Background(), llm.Request{Human: "h"})
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error, got nil")
				}
				if tt.wantTrunc && !errors.Is(err, llm.ErrTruncated) {
					t.Errorf("want ErrTruncated, got %v", err)
				}
				if tt.errSub != "" && !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("err %q missing %q", err, tt.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if out != tt.wantOut {
				t.Errorf("out = %q, want %q", out, tt.wantOut)
			}
		})
	}
}
