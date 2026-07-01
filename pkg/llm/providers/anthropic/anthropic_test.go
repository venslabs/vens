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

package anthropic

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/venslabs/vens/pkg/llm"
)

// recordedReq captures what the fake Anthropic endpoint received.
type recordedReq struct {
	path   string
	method string
	body   map[string]any
	raw    string
	hits   int
}

// newTestClient points the SDK at an httptest server via ANTHROPIC_BASE_URL
// (read natively by anthropic-sdk-go), returning a real adapter Client plus the
// capture. Uses t.Setenv, so tests must not call t.Parallel.
func newTestClient(t *testing.T, model string, status int, respBody string) (*Client, *recordedReq) {
	t.Helper()
	rec := &recordedReq{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.hits++
		rec.path = r.URL.Path
		rec.method = r.Method
		b, _ := io.ReadAll(r.Body)
		rec.raw = string(b)
		_ = json.Unmarshal(b, &rec.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)

	t.Setenv("ANTHROPIC_API_KEY", "test-key")
	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)

	c, err := New(model)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, rec
}

const successBody = `{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4-5",` +
	`"content":[{"type":"text","text":"{\"cves\":[]}"}],"stop_reason":"end_turn","stop_sequence":null,` +
	`"usage":{"input_tokens":1,"output_tokens":1}}`

func newReq() llm.Request {
	return llm.Request{
		System:      "you are vens",
		Human:       "score these cves",
		Schema:      json.RawMessage(`{"type":"object","properties":{"cves":{"type":"array"}}}`),
		Temperature: 0,
		Seed:        42, // Anthropic has no seed param; must be ignored
	}
}

// The outgoing request carries the schema in output_config.format, a hardcoded
// max_tokens, an explicit temperature=0, the system block, and no seed.
func TestGenerate_OutgoingRequest(t *testing.T) {
	c, rec := newTestClient(t, "claude-sonnet-4-5", 200, successBody)

	out, err := c.Generate(context.Background(), newReq())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if out != `{"cves":[]}` {
		t.Fatalf("out = %q", out)
	}

	if rec.method != http.MethodPost || rec.path != "/v1/messages" {
		t.Fatalf("hit %s %s", rec.method, rec.path)
	}
	if rec.body["model"] != "claude-sonnet-4-5" {
		t.Errorf("model = %v", rec.body["model"])
	}
	if rec.body["max_tokens"] != float64(16384) {
		t.Errorf("max_tokens = %v", rec.body["max_tokens"])
	}
	if !strings.Contains(rec.raw, `"temperature":0`) {
		t.Errorf("temperature not sent as 0: %s", rec.raw)
	}
	if _, ok := rec.body["seed"]; ok {
		t.Error("seed must not be sent")
	}

	sys := rec.body["system"].([]any)
	sb := sys[0].(map[string]any)
	if sb["type"] != "text" || sb["text"] != "you are vens" {
		t.Errorf("system block = %v", sb)
	}

	msgs := rec.body["messages"].([]any)
	m0 := msgs[0].(map[string]any)
	content := m0["content"].([]any)
	cb := content[0].(map[string]any)
	if m0["role"] != "user" || cb["type"] != "text" || cb["text"] != "score these cves" {
		t.Errorf("user msg = %v", m0)
	}

	oc := rec.body["output_config"].(map[string]any)
	format := oc["format"].(map[string]any)
	if format["type"] != "json_schema" {
		t.Errorf("format.type = %v", format["type"])
	}
	var wantSchema map[string]any
	_ = json.Unmarshal(newReq().Schema, &wantSchema)
	gotSchema, _ := json.Marshal(format["schema"])
	wantJSON, _ := json.Marshal(wantSchema)
	if string(gotSchema) != string(wantJSON) {
		t.Errorf("schema = %s want %s", gotSchema, wantJSON)
	}
}

func TestGenerate_ResponseBranches(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		want    string
		wantErr string // substring; "" => no error
		errIs   error  // errors.Is target; nil => skip
	}{
		{
			name:   "success",
			status: 200, body: successBody,
			want: `{"cves":[]}`,
		},
		{
			name:    "truncated_max_tokens",
			status:  200,
			body:    `{"id":"m","type":"message","role":"assistant","model":"x","content":[{"type":"text","text":"partial"}],"stop_reason":"max_tokens","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`,
			wantErr: "max_tokens", errIs: llm.ErrTruncated,
		},
		{
			name:    "no_text_block",
			status:  200,
			body:    `{"id":"m","type":"message","role":"assistant","model":"x","content":[{"type":"tool_use","id":"t","name":"n","input":{}}],"stop_reason":"tool_use","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`,
			wantErr: "no text content block",
		},
		{
			name:    "api_error_400",
			status:  400,
			body:    `{"type":"error","error":{"type":"invalid_request_error","message":"bad request"}}`,
			wantErr: "message failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestClient(t, "x", tt.status, tt.body)
			got, err := c.Generate(context.Background(), newReq())
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if got != tt.want {
					t.Fatalf("got %q want %q", got, tt.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want contains %q", err, tt.wantErr)
			}
			if tt.errIs != nil && !errors.Is(err, tt.errIs) {
				t.Fatalf("err = %v, want errors.Is %v", err, tt.errIs)
			}
		})
	}
}

// An invalid schema fails before any network call.
func TestGenerate_InvalidSchema_NoNetwork(t *testing.T) {
	c, rec := newTestClient(t, "x", 200, successBody)
	req := newReq()
	req.Schema = json.RawMessage(`not-json`)
	_, err := c.Generate(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "invalid schema") {
		t.Fatalf("err = %v", err)
	}
	if rec.hits != 0 {
		t.Errorf("handler should not be hit, got %d", rec.hits)
	}
}
