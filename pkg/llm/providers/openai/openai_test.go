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

	"github.com/openai/openai-go/v3/option"

	"github.com/venslabs/vens/pkg/llm"
)

// A reasoning model with an explicit temperature fails clearly instead of
// silently dropping the flag; no request is sent.
func TestGenerate_ReasoningModelRefusesExplicitTemperature(t *testing.T) {
	url, captured := fakeServer(t, http.StatusOK, successBody)
	c := newTestClient(t, "o3-mini", url)
	_, err := c.Generate(context.Background(), llm.Request{
		Schema:      json.RawMessage(testSchema),
		Temperature: fptr(0.7),
	})
	if err == nil || !strings.Contains(err.Error(), "refuses an explicit temperature") {
		t.Fatalf("Generate err = %v, want a refuses-temperature error", err)
	}
	if len(*captured) != 0 {
		t.Error("no request must be sent when the model refuses the temperature")
	}
}

// Without an explicit temperature, no temperature key is sent — for chat
// models and reasoning models alike. The flag's zero default is never
// forwarded on its own, so a plain run keeps working on both.
func TestGenerate_OmitsTemperatureWhenFlagNotPassed(t *testing.T) {
	for _, model := range []string{"gpt-4o", "gpt-5.4-mini"} {
		t.Run(model, func(t *testing.T) {
			url, captured := fakeServer(t, http.StatusOK, successBody)
			c := newTestClient(t, model, url)
			if _, err := c.Generate(context.Background(), llm.Request{Schema: json.RawMessage(testSchema)}); err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if _, ok := (*captured)["temperature"]; ok {
				t.Error("temperature must be omitted when the flag is not passed")
			}
		})
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

func fptr(f float64) *float64 { return &f }

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

// A gpt-4o request carries the strict json_schema, the system/user split, an
// explicit temperature=0 plus a non-zero seed. The explicit flag value is
// forwarded as-is.
func TestGenerate_RequestShape(t *testing.T) {
	url, captured := fakeServer(t, http.StatusOK, successBody)
	c := newTestClient(t, "gpt-4o", url)

	if _, err := c.Generate(context.Background(), llm.Request{
		System:      "you are a scorer",
		Human:       "score this",
		Schema:      json.RawMessage(testSchema),
		Temperature: fptr(0),
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

	// an explicitly passed temperature is forwarded as-is (including 0).
	if temp, ok := req["temperature"]; !ok || temp.(float64) != 0 {
		t.Errorf("temperature = %v (present=%v), want 0", req["temperature"], ok)
	}
	if s, ok := req["seed"]; !ok || s.(float64) != 42 {
		t.Errorf("seed = %v (present=%v), want 42", req["seed"], ok)
	}
}

// A zero seed is omitted from the request.
func TestGenerate_OmitsSeed(t *testing.T) {
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

// An explicitly passed temperature is forwarded as-is, including non-zero
// values (0 is already covered by TestGenerate_RequestShape).
func TestGenerate_ForwardsExplicitTemperature(t *testing.T) {
	url, captured := fakeServer(t, http.StatusOK, successBody)
	c := newTestClient(t, "gpt-4o", url)
	if _, err := c.Generate(context.Background(), llm.Request{
		Schema:      json.RawMessage(testSchema),
		Temperature: fptr(0.7),
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if temp, ok := (*captured)["temperature"]; !ok || temp.(float64) != 0.7 {
		t.Errorf("temperature = %v (present=%v), want 0.7", (*captured)["temperature"], ok)
	}
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func capturingClient(got *string) option.RequestOption {
	return option.WithHTTPClient(&http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			*got = r.URL.String()
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(successBody)),
				Request:    r,
			}, nil
		}),
	})
}

// Asserting what resolveBaseURL returns would keep passing with the bug back in
// place, so assert the URL the SDK actually calls.
func TestNewTargetsOpenAIWhenBaseURLIsEmpty(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("OPENAI_BASE_URL", "")

	var got string
	c, err := newClient("gpt-4o", option.WithMaxRetries(0), capturingClient(&got))
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	if _, err := c.Generate(context.Background(), llm.Request{
		System: "you are a scorer",
		Human:  "score this",
		Schema: json.RawMessage(testSchema),
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if want := defaultBaseURL + "chat/completions"; got != want {
		t.Errorf("request URL = %q, want %q", got, want)
	}
}

func TestNewKeepsAConfiguredBaseURL(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("OPENAI_BASE_URL", "http://localhost:8080/v1/")

	var got string
	c, err := newClient("gpt-4o", option.WithMaxRetries(0), capturingClient(&got))
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	if _, err := c.Generate(context.Background(), llm.Request{
		Schema: json.RawMessage(testSchema),
	}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if want := "http://localhost:8080/v1/chat/completions"; got != want {
		t.Errorf("request URL = %q, want %q", got, want)
	}
}

func TestGenerate_UnsupportedStructuredOutput(t *testing.T) {
	const body = `{"error":{"message":"Invalid parameter: 'response_format' of type 'json_schema' is not supported with this model.",` +
		`"type":"invalid_request_error","param":"response_format","code":null}}`
	url, _ := fakeServer(t, http.StatusBadRequest, body)
	c := newTestClient(t, "gpt-4-turbo", url)

	_, err := c.Generate(context.Background(), llm.Request{Schema: json.RawMessage(testSchema)})
	if !errors.Is(err, llm.ErrUnsupportedStructuredOutput) {
		t.Fatalf("err = %v, want llm.ErrUnsupportedStructuredOutput", err)
	}
	for _, want := range []string{`"gpt-4-turbo"`, "choosing-a-model.md", "not supported with this model"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestGenerate_OtherBadRequestIsNotStructuredOutput(t *testing.T) {
	const body = `{"error":{"message":"Invalid value: 'nope'","type":"invalid_request_error","param":"model","code":null}}`
	url, _ := fakeServer(t, http.StatusBadRequest, body)
	c := newTestClient(t, "gpt-4o", url)

	_, err := c.Generate(context.Background(), llm.Request{Schema: json.RawMessage(testSchema)})
	if err == nil {
		t.Fatal("Generate: want an error")
	}
	if errors.Is(err, llm.ErrUnsupportedStructuredOutput) {
		t.Errorf("err = %v, want it classified as a plain provider error", err)
	}
}

// An unknown model id (an Azure deployment name or a future id) is not in
// the refuse-list; when the API answers the explicit temperature with a 400
// naming the parameter, fail with the same clear message.
func TestGenerate_TemperatureRefusedByAPI(t *testing.T) {
	const body = `{"error":{"message":"Unsupported parameter: 'temperature' is not supported with this model.",` +
		`"type":"invalid_request_error","param":"temperature","code":null}}`
	url, _ := fakeServer(t, http.StatusBadRequest, body)
	c := newTestClient(t, "future-reasoning-9", url)

	_, err := c.Generate(context.Background(), llm.Request{
		Schema:      json.RawMessage(testSchema),
		Temperature: fptr(0.7),
	})
	if err == nil || !strings.Contains(err.Error(), "refused the explicit --llm-temperature") {
		t.Fatalf("Generate err = %v, want a refused-temperature error", err)
	}
}
