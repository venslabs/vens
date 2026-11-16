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

package generator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/venslabs/vens/pkg/llm"
)

// send makes one LLM call with the run's system prompt: it writes the call's
// debug files, asks the model, and records the reply as attestation evidence.
// question names the call in the run's counts. It returns the raw reply and
// its evidence reference.
func (g *Generator) send(ctx context.Context, run *scoringRun, question, request string, schema json.RawMessage) (raw, evidenceRef string, err error) {
	run.call(question)
	// One numbered file set per call, the names vens-demo's archive check
	// globs: fixed names would let every call overwrite the previous one,
	// hiding what the model was asked (#359).
	var debugName string
	if g.debugRunDir != "" {
		g.debugCalls++
		debugName = fmt.Sprintf("batch-%05d", g.debugCalls)
		g.writeDebugFile(ctx, debugName+".system.prompt", g.system)
		g.writeDebugFile(ctx, debugName+".human.prompt", request)
	}
	req := llm.Request{
		System:      g.system,
		Human:       request,
		Schema:      schema,
		Temperature: g.o.Temperature,
		Seed:        g.o.Seed,
	}
	if err := llm.RetryOnRateLimit(ctx, g.o.SleepOnRateLimit, g.o.RetryOnRateLimit, func(c context.Context) error {
		var e error
		raw, e = g.o.LLM.Generate(c, req)
		return e
	}); err != nil {
		return "", "", err
	}
	// Written before the reply is read, so a reply that fails to parse is on
	// disk too. A failed call, such as a truncated one, has no reply: its
	// prompts stay alone.
	if debugName != "" {
		g.writeDebugFile(ctx, debugName+".response", raw)
	}
	if g.attestor != nil {
		evidenceRef = g.attestor.AddBatch(g.system, request, []byte(raw))
	}
	return raw, evidenceRef, nil
}

// text reads a JSON string, or keeps any other value as its JSON text.
func text(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

// repeatedKeys counts, at any depth of the JSON text data, the keys an
// object writes again: encoding/json keeps the last value of such a key and
// says nothing. data is text json.Unmarshal has accepted, which bounds its
// depth; any other counts none.
func repeatedKeys(data []byte) int {
	dec := json.NewDecoder(bytes.NewReader(data))
	// A number past float64's range would fail the walk, not the decode.
	dec.UseNumber()
	n, err := countRepeated(dec)
	if err != nil {
		return 0
	}
	return n
}

// countRepeated reads one JSON value from dec and counts the keys its
// objects write again.
func countRepeated(dec *json.Decoder) (int, error) {
	t, err := dec.Token()
	if err != nil {
		return 0, err
	}
	if t != json.Delim('{') && t != json.Delim('[') {
		return 0, nil
	}
	object := t == json.Delim('{')
	seen := map[string]bool{}
	n := 0
	for dec.More() {
		if object {
			key, err := dec.Token()
			if err != nil {
				return 0, err
			}
			name, _ := key.(string)
			if seen[name] {
				n++
			}
			seen[name] = true
		}
		inner, err := countRepeated(dec)
		if err != nil {
			return 0, err
		}
		n += inner
	}
	if _, err := dec.Token(); err != nil {
		return 0, err
	}
	return n, nil
}
