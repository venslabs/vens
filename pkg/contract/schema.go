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

package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// schema is a JSON Schema written with six keywords only, the ones the
// providers' structured outputs all accept. Every object is closed and every
// property required, as OpenAI's strict mode needs. Intrusion detection's
// set rules, at least one channel and each once, are read in Go: the
// providers do not all take minItems and uniqueItems.
type schema struct {
	Type                 string     `json:"type"`
	AdditionalProperties *bool      `json:"additionalProperties,omitempty"`
	Required             []string   `json:"required,omitempty"`
	Properties           properties `json:"properties,omitempty"`
	Items                *schema    `json:"items,omitempty"`
	Enum                 []string   `json:"enum,omitempty"`
}

type property struct {
	name   string
	schema *schema
}

// properties keep their order when written: a model writing its reply in
// schema order then gives the reasoning before the answer.
type properties []property

func (ps properties) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, p := range ps {
		if i > 0 {
			b.WriteByte(',')
		}
		name, err := json.Marshal(p.name)
		if err != nil {
			return nil, err
		}
		value, err := json.Marshal(p.schema)
		if err != nil {
			return nil, err
		}
		b.Write(name)
		b.WriteByte(':')
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func object(ps ...property) *schema {
	closed := false
	required := make([]string, len(ps))
	for i, p := range ps {
		required[i] = p.name
	}
	return &schema{Type: "object", AdditionalProperties: &closed, Required: required, Properties: ps}
}

func enum(values ...string) *schema {
	return &schema{Type: "string", Enum: values}
}

// Schema returns the JSON Schema of factor f's call over the CVEs it lists:
// one answer per CVE, its vulnId one of the call's ids, so an answer for a
// CVE the call did not ask about cannot be written, and its answer one of
// the factor's ids.
func Schema(f Factor, ids []string) (json.RawMessage, error) {
	q, ok := table[f]
	if !ok {
		return nil, fmt.Errorf("%q is not a model-answered factor", f)
	}
	if err := checkIDs(ids); err != nil {
		return nil, err
	}
	answer := enum(q.ids...)
	if f == ID {
		answer = &schema{Type: "array", Items: answer}
	}
	item := object(
		property{"vulnId", enum(ids...)},
		property{"reasoning", &schema{Type: "string"}},
		property{"answer", answer},
	)
	return json.Marshal(object(property{"answers", &schema{Type: "array", Items: item}}))
}

func checkIDs(ids []string) error {
	if len(ids) == 0 {
		return errors.New("the call lists no CVE")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" {
			return errors.New("a CVE has no id")
		}
		if seen[id] {
			return fmt.Errorf("%s is twice in the call", id)
		}
		seen[id] = true
	}
	return nil
}
