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

// Package schematest gives the provider tests schemas vens sends, read from
// pkg/contract's golden frames, and the order each one writes its properties
// in, so a test can check a client keeps that order on the wire.
package schematest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Frame is one of pkg/contract's golden schemas and the order it writes the
// properties of one object schema in.
type Frame struct {
	// Name is the frame's file under pkg/contract/testdata/internet-facing.
	Name string
	// Object is the path of member names from the schema's root to the object
	// schema whose properties Order lists, empty for the root.
	Object []string
	// Order is that object's property names, in the order the frame writes them.
	Order []string
}

// Frames are a question's schema, its answer objects nested in an array, and
// the adjustment's, its properties at the root.
var Frames = []Frame{
	{
		Name:   "01-M.schema.json",
		Object: []string{"properties", "answers", "items"},
		Order:  []string{"vulnId", "reasoning", "answer"},
	},
	{
		Name:  "13-adjustment.schema.json",
		Order: []string{"reasoning", "opportunity"},
	},
}

// Read returns the frame compacted, as vens sends it, failing t unless the
// frame still writes Order and Order is not sorted: a client sending the
// schema through a Go map, which sorts keys, must not pass. The path resolves
// from a provider package's directory, where go test runs its tests.
func (f Frame) Read(t *testing.T) json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "contract", "testdata", "internet-facing", f.Name))
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var frame bytes.Buffer
	if err := json.Compact(&frame, b); err != nil {
		t.Fatalf("%s: %v", f.Name, err)
	}
	if got := PropertyNames(t, frame.Bytes(), f.Object...); !slices.Equal(got, f.Order) {
		t.Fatalf("%s writes %v, want %v", f.Name, got, f.Order)
	}
	if slices.IsSorted(f.Order) {
		t.Fatalf("%s: %v is sorted, so a client sorting keys would pass", f.Name, f.Order)
	}
	return frame.Bytes()
}

// PropertyNames returns the property names of the object schema reached from
// schema's root through path, in the order schema's bytes write them.
func PropertyNames(t *testing.T, schema []byte, path ...string) []string {
	t.Helper()
	raw := json.RawMessage(schema)
	for _, name := range append(slices.Clone(path), "properties") {
		var members map[string]json.RawMessage
		if err := json.Unmarshal(raw, &members); err != nil {
			t.Fatalf("looking for %q: %v in %s", name, err, raw)
		}
		next, ok := members[name]
		if !ok {
			t.Fatalf("no %q in %s", name, raw)
		}
		raw = next
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("properties is not an object: %s", raw)
	}
	var names []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		name, _ := tok.(string)
		names = append(names, name)
		if err := dec.Decode(new(json.RawMessage)); err != nil {
			t.Fatal(err)
		}
	}
	return names
}
