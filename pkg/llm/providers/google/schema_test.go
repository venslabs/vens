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
	"encoding/json"
	"reflect"
	"testing"
)

func TestOrderedSchema(t *testing.T) {
	tests := []struct {
		name, schema, want string
	}{
		{
			name:   "objects nested through properties and items",
			schema: `{"type":"object","properties":{"b":{"type":"array","items":{"properties":{"z":{},"a":{}}}},"a":{}}}`,
			want:   `{"type":"object","properties":{"b":{"type":"array","items":{"properties":{"z":{},"a":{}},"propertyOrdering":["z","a"]}},"a":{}},"propertyOrdering":["b","a"]}`,
		},
		{
			name:   "a property named properties is a property",
			schema: `{"properties":{"properties":{"properties":{"y":{},"x":{}}},"b":{}}}`,
			want:   `{"properties":{"properties":{"properties":{"y":{},"x":{}},"propertyOrdering":["y","x"]},"b":{}},"propertyOrdering":["properties","b"]}`,
		},
		{
			name:   "enum values are data",
			schema: `{"enum":[{"properties":{"b":{},"a":{}}}]}`,
			want:   `{"enum":[{"properties":{"b":{},"a":{}}}]}`,
		},
		{
			name:   "a schema's own propertyOrdering is kept",
			schema: `{"properties":{"b":{},"a":{}},"propertyOrdering":["a","b"]}`,
			want:   `{"properties":{"b":{},"a":{}},"propertyOrdering":["a","b"]}`,
		},
		{
			name:   "a repeated name keeps its first place and its last value",
			schema: `{"properties":{"a":{},"b":{},"a":{"type":"string"}}}`,
			want:   `{"properties":{"a":{"type":"string"},"b":{}},"propertyOrdering":["a","b"]}`,
		},
		{
			name:   "empty or null properties get no list",
			schema: `{"properties":{},"items":{"properties":null}}`,
			want:   `{"properties":{},"items":{"properties":null}}`,
		},
		{name: "a boolean schema", schema: `true`, want: `true`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := orderedSchema(json.RawMessage(tt.schema))
			if err != nil {
				t.Fatalf("orderedSchema: %v", err)
			}
			// Through JSON, as the SDK sends it.
			b, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var sent, want any
			if err := json.Unmarshal(b, &sent); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(tt.want), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(sent, want) {
				t.Errorf("got  %s\nwant %s", b, tt.want)
			}
		})
	}
}

// A schema a plain decode rejects is rejected, trailing data included.
func TestOrderedSchema_Invalid(t *testing.T) {
	for _, schema := range []string{``, `not-json`, `{"properties":{}`, `{"a":1} {"b":2}`} {
		if _, err := orderedSchema(json.RawMessage(schema)); err == nil {
			t.Errorf("orderedSchema(%q) = nil error", schema)
		}
	}
}
