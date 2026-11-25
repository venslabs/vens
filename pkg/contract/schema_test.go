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
	"encoding/json"
	"maps"
	"slices"
	"testing"
)

// every generated schema, decoded: each question's over two CVEs, and the
// adjustment's.
func generatedSchemas(t *testing.T) map[string]any {
	t.Helper()
	out := map[string]any{}
	decode := func(name, raw string) {
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = v
	}
	for _, f := range Order() {
		decode(string(f), data(t)(Schema(f, []string{"CVE-A", "CVE-B"})))
	}
	decode("adjustment", data(t)(AdjustmentSchema(base(), describedCVE)))
	decode("undescribed adjustment", data(t)(AdjustmentSchema(base(), CVE{ID: "CVE-N", Rows: []Row{{PkgName: "liba"}}})))
	return out
}

// keywords collects the keywords a schema uses; under properties, the keys
// are property names.
func keywords(node any, names bool, used map[string]bool) {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if !names {
				used[k] = true
			}
			keywords(v, !names && k == "properties", used)
		}
	case []any:
		for _, v := range n {
			keywords(v, false, used)
		}
	}
}

// Only the six keywords every provider's structured output takes: an array's
// minItems and uniqueItems are Go's to read.
func TestSchemasUseTheSixKeywordsOnly(t *testing.T) {
	six := []string{"additionalProperties", "enum", "items", "properties", "required", "type"}
	all := map[string]bool{}
	for name, s := range generatedSchemas(t) {
		used := map[string]bool{}
		keywords(s, false, used)
		for k := range used {
			if !slices.Contains(six, k) {
				t.Errorf("%s uses %s", name, k)
			}
			all[k] = true
		}
	}
	if got := slices.Sorted(maps.Keys(all)); !slices.Equal(got, six) {
		t.Errorf("the schemas use %v, want the six %v", got, six)
	}
}

// objects calls each with every object schema under node.
func objects(node any, each func(map[string]any)) {
	switch n := node.(type) {
	case map[string]any:
		if n["type"] == "object" {
			each(n)
		}
		for _, v := range n {
			objects(v, each)
		}
	case []any:
		for _, v := range n {
			objects(v, each)
		}
	}
}

// Every object is closed and requires every property, as OpenAI's strict
// mode needs.
func TestSchemaObjectsAreClosedAndRequireEveryProperty(t *testing.T) {
	for name, s := range generatedSchemas(t) {
		objects(s, func(o map[string]any) {
			props, _ := o["properties"].(map[string]any)
			var required []string
			for _, r := range o["required"].([]any) {
				required = append(required, r.(string))
			}
			if o["additionalProperties"] != false || !slices.Equal(slices.Sorted(maps.Keys(props)), slices.Sorted(slices.Values(required))) {
				t.Errorf("%s: an object with properties %v requires %v, additionalProperties %v", name, slices.Sorted(maps.Keys(props)), required, o["additionalProperties"])
			}
		})
	}
}

// A call's answers name only the CVEs it asks about, and Intrusion
// detection's answer is a set of its ids.
func TestSchemaAnswersTheCallsCVEs(t *testing.T) {
	var s struct {
		Properties struct {
			Answers struct {
				Type  string
				Items struct {
					Properties struct {
						VulnID struct{ Enum []string } `json:"vulnId"`
						Answer struct {
							Type  string
							Items struct{ Type string }
						}
					}
				}
			}
		}
	}
	for _, f := range Order() {
		ids := []string{"CVE-Z", "CVE-A", "CVE-M"}
		if err := json.Unmarshal([]byte(data(t)(Schema(f, ids))), &s); err != nil {
			t.Fatal(err)
		}
		answer := s.Properties.Answers.Items.Properties.Answer
		wantType := "string"
		if f == ID {
			wantType = "array"
		}
		if s.Properties.Answers.Type != "array" || !slices.Equal(s.Properties.Answers.Items.Properties.VulnID.Enum, ids) || answer.Type != wantType {
			t.Errorf("%s: answers %s, vulnId enum %v, answer %s", f, s.Properties.Answers.Type, s.Properties.Answers.Items.Properties.VulnID.Enum, answer.Type)
		}
		if f == ID && answer.Items.Type != "string" {
			t.Errorf("ID's answer is an array of %q", answer.Items.Type)
		}
	}
}
