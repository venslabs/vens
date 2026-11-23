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

package testutil

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/llm"
)

var ids = []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"}

type reply struct {
	Answers []struct {
		VulnID    string          `json:"vulnId"`
		Reasoning string          `json:"reasoning"`
		Answer    json.RawMessage `json:"answer"`
	} `json:"answers"`
}

func ask(t *testing.T, f contract.Factor) (reply, string) {
	t.Helper()
	schema, err := contract.Schema(f, ids)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := NewMockLLM().Generate(context.Background(), llm.Request{Human: "any request", Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	var r reply
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("%s: %v: %s", f, err, raw)
	}
	return r, raw
}

// The mock answers every CVE the schema asks about, once, with an answer
// Go reads as one of the question's listed answers, never cannot_tell, the
// same each time it is asked.
func TestMockAnswersFromTheSchema(t *testing.T) {
	for _, f := range contract.Order() {
		r, raw := ask(t, f)
		var got []string
		for _, a := range r.Answers {
			got = append(got, a.VulnID)
			var answer []string
			if f == contract.ID {
				if err := json.Unmarshal(a.Answer, &answer); err != nil {
					t.Fatalf("%s: %s is no set", f, a.Answer)
				}
			} else {
				var id string
				if err := json.Unmarshal(a.Answer, &id); err != nil {
					t.Fatalf("%s: %s is no id", f, a.Answer)
				}
				answer = []string{id}
			}
			if reading, err := contract.ReadAnswer(f, answer...); err != nil || reading != contract.Answered {
				t.Errorf("%s: %s answered %q, read %v", f, a.VulnID, answer, reading)
			}
			if a.Reasoning == "" {
				t.Errorf("%s: %s has no reasoning", f, a.VulnID)
			}
		}
		if !slices.Equal(got, ids) {
			t.Errorf("%s answers %v, asked %v", f, got, ids)
		}
		if _, again := ask(t, f); again != raw {
			t.Errorf("%s: the same call answered twice differently", f)
		}
	}
}

func TestMockSkipsAndForcesCannotTell(t *testing.T) {
	t.Setenv(SkipEnv, "CVE-2024-0002, CVE-2024-0004")
	r, _ := ask(t, contract.M)
	if len(r.Answers) != 2 || r.Answers[0].VulnID != "CVE-2024-0001" || r.Answers[1].VulnID != "CVE-2024-0003" {
		t.Errorf("with %s set, answered %+v", SkipEnv, r.Answers)
	}

	t.Setenv(SkipEnv, "")
	t.Setenv(CannotTellEnv, "millions")
	for _, f := range contract.Order() {
		r, _ := ask(t, f)
		for _, a := range r.Answers {
			cannot := string(a.Answer) == `"cannot_tell"`
			if cannot != (f == contract.PV) {
				t.Errorf("with %s=millions, %s answered %s", CannotTellEnv, f, a.Answer)
			}
		}
	}

	// Written id@CVE, only that vulnerability is answered cannot_tell.
	t.Setenv(CannotTellEnv, "millions@CVE-2024-0003")
	r, _ = ask(t, contract.PV)
	for _, a := range r.Answers {
		if cannot := string(a.Answer) == `"cannot_tell"`; cannot != (a.VulnID == "CVE-2024-0003") {
			t.Errorf("with %s=millions@CVE-2024-0003, %s answered %s", CannotTellEnv, a.VulnID, a.Answer)
		}
	}

	t.Setenv(CannotTellEnv, "cannot_tell")
	r, _ = ask(t, contract.ID)
	for _, a := range r.Answers {
		if string(a.Answer) != `["cannot_tell"]` {
			t.Errorf("with %s=cannot_tell, ID answered %s", CannotTellEnv, a.Answer)
		}
	}
}

// The adjustment's reply holds the reasoning and, for each field its schema
// asks, an answer from that field's list.
func TestMockAnswersTheAdjustment(t *testing.T) {
	described := contract.CVE{ID: "CVE-X", Rows: []contract.Row{{Description: "A described vulnerability."}}}
	schema, err := contract.AdjustmentSchema(described)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := NewMockLLM().Generate(context.Background(), llm.Request{Human: "a flagged CVE", Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	lists := map[string][]string{
		"opportunity": {"no_access_or_resources_required", "some_access_or_resources_required", "special_access_or_resources_required", "full_access_or_expensive_resources_required", "keep"},
	}
	for name, list := range lists {
		if !slices.Contains(list, got[name]) {
			t.Errorf("%s answered %q, not one of %v", name, got[name], list)
		}
	}
	if got["reasoning"] == "" || len(got) != len(lists)+1 {
		t.Errorf("adjustment reply %v", got)
	}
}

func TestMockFails(t *testing.T) {
	t.Setenv(FailEnv, "1")
	if _, err := NewMockLLM().Generate(context.Background(), llm.Request{}); err == nil {
		t.Errorf("with %s set, the mock answered", FailEnv)
	}
}
