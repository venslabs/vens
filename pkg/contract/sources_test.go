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
	"testing"
)

// Where each of the 16 levels came from: SL, ED and A are constants and Size
// is the config's; Loss of confidentiality, integrity and availability are
// the CVSS vectors', whatever the answers, the adjustment or the vectors
// give; Privacy violation takes its floor where the usable v3 vectors give
// C:N; a question not asked takes the config's level; an answer read,
// crossed with the config where Go crosses it, is the answer's, unless the
// config's cap or the adjustment lowers it.
func TestSources(t *testing.T) {
	answered := Answers{M: "possible_reward", O: "some_access_or_resources_required", EE: "easy", ID: []string{"network"},
		LAC: "identified", FD: "bankruptcy", RD: "minimal_damage", NC: "clear_violation", PV: "thousands"}
	everyAnswer := map[Factor]Source{
		SL: SourceConstant, M: SourceAnswer, O: SourceAnswer, S: SourceConfig, ED: SourceConstant, EE: SourceAnswer,
		A: SourceConstant, ID: SourceAnswer, LC: SourceCVSS, LI: SourceCVSS, LAV: SourceCVSS, LAC: SourceAnswer,
		FD: SourceAnswer, RD: SourceAnswer, NC: SourceAnswer, PV: SourceAnswer,
	}
	but := func(changes map[Factor]Source) map[Factor]Source {
		out := maps.Clone(everyAnswer)
		maps.Copy(out, changes)
		return out
	}
	uniform, none, hundreds := declared(), declared(), declared()
	uniform.Detection = &Detection{Network: "logged", Host: "logged", Application: "logged"}
	none.DataSubjects = ptr("none")
	hundreds.DataSubjects = ptr("hundreds")
	for name, c := range map[string]struct {
		d        Deployment
		cve      CVE
		a        Answers
		adjusted *Adjusted
		want     map[Factor]Source
	}{
		"every field declared, every question answered": {declared(), describedCVE, answered, nil, everyAnswer},
		"nothing declared":               {base(), describedCVE, answered, nil, but(map[Factor]Source{ID: SourceConfig, NC: SourceConfig})},
		"every axis at N":                {declared(), impactCVE("N", "N", "N"), answered, nil, but(map[Factor]Source{PV: SourceFloor})},
		"every axis at N, adjusted":      {declared(), impactCVE("N", "N", "N"), answered, &Adjusted{Confidentiality: notAffected}, but(map[Factor]Source{PV: SourceFloor})},
		"no vector":                      {declared(), impactCVE("", "", ""), answered, nil, everyAnswer},
		"detection at one level":         {uniform, describedCVE, answered, nil, but(map[Factor]Source{ID: SourceConfig})},
		"data_subjects none":             {none, describedCVE, answered, nil, but(map[Factor]Source{PV: SourceConfig})},
		"data_subjects under the answer": {hundreds, describedCVE, answered, nil, but(map[Factor]Source{PV: SourceConfig})},
		"data_subjects over the answer":  {hundreds, describedCVE, changed(answered, func(a *Answers) { a.PV = "one_individual" }), nil, everyAnswer},
		"the adjustment lowers":          {declared(), describedCVE, answered, &Adjusted{Opportunity: "full_access_or_expensive_resources_required", Confidentiality: notAffected}, but(map[Factor]Source{O: SourceAdjustment, PV: SourceAdjustment})},
		"the adjustment keeps":           {declared(), describedCVE, answered, &Adjusted{Opportunity: keep, Confidentiality: affected}, everyAnswer},
		"the adjustment at the baseline": {declared(), describedCVE, answered, &Adjusted{Opportunity: "some_access_or_resources_required"}, everyAnswer},
		"the adjustment off its list":    {declared(), describedCVE, answered, &Adjusted{Opportunity: "bogus"}, everyAnswer},
	} {
		if got := computeFor(t, c.d, c.cve, c.a, c.adjusted).Sources; !maps.Equal(got, c.want) {
			t.Errorf("%s:\n got %v\nwant %v", name, got, c.want)
		}
	}
}

func changed(a Answers, change func(*Answers)) Answers {
	change(&a)
	return a
}

func TestSourcesWriteTheirNames(t *testing.T) {
	got, err := json.Marshal(map[Factor]Source{SL: SourceConstant, O: SourceAdjustment, LC: SourceCVSS, PV: SourceFloor, S: SourceConfig, M: SourceAnswer})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"LC":"cvss","M":"answer","O":"adjustment","PV":"floor","S":"config","SL":"constant"}`; string(got) != want {
		t.Errorf("%s, want %s", got, want)
	}
	if got := Source(0).String(); got != "unknown" {
		t.Errorf("Source(0) = %s", got)
	}
}
