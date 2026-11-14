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
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

func leveled[V ~int](c contract[V]) string {
	parts := make([]string, len(c.answers))
	for i, a := range c.answers {
		parts[i] = fmt.Sprintf("%s=%d", a.id, a.value)
	}
	return strings.Join(parts, " ")
}

// Each question's answers in the order shown and the level Go maps each to,
// cannot_tell last at the factor's worst case. Intrusion detection, Loss of
// confidentiality and Loss of accountability map to no level of their own:
// Go crosses them with the config.
func TestTableAnswersAndLevels(t *testing.T) {
	want := map[Factor]string{
		M:   "low_or_no_reward=1 possible_reward=4 high_reward=9 cannot_tell=9",
		O:   "no_access_or_resources_required=9 some_access_or_resources_required=7 special_access_or_resources_required=4 full_access_or_expensive_resources_required=0 cannot_tell=9",
		EE:  "theoretical=1 difficult=3 easy=5 automated_tools_available=9 cannot_tell=9",
		ID:  "network host application cannot_tell",
		LC:  "minimal extensive all cannot_tell",
		LI:  "minimal_slightly_corrupt=1 minimal_seriously_corrupt=3 extensive_slightly_corrupt=5 extensive_seriously_corrupt=7 all_data_totally_corrupt=9 cannot_tell=9",
		LAV: "minimal_secondary_interrupted=1 minimal_primary_interrupted=5 extensive_secondary_interrupted=5 extensive_primary_interrupted=7 all_services_completely_lost=9 cannot_tell=9",
		LAC: "identified unidentified defeats_attribution cannot_tell",
		FD:  "less_than_cost_to_fix=1 minor_effect_on_annual_profit=3 significant_effect_on_annual_profit=7 bankruptcy=9 cannot_tell=9",
		RD:  "minimal_damage=1 loss_of_major_accounts=4 loss_of_goodwill=5 brand_damage=9 cannot_tell=9",
		NC:  "minor_violation=2 clear_violation=5 high_profile_violation=7 cannot_tell=7",
		PV:  "none=3 one_individual=3 hundreds=5 thousands=7 millions=9 cannot_tell=9",
	}
	got := map[Factor]string{
		M: leveled(motive), O: leveled(opportunity), EE: leveled(easeOfExploit),
		ID: strings.Join(ids(intrusionDetection), " "), LC: strings.Join(ids(confidentiality), " "),
		LI: leveled(integrity), LAV: leveled(availability), LAC: strings.Join(ids(accountability), " "),
		FD: leveled(financialDamage), RD: leveled(reputationDamage), NC: leveled(nonCompliance), PV: leveled(privacyViolation),
	}
	for _, f := range Order() {
		if got[f] != want[f] {
			t.Errorf("%s:\n got %s\nwant %s", f, got[f], want[f])
		}
	}
}

// The table holds the 12 questions, each under its own factor, with its
// counter, distinct ids and cannot_tell last.
func TestTableHoldsTheTwelveQuestions(t *testing.T) {
	counters := map[Factor]string{
		M: "motive_cannot_tell", O: "opportunity_cannot_tell", EE: "ease_of_exploit_cannot_tell",
		ID: "intrusion_detection_cannot_tell", LC: "confidentiality_cannot_tell", LI: "integrity_cannot_tell",
		LAV: "availability_cannot_tell", LAC: "accountability_cannot_tell", FD: "financial_damage_cannot_tell",
		RD: "reputation_cannot_tell", NC: "non_compliance_cannot_tell", PV: "privacy_cannot_tell",
	}
	if got := slices.Sorted(maps.Keys(table)); !slices.Equal(got, slices.Sorted(slices.Values(Order()))) {
		t.Fatalf("the table holds %v, the calls ask %v", got, Order())
	}
	for f, q := range table {
		if q.factor != f || q.counter != counters[f] {
			t.Errorf("table[%s] is %s's question, counting %s", f, q.factor, q.counter)
		}
		if q.ids[len(q.ids)-1] != cannotTell || len(q.ids) != len(q.texts) {
			t.Errorf("%s: ids %v, %d texts; cannot_tell must be last", f, q.ids, len(q.texts))
		}
		if len(slices.Compact(slices.Sorted(slices.Values(q.ids)))) != len(q.ids) {
			t.Errorf("%s: an id is listed twice: %v", f, q.ids)
		}
		// Intrusion detection asks where an attempt would show, whoever makes it.
		if names := strings.Contains(q.question, "{group}"); names == (f == ID) {
			t.Errorf("%s's question names the attacker group: %t", f, names)
		}
	}
}

// The tables Go crosses the split factors' answers with, and the levels it
// sets alone.
func TestCrossedLevels(t *testing.T) {
	lc := map[string][2]int{"minimal": {2, 6}, "extensive": {6, 7}, "all": {9, 9}, cannotTell: {9, 9}}
	for id, want := range lc {
		for column, ds := range []string{"medium", "high"} {
			d := base()
			d.DataSensitivity.Value = ds
			if got := level(t, "LC", d, [3]bool{}, Answers{LC: id}, nil); got != want[column] {
				t.Errorf("LC %s on %s data = %d, want %d", id, ds, got, want[column])
			}
		}
	}
	lac := map[string][3]int{"identified": {7, 7, 1}, "unidentified": {9, 7, 7}, "defeats_attribution": {9, 9, 9}, cannotTell: {9, 9, 9}}
	for id, want := range lac {
		for i, tr := range traceabilities {
			d := base()
			d.Traceability = ptr(tr)
			if got := level(t, "LAC", d, [3]bool{}, Answers{LAC: id}, nil); got != want[i] {
				t.Errorf("LAC %s under %s = %d, want %d", id, tr, got, want[i])
			}
		}
	}
	for declared, want := range map[string]int{"not_logged": 9, "logged": 8, "logged_and_reviewed": 3, activeInApplication: 1} {
		d := base()
		d.Detection = &Detection{Network: "not_logged", Host: "not_logged", Application: declared}
		if got := level(t, "ID", d, [3]bool{}, Answers{ID: []string{"application"}}, nil); got != want {
			t.Errorf("ID with application %s = %d, want %d", declared, got, want)
		}
	}
	// Privacy violation: the lower of the answer's band and the declared
	// population's, the caps that leave it asked.
	bands := map[string]int{"none": 3, "one_individual": 3, "hundreds": 5, "thousands": 7, "millions": 9, cannotTell: 9}
	for answer, own := range bands {
		for _, population := range []string{"hundreds", "thousands", "millions"} {
			d := base()
			d.DataSubjects = ptr(population)
			if got, want := level(t, "PV", d, [3]bool{}, Answers{PV: answer}, nil), min(own, bands[population]); got != want {
				t.Errorf("PV %s capped by %s = %d, want %d", answer, population, got, want)
			}
		}
	}
	for exposure, want := range map[string]int{"internet": 9, "private": 6, "internal": 4} {
		d := base()
		d.Exposure.Value = exposure
		if got := level(t, "S", d, [3]bool{}, Answers{}, nil); got != want {
			t.Errorf("S for %s = %d, want %d", exposure, got, want)
		}
	}
	got := levels(compute(t, base(), [3]bool{}, Answers{}, nil).Vector)
	if got["SL"] != 9 || got["ED"] != 9 || got["A"] != 9 {
		t.Errorf("SL %d, ED %d, A %d: each is 9 for every finding", got["SL"], got["ED"], got["A"])
	}
}
