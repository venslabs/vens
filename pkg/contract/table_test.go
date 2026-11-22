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

	"github.com/venslabs/vens/pkg/owasp"
	"github.com/venslabs/vens/pkg/riskconfig"
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
// Go crosses them with the config. Reachability's answers map to whether Go
// reads them as reachable, its cannot_tell to the worst case, reachable.
func TestTableAnswersAndLevels(t *testing.T) {
	want := map[Factor]string{
		R:   "reachable=true not_reachable=false cannot_tell=true",
		M:   "low_or_no_reward=1 possible_reward=4 high_reward=9 cannot_tell=9",
		O:   "no_access_or_resources_required=9 some_access_or_resources_required=7 special_access_or_resources_required=4 full_access_or_expensive_resources_required=0 cannot_tell=9",
		EE:  "theoretical=1 difficult=3 easy=5 automated_tools_available=9 cannot_tell=9",
		ID:  "network host application cannot_tell",
		LC:  "no_impact minimal extensive all cannot_tell",
		LI:  "no_impact=1 minimal_slightly_corrupt=1 minimal_seriously_corrupt=3 extensive_slightly_corrupt=5 extensive_seriously_corrupt=7 all_data_totally_corrupt=9 cannot_tell=9",
		LAV: "no_impact=1 minimal_secondary_interrupted=1 minimal_primary_interrupted=5 extensive_secondary_interrupted=5 extensive_primary_interrupted=7 all_services_completely_lost=9 cannot_tell=9",
		LAC: "identified unidentified defeats_attribution cannot_tell",
		FD:  "less_than_cost_to_fix=1 minor_effect_on_annual_profit=3 significant_effect_on_annual_profit=7 bankruptcy=9 cannot_tell=9",
		RD:  "minimal_damage=1 loss_of_major_accounts=4 loss_of_goodwill=5 brand_damage=9 cannot_tell=9",
		NC:  "minor_violation=2 clear_violation=5 high_profile_violation=7 cannot_tell=7",
		PV:  "none=3 one_individual=3 hundreds=5 thousands=7 millions=9 cannot_tell=9",
	}
	var reached []string
	for _, a := range reachability.answers {
		reached = append(reached, fmt.Sprintf("%s=%t", a.id, a.value))
	}
	got := map[Factor]string{
		R: strings.Join(reached, " "), M: leveled(motive), O: leveled(opportunity), EE: leveled(easeOfExploit),
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

// The table holds the 13 questions, each under its own factor, with its
// counter, distinct ids and cannot_tell last.
func TestTableHoldsTheThirteenQuestions(t *testing.T) {
	counters := map[Factor]string{
		R: "reachability_cannot_tell", M: "motive_cannot_tell", O: "opportunity_cannot_tell", EE: "ease_of_exploit_cannot_tell",
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

// Privacy violation's answers are the config's bands, in their order and at
// their levels, each with a text of its own, and a declared band caps at its
// level: the answer and the cap are one table.
func TestPrivacyAnswersAreTheConfigsBands(t *testing.T) {
	bands := riskconfig.DataSubjectsBands()
	answers := privacyViolation.answers
	if len(answers) != len(bands)+1 || answers[len(bands)].id != cannotTell {
		t.Fatalf("Privacy violation lists %d answers, want the %d bands then cannot_tell", len(answers), len(bands))
	}
	for i, b := range bands {
		a := answers[i]
		if a.id != b.Name || a.value != b.Level || a.text == "" {
			t.Errorf("answer %d is %s at %d (text %q), want band %s at %d with a text", i, a.id, a.value, a.text, b.Name, b.Level)
		}
		if got := band(b.Name); got != b.Level {
			t.Errorf("data_subjects %s caps at %d, its band's level is %d", b.Name, got, b.Level)
		}
	}
	if got := answers[len(bands)].value; got != owasp.PrivacyViolationMillionsOfPeople {
		t.Errorf("cannot_tell maps to %d, want the largest band's 9", got)
	}
	// Built from another table, the answers follow it.
	other := []riskconfig.Band{{Name: "few", Level: owasp.PrivacyViolationOneIndividual}, {Name: "many", Level: owasp.PrivacyViolationThousandsOfPeople}}
	got := contract[owasp.PrivacyViolation]{answers: bandAnswers(other, map[string]string{"few": "Few.", "many": "Many."})}
	if want := "few=3 many=7 cannot_tell=7"; leveled(got) != want {
		t.Errorf("bandAnswers over another table = %s, want %s", leveled(got), want)
	}
}

// The tables Go crosses the split factors' answers with, and the levels it
// sets alone.
func TestCrossedLevels(t *testing.T) {
	lc := map[string][2]int{noImpactID: {2, 2}, "minimal": {2, 6}, "extensive": {6, 7}, "all": {9, 9}, cannotTell: {9, 9}}
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

// belowScale is one technical impact question, its answers at the lowest
// level, and the config states its rule reads.
type belowScale struct {
	factor  Factor
	set     func(*Answers, string)
	list    []string
	lowest  []string
	configs []Deployment
}

func belowScaleCases() []belowScale {
	var sensitive, traced []Deployment
	for _, ds := range sensitivities {
		d := base()
		d.DataSensitivity.Value = ds
		sensitive = append(sensitive, d)
	}
	for _, tr := range []*string{nil, ptr("none"), ptr("per_request"), ptr("per_individual")} {
		d := base()
		d.Traceability = tr
		traced = append(traced, d)
	}
	required := base()
	required.AvailabilityRequirement = &Setting{"critical", "Zero downtime tolerance"}
	below := []string{noImpactID}
	return []belowScale{
		{LC, func(a *Answers, id string) { a.LC = id }, ids(confidentiality), below, sensitive},
		{LI, func(a *Answers, id string) { a.LI = id }, ids(integrity), below, []Deployment{base()}},
		{LAV, func(a *Answers, id string) { a.LAV = id }, ids(availability), below, []Deployment{base(), required}},
		{LAC, func(a *Answers, id string) { a.LAC = id }, ids(accountability), []string{"identified"}, traced},
	}
}

// No impact, and Loss of accountability's identified, its no accountability
// loss, are answers, not cannot_tell: read as answered and counted as
// nothing, they take the factor's floor, Loss of accountability's the lowest
// level its traceability column gives, under every config state and
// adjustment. They keep or lower: no other answer, an id off the list or
// cannot_tell gives a lower level, and cannot_tell still gives the worst.
func TestBelowTheScaleAnswersTakeTheLowestLevel(t *testing.T) {
	adjustments := []*Adjusted{nil}
	for _, adj := range adjustedAxis {
		adjustments = append(adjustments, &Adjusted{Confidentiality: adj, Integrity: adj, Availability: adj})
	}
	for _, c := range belowScaleCases() {
		for _, d := range c.configs {
			var all []int
			for _, id := range append(slices.Clone(c.list), "bogus") {
				var a Answers
				c.set(&a, id)
				all = append(all, level(t, string(c.factor), d, [3]bool{}, a, nil))
			}
			lowest, worst := slices.Min(all), slices.Max(all)
			for _, id := range c.lowest {
				for _, adjusted := range adjustments {
					var a Answers
					c.set(&a, id)
					l := compute(t, d, [3]bool{}, a, adjusted)
					if got := levels(l.Vector)[string(c.factor)]; got != lowest {
						t.Errorf("%s %s (traceability %v, adjusted %+v): level %d, want the lowest, %d", c.factor, id, d.Traceability, adjusted, got, lowest)
					}
					if l.Readings[c.factor] != Answered || l.Sources[c.factor] != SourceAnswer {
						t.Errorf("%s %s: read %v from %v, want answered from the answer", c.factor, id, l.Readings[c.factor], l.Sources[c.factor])
					}
					if slices.Contains(l.Counters, c.factor.Counter()) {
						t.Errorf("%s %s counted %s", c.factor, id, c.factor.Counter())
					}
				}
			}
			var a Answers
			c.set(&a, cannotTell)
			if got := level(t, string(c.factor), d, [3]bool{}, a, nil); got != worst {
				t.Errorf("%s cannot_tell: level %d, want the worst, %d", c.factor, got, worst)
			}
		}
	}
	// The floors as numbers: LC 2, LI 1, LAV 1, and LAC 7 undeclared, under
	// none and per_request, 1 under per_individual.
	want := map[Factor][]int{LC: {2, 2, 2, 2}, LI: {1}, LAV: {1, 1}, LAC: {7, 7, 7, 1}}
	for _, c := range belowScaleCases() {
		for i, d := range c.configs {
			for _, id := range c.lowest {
				var a Answers
				c.set(&a, id)
				if got := level(t, string(c.factor), d, [3]bool{}, a, nil); got != want[c.factor][i] {
					t.Errorf("%s %s in config %d: %d, want %d", c.factor, id, i, got, want[c.factor][i])
				}
			}
		}
	}
}

// Loss of accountability's no-loss row is, column by column, the lowest
// level any answer gives: never one the records in place cannot back.
func TestNoAccountabilityLossIsTheLowestOfItsColumn(t *testing.T) {
	for column, tr := range traceabilities {
		lowest := accountabilityLevels[actorDefeatsAttribution][column]
		for _, row := range accountabilityLevels {
			lowest = min(lowest, row[column])
		}
		if got := accountabilityLevels[actorNoLoss][column]; got != lowest {
			t.Errorf("no loss under %s: %d, the column's lowest is %d", tr, got, lowest)
		}
	}
}

// Reachability is defined once, in the system prompt every call shares, and
// asked once, by its own question, which refers to that definition: only its
// not_reachable answer says the vulnerable code is not reachable, in the
// definition's words. No other question or answer judges reachability, so
// none can contradict that answer. Loss of confidentiality, integrity and
// availability list no_impact first, Loss of accountability identified.
func TestReachabilityIsDefinedOnceAndReadTheSameWay(t *testing.T) {
	system, err := SystemPrompt(base())
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"A vulnerability is reachable here when", "It is not reachable here only when the facts given show it"} {
		if n := strings.Count(system, part); n != 1 {
			t.Errorf("the system prompt says %q %d times, want once", part, n)
		}
	}
	if q := table[R]; !strings.HasSuffix(q.question, "as reachability is defined above?") || !strings.Contains(q.question, "{group}") {
		t.Errorf("reachability's question: %q", q.question)
	}
	if got := ids(reachability); !slices.Equal(got, []string{"reachable", notReachableID, cannotTell}) {
		t.Errorf("reachability lists %v", got)
	}
	for f, q := range table {
		if f != R && strings.Contains(q.question, "reachab") {
			t.Errorf("%s's question speaks of reachability, which its own question asks", f)
		}
		for i, text := range q.texts {
			says := strings.Contains(text, "not reachable")
			if says != (f == R && q.ids[i] == notReachableID) {
				t.Errorf("%s %s: says not reachable: %t", f, q.ids[i], says)
			}
			if says && text != notReachableText {
				t.Errorf("%s %s says not reachable in its own words: %q", f, q.ids[i], text)
			}
		}
	}
	for _, f := range []Factor{LC, LI, LAV, LAC} {
		first := noImpactID
		if f == LAC {
			first = "identified"
		}
		if q := table[f]; q.ids[0] != first || slices.Contains(q.ids, notReachableID) {
			t.Errorf("%s lists %v, want %s first and no not_reachable", f, q.ids, first)
		}
	}
	if slices.Contains(table[LAC].ids, noImpactID) {
		t.Error("Loss of accountability lists no_impact: identified is its no accountability loss")
	}
	for answer, want := range map[string]bool{"reachable": true, notReachableID: false, cannotTell: true, "": true, "bogus": true} {
		if got := Reachable(answer); got != want {
			t.Errorf("Reachable(%q) = %t, want %t", answer, got, want)
		}
	}
}

// cannot_tell on reachability and the four technical impact questions says
// only that the facts do not decide between the answers listed, not
// reachable and no impact included.
func TestImpactCannotTellOnlyMeansTheFactsDoNotDecide(t *testing.T) {
	for _, f := range Order() {
		q := table[f]
		want := cannotTellText
		switch f {
		case R, LC, LI, LAV, LAC:
			want = impactCannotTellText
		case ID:
			continue
		}
		if got := q.texts[len(q.texts)-1]; got != want {
			t.Errorf("%s's cannot_tell reads %q, want %q", f, got, want)
		}
	}
	if !strings.Contains(systemTemplate, "Choose cannot_tell only when the facts given do not decide between the other answers") {
		t.Error("the system prompt no longer limits cannot_tell to facts that do not decide")
	}
}

// Loss of accountability asks authentication and attribution as two facts,
// not whether records exist, and its identified answer, no accountability
// loss, needs the attacker to authenticate: under none, an attacker who need
// not authenticate is completely anonymous, 9, where identified is 7.
func TestAccountabilityAsksAuthenticationAndAttributionApart(t *testing.T) {
	q := table[LAC]
	for _, part := range []string{"must {group} authenticate to this service under an identity of their own?", "Apart from that,", "records of who did what", "Answer the two facts separately; whether records exist is not asked."} {
		if !strings.Contains(q.question, part) {
			t.Errorf("Loss of accountability's question lacks %q: %q", part, q.question)
		}
	}
	if identified := q.texts[slices.Index(q.ids, "identified")]; !strings.HasPrefix(identified, "Identified, no accountability loss: they must authenticate") {
		t.Errorf("identified: %q", identified)
	}
	if unidentified := q.texts[slices.Index(q.ids, "unidentified")]; !strings.Contains(unidentified, "no service to authenticate to") {
		t.Errorf("unidentified does not cover a deployment with no service to authenticate to: %q", unidentified)
	}
	for column, tr := range traceabilities {
		if accountabilityLevels[actorUnidentified][column] < accountabilityLevels[actorNoLoss][column] {
			t.Errorf("under %s, unidentified is below identified", tr)
		}
	}
	if accountabilityLevels[actorUnidentified][0] <= accountabilityLevels[actorNoLoss][0] {
		t.Error("under none, not having to authenticate gives identified's level")
	}
}

// Ease of exploit is judged from where the attacker group already is, as
// Opportunity counts only what they need beyond what they have: the
// exposure's own access control is part of the group, not a control in front
// of the deployment.
func TestEaseOfExploitStartsFromWhereTheGroupAlreadyIs(t *testing.T) {
	if q := table[EE].question; !strings.Contains(q, "{group}, from where they already are,") ||
		!strings.Contains(q, "Any access control the exposure itself requires") || !strings.Contains(q, "{group} are already past it") {
		t.Errorf("Ease of exploit's question: %q", q)
	}
	if q := table[O].question; !strings.Contains(q, "beyond what they already have") {
		t.Errorf("Opportunity's question: %q", q)
	}
	for _, e := range []string{"internal", "private", "internet"} {
		d := base()
		d.Exposure.Value = e
		request, err := Request(EE, d, cvssBatch)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(request, "{group}") || !strings.Contains(request, exposures[e].group+" are already past it") {
			t.Errorf("%s: the group is not filled in Ease of exploit's question", e)
		}
	}
}

// Intrusion detection is skipped only where every answer it permits, any set
// of channels, cannot_tell, an empty set or an id off the list, gives the
// same level: a channel at 8 beside two at 9 still asks it.
func TestIntrusionDetectionAskedExactlyWhereAnAnswerCanMoveIt(t *testing.T) {
	for _, det := range detections() {
		d := base()
		d.Detection = det
		reached := map[int]bool{}
		for _, set := range channelSets() {
			reached[level(t, "ID", d, [3]bool{}, Answers{ID: set}, nil)] = true
		}
		if got := slices.Contains(questions(t, d, [3]bool{}), ID); got != (len(reached) > 1) {
			t.Errorf("detection %+v: asked %t, levels reachable %v", det, got, reached)
		}
	}
	d := base()
	d.Detection = &Detection{Network: "logged", Host: "not_logged", Application: "not_logged"}
	if !slices.Contains(questions(t, d, [3]bool{}), ID) {
		t.Error("a channel logged without review beside two not logged: ID not asked")
	}
}

// Ease of discovery and Awareness stay constant and declared, from no
// source: the same 9 under every exposure, detection, traceability and
// answer.
func TestEaseOfDiscoveryAndAwarenessStayConstant(t *testing.T) {
	for _, e := range []string{"internal", "private", "internet"} {
		for _, det := range detections()[:2] {
			for _, a := range []Answers{{}, {EE: "theoretical", O: "full_access_or_expensive_resources_required", LC: noImpactID}} {
				d := base()
				d.Exposure.Value, d.Detection, d.Traceability = e, det, ptr("per_individual")
				l := compute(t, d, [3]bool{}, a, nil)
				if l.Vector.ED != 9 || l.Vector.A != 9 || l.Sources[ED] != SourceConstant || l.Sources[A] != SourceConstant {
					t.Errorf("%s: ED %d from %v, A %d from %v; want 9 from the constant", e, l.Vector.ED, l.Sources[ED], l.Vector.A, l.Sources[A])
				}
			}
		}
	}
}

// Loss of confidentiality and integrity count everything an exploit repeated
// as often as it can reaches, so no answer weighs whether the attacker
// chooses or repeats; where the deployment's description and notes are
// silent, LC counts whatever the service can read and LAV counts what is
// interrupted as primary.
func TestExtentIsWhatRepeatedExploitsReach(t *testing.T) {
	for f, part := range map[Factor]string{
		LC:  "Count all the distinct data they could read by exploiting it as often as they can.",
		LI:  "Count all the distinct data they could corrupt by exploiting it as often as they can.",
		LAV: "Where they do not say, count what is interrupted as primary.",
	} {
		if !strings.HasSuffix(table[f].question, part) {
			t.Errorf("%s's question does not end with %q: %q", f, part, table[f].question)
		}
	}
	if q := table[LC].question; !strings.Contains(q, "Where they do not say, it handles whatever the service can read.") {
		t.Errorf("LC's question: %q", q)
	}
	for _, f := range []Factor{LC, LI} {
		for i, text := range table[f].texts {
			for _, word := range []string{"choose", "keep reading", "again and again"} {
				if strings.Contains(text, word) {
					t.Errorf("%s %s weighs the attacker's choice or repetition: %q", f, table[f].ids[i], text)
				}
			}
		}
	}
}
