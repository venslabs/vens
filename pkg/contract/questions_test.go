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
	"maps"
	"slices"
	"testing"

	"github.com/venslabs/vens/pkg/cvss"
)

func questions(t *testing.T, d Deployment, floored [3]bool) []Factor {
	t.Helper()
	q, err := Questions(d, floored)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

var (
	allFloored = [3]bool{true, true, true}
	cFloored   = [3]bool{cvss.Confidentiality: true}
)

// declared declares every field the rules read, at values that leave every
// question asked.
func declared() Deployment {
	d := base()
	d.Frameworks = []string{"PCI-DSS"}
	d.Traceability = ptr("per_request")
	d.DataSubjects = ptr("thousands")
	d.Detection = &Detection{Network: "logged", Host: "not_logged", Application: "logged_and_reviewed"}
	return d
}

func TestQuestionsInTheDeclaredOrder(t *testing.T) {
	if got := questions(t, declared(), [3]bool{}); !slices.Equal(got, Order()) {
		t.Errorf("every field declared, nothing floored: %v, want %v", got, Order())
	}
	if got, want := questions(t, base(), allFloored), []Factor{M, O, EE, LAC, FD, RD}; !slices.Equal(got, want) {
		t.Errorf("nothing declared, every axis floored: %v, want %v", got, want)
	}
	order := Order()
	order[0] = PV
	if Order()[0] != M {
		t.Error("Order shares its slice with the package")
	}
}

// What is not asked: LC and PV when C is floored, LI when I is, LAV when A
// is, ID when detection is undeclared or declared at one level, NC when no
// framework is declared, PV when data_subjects caps it at the lowest level.
func TestQuestionsNotAsked(t *testing.T) {
	uniform := declared()
	uniform.Detection = &Detection{Network: "logged", Host: "logged", Application: "logged"}
	undeclared := declared()
	undeclared.Detection = nil
	noFramework := declared()
	noFramework.Frameworks = nil
	none, one, hundreds, unset := declared(), declared(), declared(), declared()
	none.DataSubjects, one.DataSubjects, hundreds.DataSubjects, unset.DataSubjects = ptr("none"), ptr("one_individual"), ptr("hundreds"), nil
	for _, c := range []struct {
		name    string
		d       Deployment
		floored [3]bool
		missing []Factor
	}{
		{"C floored", declared(), cFloored, []Factor{LC, PV}},
		{"I floored", declared(), [3]bool{cvss.Integrity: true}, []Factor{LI}},
		{"A floored", declared(), [3]bool{cvss.Availability: true}, []Factor{LAV}},
		{"detection undeclared", undeclared, [3]bool{}, []Factor{ID}},
		{"detection at one level", uniform, [3]bool{}, []Factor{ID}},
		{"no framework", noFramework, [3]bool{}, []Factor{NC}},
		{"data_subjects none", none, [3]bool{}, []Factor{PV}},
		{"data_subjects one_individual", one, [3]bool{}, []Factor{PV}},
		{"data_subjects hundreds", hundreds, [3]bool{}, nil},
		{"data_subjects undeclared", unset, [3]bool{}, nil},
	} {
		want := slices.DeleteFunc(Order(), func(f Factor) bool { return slices.Contains(c.missing, f) })
		if got := questions(t, c.d, c.floored); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", c.name, got, want)
		}
	}
}

// The CVE whose only vector is v4, its three V metrics at N, SC and SI at L
// and SA at N: an impact on subsequent systems alone keeps C and I
// applicable, so LC, LI and PV are asked and LAV is not.
func TestQuestionsOnASubsequentSystemsOnlyV4Vector(t *testing.T) {
	a := cvss.ApplicabilityOf([]cvss.Vector{{Source: "nvd", Version: "4.0",
		Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"}})
	got := questions(t, declared(), a.Floored)
	for _, f := range []Factor{LC, LI, PV} {
		if !slices.Contains(got, f) {
			t.Errorf("%s not asked: %v", f, got)
		}
	}
	if slices.Contains(got, LAV) {
		t.Errorf("LAV asked with VA and SA at N: %v", got)
	}
}

// A question not asked takes the level Go decides and counts nothing, even
// fed an answer that would count.
func TestNotAskedTakesGosLevelAndCountsNothing(t *testing.T) {
	all := Answers{M: "high_reward", O: cannotTell, EE: cannotTell, ID: []string{cannotTell}, LC: cannotTell,
		LI: cannotTell, LAV: cannotTell, LAC: cannotTell, FD: cannotTell, RD: cannotTell, NC: cannotTell, PV: cannotTell}
	d := declared()
	d.Detection = &Detection{Network: "logged", Host: "logged", Application: "logged"}
	d.DataSubjects = ptr("one_individual")
	d.Frameworks = nil
	l := compute(t, d, allFloored, all, nil)
	want := map[string]int{"ID": 8, "LC": 2, "LI": 1, "LAV": 1, "NC": 2, "PV": 3}
	got := levels(l.Vector)
	for f, w := range want {
		if got[f] != w {
			t.Errorf("%s = %d, want %d", f, got[f], w)
		}
	}
	for _, f := range []Factor{ID, LC, LI, LAV, NC, PV} {
		if _, read := l.Readings[f]; read {
			t.Errorf("%s not asked, yet read %v", f, l.Readings[f])
		}
	}
	for _, c := range l.Counters {
		switch c {
		case "intrusion_detection_cannot_tell", "confidentiality_cannot_tell", "integrity_cannot_tell",
			"availability_cannot_tell", "non_compliance_cannot_tell", "privacy_cannot_tell", "data_subjects_missing":
			t.Errorf("a question not asked counted %s", c)
		}
	}
	// C floored also floors PV, whatever data_subjects caps.
	d.DataSubjects = ptr("millions")
	if got := level(t, "PV", d, cFloored, all, nil); got != 3 {
		t.Errorf("PV with C floored = %d, want 3", got)
	}
}

// cannot_tell, or an answer off the list, takes each factor's worst case and
// counts it.
func TestCannotTellLevelsAndCounters(t *testing.T) {
	cases := []struct {
		factor  Factor
		set     func(*Answers, string)
		level   int
		counter string
	}{
		{M, func(a *Answers, s string) { a.M = s }, 9, "motive_cannot_tell"},
		{O, func(a *Answers, s string) { a.O = s }, 9, "opportunity_cannot_tell"},
		{EE, func(a *Answers, s string) { a.EE = s }, 9, "ease_of_exploit_cannot_tell"},
		{ID, func(a *Answers, s string) { a.ID = []string{s} }, 9, "intrusion_detection_cannot_tell"},
		{LC, func(a *Answers, s string) { a.LC = s }, 9, "confidentiality_cannot_tell"},
		{LI, func(a *Answers, s string) { a.LI = s }, 9, "integrity_cannot_tell"},
		{LAV, func(a *Answers, s string) { a.LAV = s }, 9, "availability_cannot_tell"},
		{LAC, func(a *Answers, s string) { a.LAC = s }, 9, "accountability_cannot_tell"},
		{FD, func(a *Answers, s string) { a.FD = s }, 9, "financial_damage_cannot_tell"},
		{RD, func(a *Answers, s string) { a.RD = s }, 9, "reputation_cannot_tell"},
		{NC, func(a *Answers, s string) { a.NC = s }, 7, "non_compliance_cannot_tell"},
		{PV, func(a *Answers, s string) { a.PV = s }, 9, "privacy_cannot_tell"},
	}
	d := declared()
	d.Traceability = ptr("per_individual")
	d.DataSubjects = ptr("millions")
	d.Detection = &Detection{Network: "logged", Host: "not_logged", Application: activeInApplication}
	for _, c := range cases {
		for _, raw := range []string{cannotTell, "", "bogus", "High_Reward"} {
			var a Answers
			c.set(&a, raw)
			l := compute(t, d, [3]bool{}, a, nil)
			want := CannotTell
			if raw != cannotTell {
				want = Invalid
			}
			if got := levels(l.Vector)[string(c.factor)]; got != c.level {
				t.Errorf("%s %q: level %d, want %d", c.factor, raw, got, c.level)
			}
			if l.Readings[c.factor] != want {
				t.Errorf("%s %q: read %v, want %v", c.factor, raw, l.Readings[c.factor], want)
			}
			if !slices.Contains(l.Counters, c.counter) {
				t.Errorf("%s %q: counters %v lack %s", c.factor, raw, l.Counters, c.counter)
			}
		}
	}
}

// Intrusion detection's set: a channel twice counts once; an empty set, one
// holding cannot_tell and one holding an id off the list read as
// cannot_tell, the highest of the three channels.
func TestIntrusionDetectionSets(t *testing.T) {
	d := base()
	d.Detection = &Detection{Network: "logged", Host: "logged_and_reviewed", Application: activeInApplication}
	for _, c := range []struct {
		set     []string
		level   int
		reading Reading
	}{
		{[]string{"network"}, 8, Answered},
		{[]string{"network", "network"}, 8, Answered},
		{[]string{"network", "host"}, 3, Answered},
		{[]string{"host", "application"}, 1, Answered},
		{nil, 8, Invalid},
		{[]string{}, 8, Invalid},
		{[]string{cannotTell}, 8, CannotTell},
		{[]string{cannotTell, "host"}, 8, CannotTell},
		{[]string{"application", cannotTell}, 8, CannotTell},
		{[]string{"bogus"}, 8, Invalid},
		{[]string{"application", "bogus"}, 8, Invalid},
	} {
		l := compute(t, d, [3]bool{}, Answers{ID: c.set}, nil)
		if got := int(l.Vector.ID); got != c.level || l.Readings[ID] != c.reading {
			t.Errorf("%q: ID %d read %v, want %d read %v", c.set, got, l.Readings[ID], c.level, c.reading)
		}
	}
}

// An undeclared field a rule falls back on is counted once per CVE, and only
// where the rule reads it.
func TestUndeclaredFieldsCounted(t *testing.T) {
	answered := Answers{M: "possible_reward", O: "some_access_or_resources_required", EE: "easy", ID: []string{"network"},
		LC: "minimal", LI: "minimal_slightly_corrupt", LAV: "minimal_primary_interrupted", LAC: "identified",
		FD: "bankruptcy", RD: "minimal_damage", NC: "clear_violation", PV: "hundreds"}
	if got := compute(t, declared(), [3]bool{}, answered, nil).Counters; len(got) != 0 {
		t.Errorf("every field declared and every answer listed: counters %v", got)
	}
	got := compute(t, base(), [3]bool{}, answered, nil).Counters
	if want := []string{"detection_undeclared", "traceability_missing", "data_subjects_missing"}; !slices.Equal(got, want) {
		t.Errorf("nothing declared: counters %v, want %v", got, want)
	}
	// With C floored Privacy violation is not asked, so data_subjects is not
	// read.
	got = compute(t, base(), cFloored, answered, nil).Counters
	if want := []string{"detection_undeclared", "traceability_missing"}; !slices.Equal(got, want) {
		t.Errorf("nothing declared, C floored: counters %v, want %v", got, want)
	}
	if l := compute(t, base(), [3]bool{}, answered, nil); levels(l.Vector)["ID"] != 9 || levels(l.Vector)["LAC"] != 7 {
		t.Errorf("undeclared detection and traceability: ID %d, LAC %d, want 9 and 7", l.Vector.ID, l.Vector.LAC)
	}
}

// The adjustment never raises a level. Only Opportunity, LC, LI, LAV and PV
// can move; keep, affected, cannot_tell and anything off the lists leave
// the baseline; C not_affected gives LC 2 and PV 3.
func TestAdjustmentNeverRaises(t *testing.T) {
	d := declared()
	d.DataSensitivity.Value = "critical"
	d.DataSubjects = ptr("millions")
	baselines := []Answers{
		{O: "no_access_or_resources_required", LC: "all", LI: "all_data_totally_corrupt", LAV: "all_services_completely_lost", PV: "millions"},
		{O: "special_access_or_resources_required", LC: "minimal", LI: "minimal_slightly_corrupt", LAV: "minimal_secondary_interrupted", PV: "none"},
		{O: cannotTell, LC: cannotTell, LI: cannotTell, LAV: cannotTell, PV: cannotTell},
	}
	adjustments := append(append([]string{"", keep, "bogus"}, ids(opportunity)...), adjustedAxis...)
	for _, a := range baselines {
		before := levels(compute(t, d, [3]bool{}, a, nil).Vector)
		for _, o := range adjustments {
			for _, axis := range adjustments {
				adj := &Adjusted{Opportunity: o, Confidentiality: axis, Integrity: axis, Availability: axis}
				after := levels(compute(t, d, [3]bool{}, a, adj).Vector)
				for f, b := range before {
					moved := after[f] != b
					if after[f] > b || (moved && !slices.Contains([]string{"O", "LC", "LI", "LAV", "PV"}, f)) {
						t.Errorf("%+v adjusted by %+v: %s went from %d to %d", a, *adj, f, b, after[f])
					}
				}
			}
		}
	}
	a := baselines[0]
	for _, c := range []struct {
		adj  Adjusted
		want map[string]int
	}{
		{Adjusted{Opportunity: keep}, map[string]int{"O": 9}},
		{Adjusted{Opportunity: cannotTell}, map[string]int{"O": 9}},
		{Adjusted{Opportunity: "full_access_or_expensive_resources_required"}, map[string]int{"O": 0}},
		{Adjusted{Confidentiality: notAffected}, map[string]int{"LC": 2, "PV": 3, "LI": 9}},
		{Adjusted{Confidentiality: affected, Integrity: notAffected}, map[string]int{"LC": 9, "LI": 1, "PV": 9}},
		{Adjusted{Availability: notAffected}, map[string]int{"LAV": 1}},
		{Adjusted{Availability: cannotTell}, map[string]int{"LAV": 9}},
	} {
		got := levels(compute(t, d, [3]bool{}, a, &c.adj).Vector)
		for f, w := range c.want {
			if got[f] != w {
				t.Errorf("%+v: %s = %d, want %d", c.adj, f, got[f], w)
			}
		}
	}
	// The adjustment's own cannot_tell is not counted.
	abstained := &Adjusted{Opportunity: cannotTell, Confidentiality: cannotTell, Integrity: cannotTell, Availability: cannotTell}
	if before, after := compute(t, d, [3]bool{}, a, nil).Counters, compute(t, d, [3]bool{}, a, abstained).Counters; !slices.Equal(before, after) {
		t.Errorf("the adjustment's cannot_tell counted: %v, then %v", before, after)
	}
}

func TestComputeRefusesAnInvalidDeployment(t *testing.T) {
	d := base()
	d.Exposure.Value = "public"
	if _, err := Compute(d, describedCVE, [3]bool{}, Answers{}, nil); err == nil {
		t.Error("Compute took an exposure off its list")
	}
	for _, c := range []CVE{{ID: "CVE-X"}, {Rows: []Row{{}}}} {
		if _, err := Compute(base(), c, [3]bool{}, Answers{}, nil); err == nil {
			t.Errorf("Compute took %+v", c)
		}
	}
	if _, err := Questions(d, [3]bool{}); err == nil {
		t.Error("Questions took an exposure off its list")
	}
}

func TestReadingsHoldEveryQuestionAsked(t *testing.T) {
	for _, floored := range [][3]bool{{}, cFloored, allFloored} {
		for _, d := range []Deployment{base(), declared()} {
			l := compute(t, d, floored, Answers{}, nil)
			if got, want := slices.Sorted(maps.Keys(l.Readings)), slices.Sorted(slices.Values(questions(t, d, floored))); !slices.Equal(got, want) {
				t.Errorf("readings for %v, questions %v", got, want)
			}
		}
	}
}

// With no description on any row, Motive, Opportunity and Ease of exploit
// read whatever they were answered as cannot_tell: 9, each counted once. The
// questions are still asked, and the rest reads as usual.
func TestNoDescriptionReadsTheLikelihoodAnswersAsCannotTell(t *testing.T) {
	answers := Answers{M: "low_or_no_reward", O: "full_access_or_expensive_resources_required", EE: cannotTell,
		LC: "minimal", LAC: "identified", FD: "bankruptcy", RD: "minimal_damage"}
	for _, rows := range [][]Row{
		{{PkgName: "liba"}},
		{{PkgName: "liba", Description: " \n"}, {PkgName: "libb"}},
	} {
		l := computeFor(t, base(), CVE{ID: "CVE-N", Rows: rows}, [3]bool{}, answers, nil)
		got := levels(l.Vector)
		for _, f := range []Factor{M, O, EE} {
			if got[string(f)] != 9 || l.Readings[f] != NoDescription || l.Sources[f] != SourceAnswer {
				t.Errorf("%s: level %d read %v from %v, want 9 read as no description", f, got[string(f)], l.Readings[f], l.Sources[f])
			}
		}
		for _, counter := range []string{"motive_cannot_tell", "opportunity_cannot_tell", "ease_of_exploit_cannot_tell"} {
			if n := len(slices.DeleteFunc(slices.Clone(l.Counters), func(c string) bool { return c != counter })); n != 1 {
				t.Errorf("%s counted %d times: %v", counter, n, l.Counters)
			}
		}
		if got["LC"] != 2 || l.Readings[LC] != Answered {
			t.Errorf("LC = %d read %v, want its answer's 2", got["LC"], l.Readings[LC])
		}
	}
	// One row with a description is enough to read the answers.
	c := CVE{ID: "CVE-N", Rows: []Row{{PkgName: "liba"}, {PkgName: "libb", Description: "Described."}}}
	if got := levels(computeFor(t, base(), c, [3]bool{}, answers, nil).Vector); got["M"] != 1 || got["O"] != 0 {
		t.Errorf("one row described: M %d, O %d, want 1 and 0", got["M"], got["O"])
	}
	// The adjustment can still lower Opportunity from there.
	l := computeFor(t, base(), CVE{ID: "CVE-N", Rows: []Row{{PkgName: "liba"}}}, [3]bool{}, answers,
		&Adjusted{Opportunity: "special_access_or_resources_required"})
	if l.Vector.O != 4 || l.Sources[O] != SourceAdjustment {
		t.Errorf("adjusted with no description: O %d from %v, want 4 from the adjustment", l.Vector.O, l.Sources[O])
	}
}

// An adjustment lowers Opportunity below a cannot_tell baseline of 9, which
// still counts.
func TestAdjustmentLowersACannotTellBaseline(t *testing.T) {
	l := compute(t, base(), [3]bool{}, Answers{O: cannotTell}, &Adjusted{Opportunity: "special_access_or_resources_required"})
	if l.Vector.O != 4 || l.Readings[O] != CannotTell || l.Sources[O] != SourceAdjustment || !slices.Contains(l.Counters, "opportunity_cannot_tell") {
		t.Errorf("O %d read %v from %v, counters %v", l.Vector.O, l.Readings[O], l.Sources[O], l.Counters)
	}
}

// A question skipped because no answer could move its level ignores a junk
// answer and the adjustment alike: ID keeps the one declared level and PV the
// floor data_subjects sets, neither read nor counted, while the factors
// asked take the adjustment.
func TestSkippedQuestionsIgnoreJunkAndTheAdjustment(t *testing.T) {
	d := declared()
	d.Detection = &Detection{Network: "logged_and_reviewed", Host: "logged_and_reviewed", Application: "logged_and_reviewed"}
	d.DataSubjects = ptr("none")
	a := Answers{M: "high_reward", O: "no_access_or_resources_required", EE: "easy", ID: []string{"bogus"},
		LC: "all", LI: "all_data_totally_corrupt", LAV: "all_services_completely_lost", LAC: "unidentified",
		FD: "bankruptcy", RD: "brand_damage", NC: "high_profile_violation", PV: "bogus"}
	adjusted := &Adjusted{Opportunity: "special_access_or_resources_required", Confidentiality: notAffected,
		Integrity: notAffected, Availability: notAffected}
	l := compute(t, d, [3]bool{}, a, adjusted)
	got := levels(l.Vector)
	for f, w := range map[string]int{"ID": 3, "PV": 3, "O": 4, "LC": 2, "LI": 1, "LAV": 1} {
		if got[f] != w {
			t.Errorf("%s = %d, want %d", f, got[f], w)
		}
	}
	for f, w := range map[Factor]Source{ID: SourceConfig, PV: SourceConfig, O: SourceAdjustment, LC: SourceAdjustment, LI: SourceAdjustment, LAV: SourceAdjustment} {
		if l.Sources[f] != w {
			t.Errorf("%s from %v, want %v", f, l.Sources[f], w)
		}
	}
	for _, f := range []Factor{ID, PV} {
		if _, read := l.Readings[f]; read {
			t.Errorf("%s not asked, yet read", f)
		}
	}
	if len(l.Counters) != 0 {
		t.Errorf("counters %v", l.Counters)
	}
}
