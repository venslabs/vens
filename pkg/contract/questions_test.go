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

func questions(t *testing.T, d Deployment) []Factor {
	t.Helper()
	q, err := Questions(d, describedCVE)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

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
	if got := questions(t, declared()); !slices.Equal(got, Order()) {
		t.Errorf("every field declared: %v, want %v", got, Order())
	}
	if got, want := questions(t, base()), []Factor{M, O, EE, LAC, FD, RD, PV}; !slices.Equal(got, want) {
		t.Errorf("nothing declared: %v, want %v", got, want)
	}
	if want := []Factor{M, O, EE, ID, LAC, FD, RD, NC, PV}; !slices.Equal(Order(), want) {
		t.Errorf("Order() = %v, want %v", Order(), want)
	}
	order := Order()
	order[0] = PV
	if Order()[0] != M {
		t.Error("Order shares its slice with the package")
	}
}

// What is not asked: ID when detection is undeclared or declared at one
// level, NC when no framework is declared, PV when data_subjects caps it at
// the lowest level, and M, O and EE when no row describes the CVE, a title
// alone or a blank description included; one row described of two is
// enough. Loss of confidentiality, integrity and availability are never
// asked, and no vector stops Privacy violation.
func TestQuestionsNotAsked(t *testing.T) {
	titled := CVE{ID: "CVE-N", Rows: []Row{{PkgName: "liba", Title: "[Privilege escalation possible to other user than root]"}}}
	blank := CVE{ID: "CVE-N", Rows: []Row{{PkgName: "liba", Description: " \n\t"}, {PkgName: "libb"}}}
	oneOfTwo := CVE{ID: "CVE-N", Rows: []Row{{PkgName: "liba"}, {PkgName: "libb", Description: "Described."}}}
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
		cve     CVE
		missing []Factor
	}{
		{"detection undeclared", undeclared, describedCVE, []Factor{ID}},
		{"detection at one level", uniform, describedCVE, []Factor{ID}},
		{"no framework", noFramework, describedCVE, []Factor{NC}},
		{"data_subjects none", none, describedCVE, []Factor{PV}},
		{"data_subjects one_individual", one, describedCVE, []Factor{PV}},
		{"data_subjects hundreds", hundreds, describedCVE, nil},
		{"data_subjects undeclared", unset, describedCVE, nil},
		{"a title alone", declared(), titled, []Factor{M, O, EE}},
		{"a blank description", declared(), blank, []Factor{M, O, EE}},
		{"no description, nothing declared", base(), titled, []Factor{M, O, EE, ID, NC}},
		{"one row described of two", declared(), oneOfTwo, nil},
		{"every axis at N", declared(), impactCVE("N", "N", "N"), nil},
		{"no vector", declared(), impactCVE("", "", ""), nil},
	} {
		want := slices.DeleteFunc(Order(), func(f Factor) bool { return slices.Contains(c.missing, f) })
		got, err := Questions(c.d, c.cve)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", c.name, got, want)
		}
	}
}

// A question not asked takes the level Go decides and counts nothing, even
// fed an answer that would count.
func TestNotAskedTakesGosLevelAndCountsNothing(t *testing.T) {
	all := Answers{M: "high_reward", O: cannotTell, EE: cannotTell, ID: []string{cannotTell},
		LAC: cannotTell, FD: cannotTell, RD: cannotTell, NC: cannotTell, PV: cannotTell}
	d := declared()
	d.Detection = &Detection{Network: "logged", Host: "logged", Application: "logged"}
	d.DataSubjects = ptr("one_individual")
	d.Frameworks = nil
	l := compute(t, d, all, nil)
	want := map[string]int{"ID": 8, "NC": 2, "PV": 3}
	got := levels(l.Vector)
	for f, w := range want {
		if got[f] != w {
			t.Errorf("%s = %d, want %d", f, got[f], w)
		}
	}
	for _, f := range []Factor{ID, NC, PV} {
		if _, read := l.Readings[f]; read {
			t.Errorf("%s not asked, yet read %v", f, l.Readings[f])
		}
	}
	for _, c := range l.Counters {
		switch c {
		case "intrusion_detection_cannot_tell", "non_compliance_cannot_tell", "privacy_cannot_tell", "data_subjects_missing":
			t.Errorf("a question not asked counted %s", c)
		}
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
			l := compute(t, d, a, nil)
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
		l := compute(t, d, Answers{ID: c.set}, nil)
		if got := int(l.Vector.ID); got != c.level || l.Readings[ID] != c.reading {
			t.Errorf("%q: ID %d read %v, want %d read %v", c.set, got, l.Readings[ID], c.level, c.reading)
		}
	}
}

// An undeclared field a rule falls back on is counted once per CVE, and only
// where the rule reads it.
func TestUndeclaredFieldsCounted(t *testing.T) {
	answered := Answers{M: "possible_reward", O: "some_access_or_resources_required", EE: "easy", ID: []string{"network"},
		LAC: "identified", FD: "bankruptcy", RD: "minimal_damage", NC: "clear_violation", PV: "hundreds"}
	if got := compute(t, declared(), answered, nil).Counters; len(got) != 0 {
		t.Errorf("every field declared and every answer listed: counters %v", got)
	}
	got := compute(t, base(), answered, nil).Counters
	if want := []string{"detection_undeclared", "traceability_missing", "data_subjects_missing"}; !slices.Equal(got, want) {
		t.Errorf("nothing declared: counters %v, want %v", got, want)
	}
	// Every axis at N no longer keeps Privacy violation from asking, so
	// data_subjects is still read.
	l := computeFor(t, base(), impactCVE("N", "N", "N"), answered, nil)
	if want := []string{"detection_undeclared", "traceability_missing", "data_subjects_missing"}; !slices.Equal(l.Counters, want) {
		t.Errorf("nothing declared, every axis at N: counters %v, want %v", l.Counters, want)
	}
	if l := compute(t, base(), answered, nil); levels(l.Vector)["ID"] != 9 || levels(l.Vector)["LAC"] != 7 {
		t.Errorf("undeclared detection and traceability: ID %d, LAC %d, want 9 and 7", l.Vector.ID, l.Vector.LAC)
	}
}

// The adjustment never raises a level, and moves Opportunity alone; keep,
// cannot_tell and anything off the list leave the baseline.
func TestAdjustmentNeverRaises(t *testing.T) {
	d := declared()
	d.DataSensitivity.Value = "critical"
	d.DataSubjects = ptr("millions")
	baselines := []Answers{
		{O: "no_access_or_resources_required", PV: "millions"},
		{O: "special_access_or_resources_required", PV: "none"},
		{O: cannotTell, PV: cannotTell},
	}
	adjustments := append([]string{"", keep, "bogus", cannotTell}, ids(opportunity)...)
	for _, a := range baselines {
		before := levels(compute(t, d, a, nil).Vector)
		for _, o := range adjustments {
			adj := &Adjusted{Opportunity: o}
			after := levels(compute(t, d, a, adj).Vector)
			for f, b := range before {
				if moved := after[f] != b; after[f] > b || (moved && f != "O") {
					t.Errorf("%+v adjusted by %+v: %s went from %d to %d", a, *adj, f, b, after[f])
				}
			}
		}
	}
	a := baselines[0]
	for _, c := range []struct {
		adj  Adjusted
		want int
	}{
		{Adjusted{Opportunity: keep}, 9},
		{Adjusted{Opportunity: cannotTell}, 9},
		{Adjusted{Opportunity: "full_access_or_expensive_resources_required"}, 0},
	} {
		if got := level(t, "O", d, a, &c.adj); got != c.want {
			t.Errorf("%+v: O = %d, want %d", c.adj, got, c.want)
		}
	}
	// The adjustment's own cannot_tell is not counted.
	abstained := &Adjusted{Opportunity: cannotTell}
	if before, after := compute(t, d, a, nil).Counters, compute(t, d, a, abstained).Counters; !slices.Equal(before, after) {
		t.Errorf("the adjustment's cannot_tell counted: %v, then %v", before, after)
	}
}

func TestComputeRefusesAnInvalidDeployment(t *testing.T) {
	d := base()
	d.Exposure.Value = "public"
	if _, err := Compute(d, describedCVE, Answers{}, nil); err == nil {
		t.Error("Compute took an exposure off its list")
	}
	for _, c := range []CVE{{ID: "CVE-X"}, {Rows: []Row{{}}}} {
		if _, err := Compute(base(), c, Answers{}, nil); err == nil {
			t.Errorf("Compute took %+v", c)
		}
	}
	if _, err := Questions(d, describedCVE); err == nil {
		t.Error("Questions took an exposure off its list")
	}
}

func TestReadingsHoldEveryQuestionAsked(t *testing.T) {
	for _, d := range []Deployment{base(), declared()} {
		l := compute(t, d, Answers{}, nil)
		if got, want := slices.Sorted(maps.Keys(l.Readings)), slices.Sorted(slices.Values(questions(t, d))); !slices.Equal(got, want) {
			t.Errorf("readings for %v, questions %v", got, want)
		}
	}
}

// With no description on any row, Motive, Opportunity and Ease of exploit
// are not asked: whatever answers they hold, each reads no_description and
// takes cannot_tell's 9, counted once. The rest reads as usual.
func TestNoDescriptionReadsTheLikelihoodAnswersAsCannotTell(t *testing.T) {
	answers := Answers{M: "low_or_no_reward", O: "full_access_or_expensive_resources_required", EE: cannotTell,
		LAC: "identified", FD: "bankruptcy", RD: "minimal_damage"}
	for _, rows := range [][]Row{
		{{PkgName: "liba"}},
		{{PkgName: "liba", Description: " \n"}, {PkgName: "libb"}},
	} {
		l := computeFor(t, base(), CVE{ID: "CVE-N", Rows: rows}, answers, nil)
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
		if got["FD"] != 9 || l.Readings[FD] != Answered {
			t.Errorf("FD = %d read %v, want its answer's 9", got["FD"], l.Readings[FD])
		}
	}
	// One row with a description is enough to read the answers.
	c := CVE{ID: "CVE-N", Rows: []Row{{PkgName: "liba"}, {PkgName: "libb", Description: "Described."}}}
	if got := levels(computeFor(t, base(), c, answers, nil).Vector); got["M"] != 1 || got["O"] != 0 {
		t.Errorf("one row described: M %d, O %d, want 1 and 0", got["M"], got["O"])
	}
	// Nor can the adjustment lower Opportunity from there: a description is
	// a prerequisite of that answer too.
	l := computeFor(t, base(), CVE{ID: "CVE-N", Rows: []Row{{PkgName: "liba"}}}, answers,
		&Adjusted{Opportunity: "special_access_or_resources_required"})
	if l.Vector.O != 9 || l.Sources[O] != SourceAnswer || l.Readings[O] != NoDescription {
		t.Errorf("adjusted with no description: O %d from %v read %v, want 9 from no description", l.Vector.O, l.Sources[O], l.Readings[O])
	}
}

// An adjustment lowers Opportunity below a cannot_tell baseline of 9, which
// still counts.
func TestAdjustmentLowersACannotTellBaseline(t *testing.T) {
	l := compute(t, base(), Answers{O: cannotTell}, &Adjusted{Opportunity: "special_access_or_resources_required"})
	if l.Vector.O != 4 || l.Readings[O] != CannotTell || l.Sources[O] != SourceAdjustment || !slices.Contains(l.Counters, "opportunity_cannot_tell") {
		t.Errorf("O %d read %v from %v, counters %v", l.Vector.O, l.Readings[O], l.Sources[O], l.Counters)
	}
}

// A question skipped because no answer could move its level ignores a junk
// answer and the adjustment alike: ID keeps the one declared level and PV the
// floor data_subjects sets, neither read nor counted, while Opportunity takes
// the adjustment.
func TestSkippedQuestionsIgnoreJunkAndTheAdjustment(t *testing.T) {
	d := declared()
	d.Detection = &Detection{Network: "logged_and_reviewed", Host: "logged_and_reviewed", Application: "logged_and_reviewed"}
	d.DataSubjects = ptr("none")
	a := Answers{M: "high_reward", O: "no_access_or_resources_required", EE: "easy", ID: []string{"bogus"},
		LAC: "unidentified", FD: "bankruptcy", RD: "brand_damage", NC: "high_profile_violation", PV: "bogus"}
	l := compute(t, d, a, &Adjusted{Opportunity: "special_access_or_resources_required"})
	got := levels(l.Vector)
	for f, w := range map[string]int{"ID": 3, "PV": 3, "O": 4} {
		if got[f] != w {
			t.Errorf("%s = %d, want %d", f, got[f], w)
		}
	}
	for f, w := range map[Factor]Source{ID: SourceConfig, PV: SourceConfig, O: SourceAdjustment} {
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

// C2's table: Loss of confidentiality, integrity and availability from the
// worst value each axis takes over the CVE's usable CVSS v3 vectors,
// confidentiality's in data_sensitivity's column, every cell. Go alone
// reads them: no answer is asked or read, nothing is counted, and the
// source is the vectors.
func TestTechnicalImpactsFromCVSS(t *testing.T) {
	lc := map[string]map[string]int{
		"N": {"low": 2, "medium": 2, "high": 2, "critical": 2},
		"L": {"low": 2, "medium": 2, "high": 6, "critical": 6},
		"H": {"low": 6, "medium": 6, "high": 7, "critical": 7},
	}
	li := map[string]int{"N": 1, "L": 3, "H": 7}
	lav := map[string]int{"N": 1, "L": 5, "H": 7}
	answered := Answers{M: "possible_reward", O: "some_access_or_resources_required", EE: "easy", ID: []string{"network"},
		LAC: "identified", FD: "bankruptcy", RD: "minimal_damage", NC: "clear_violation", PV: "hundreds"}
	for _, value := range []string{"N", "L", "H"} {
		for _, ds := range sensitivities {
			d := declared()
			d.DataSensitivity.Value = ds
			l := computeFor(t, d, impactCVE(value, "N", "N"), answered, nil)
			if got := int(l.Vector.LC); got != lc[value][ds] {
				t.Errorf("C:%s, data_sensitivity %s: LC = %d, want %d", value, ds, got, lc[value][ds])
			}
		}
		if got := int(computeFor(t, declared(), impactCVE("N", value, "N"), answered, nil).Vector.LI); got != li[value] {
			t.Errorf("I:%s: LI = %d, want %d", value, got, li[value])
		}
		if got := int(computeFor(t, declared(), impactCVE("N", "N", value), answered, nil).Vector.LAV); got != lav[value] {
			t.Errorf("A:%s: LAV = %d, want %d", value, got, lav[value])
		}
	}
	l := computeFor(t, declared(), impactCVE("H", "L", "N"), answered, nil)
	for _, f := range []Factor{LC, LI, LAV} {
		if l.Sources[f] != SourceCVSS {
			t.Errorf("%s from %v, want cvss", f, l.Sources[f])
		}
		if _, read := l.Readings[f]; read {
			t.Errorf("%s read %v: no question asks it", f, l.Readings[f])
		}
	}
	if len(l.Counters) != 0 || l.Impact.Values != [3]string{"H", "L", "N"} {
		t.Errorf("counters %v, impact %+v", l.Counters, l.Impact)
	}
}

// With no usable CVSS v3 vector, no default being documented, Loss of
// confidentiality, integrity and availability are 9 in either column, the
// CVE counted once as cvss_v3_missing: no vector, a v2 or a v4 vector alone,
// or a v3 vector refused whole. One usable vector is enough.
func TestTechnicalImpactsWithoutAUsableVector(t *testing.T) {
	v2 := cvss.Vector{Source: "nvd", Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:N"}
	v4 := cvss.Vector{Source: "nvd", Version: "4.0", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"}
	refused := v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N")
	for name, vectors := range map[string][]cvss.Vector{
		"no vector":       nil,
		"v2 alone":        {v2},
		"v4 alone":        {v4},
		"v3 refused":      {refused},
		"all three apart": {v2, v4, refused},
	} {
		for _, ds := range []string{"low", "critical"} {
			d := declared()
			d.DataSensitivity.Value = ds
			c := CVE{ID: "CVE-V", Rows: []Row{{PkgName: "liba", Description: "Described.", CVSS: vectors}}}
			l := computeFor(t, d, c, Answers{}, nil)
			if l.Vector.LC != 9 || l.Vector.LI != 9 || l.Vector.LAV != 9 {
				t.Errorf("%s, %s: LC %d, LI %d, LAV %d, want 9", name, ds, l.Vector.LC, l.Vector.LI, l.Vector.LAV)
			}
			if n := len(slices.DeleteFunc(slices.Clone(l.Counters), func(c string) bool { return c != vectorMissing })); n != 1 {
				t.Errorf("%s, %s: counters %v, want %s once", name, ds, l.Counters, vectorMissing)
			}
			for _, f := range []Factor{LC, LI, LAV} {
				if l.Sources[f] != SourceCVSS {
					t.Errorf("%s: %s from %v, want cvss", name, f, l.Sources[f])
				}
			}
		}
	}
	c := CVE{ID: "CVE-V", Rows: []Row{{PkgName: "liba", Description: "Described.", CVSS: []cvss.Vector{v2, refused, v31("redhat", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")}}}}
	if l := computeFor(t, declared(), c, Answers{}, nil); l.Vector.LC != 2 || slices.Contains(l.Counters, vectorMissing) {
		t.Errorf("one usable vector: LC %d, counters %v", l.Vector.LC, l.Counters)
	}
}

// Every vector of every row counts: per axis the worst value over all of
// them, whatever row or source gives it.
func TestTechnicalImpactsTakeTheWorstValueOverRows(t *testing.T) {
	c := CVE{ID: "CVE-W", Rows: []Row{
		{PkgName: "liba", Description: "Described.", CVSS: []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H")}},
		{PkgName: "libb", CVSS: []cvss.Vector{v31("redhat", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N")}},
	}}
	d := declared()
	d.DataSensitivity.Value = "high"
	l := computeFor(t, d, c, Answers{}, nil)
	if l.Vector.LC != 7 || l.Vector.LI != 3 || l.Vector.LAV != 7 {
		t.Errorf("LC %d, LI %d, LAV %d, want 7, 3 and 7", l.Vector.LC, l.Vector.LI, l.Vector.LAV)
	}
}

// Privacy violation follows no Loss of confidentiality floor: a CVE whose
// vectors give C:N, or none, is asked it, and its answer stands under the
// cap data_subjects sets.
func TestPrivacyViolationFollowsNoConfidentialityFloor(t *testing.T) {
	for _, c := range []CVE{impactCVE("N", "N", "N"), impactCVE("", "", "")} {
		for _, subjects := range []*string{nil, ptr("thousands"), ptr("millions")} {
			d := declared()
			d.DataSubjects = subjects
			q, err := Questions(d, c)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(q, PV) {
				t.Errorf("%s, data_subjects %v: PV not asked", c.Rows[0].CVSS, subjects)
			}
			want := 9
			if subjects != nil && *subjects == "thousands" {
				want = 7
			}
			if l := computeFor(t, d, c, Answers{PV: "millions"}, nil); int(l.Vector.PV) != want {
				t.Errorf("%v, data_subjects %v: PV = %d, want %d", c.Rows[0].CVSS, subjects, l.Vector.PV, want)
			}
		}
	}
}
