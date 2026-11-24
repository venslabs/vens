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
	"slices"
	"strings"
	"testing"

	"github.com/venslabs/vens/pkg/owasp"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// wantDamage is the table the decision of 24/11/2026 gives, written apart
// from riskconfig's: Financial damage, then Reputation damage, by
// business_criticality at a low, a medium and a high technical impact.
var wantDamage = map[string][2][3]int{
	"low":      {{1, 1, 1}, {1, 1, 1}},
	"medium":   {{1, 1, 3}, {1, 1, 4}},
	"high":     {{1, 3, 7}, {1, 4, 5}},
	"critical": {{3, 7, 9}, {4, 5, 9}},
}

// OWASP's options for each (OWASP_Risk_Rating_Methodology.md:178, :180).
var (
	financialOptions  = []int{1, 3, 7, 9}
	reputationOptions = []int{1, 4, 5, 9}
)

// The technical levels a CVSS v3 value gives, written apart from the rules':
// Loss of confidentiality on non-sensitive then critical data, Loss of
// integrity, Loss of availability on secondary then primary services.
var (
	cellLC  = map[byte][2]int{'N': {2, 2}, 'L': {2, 6}, 'H': {6, 7}}
	cellLI  = map[byte]int{'N': 1, 'L': 3, 'H': 7}
	cellLAV = map[byte][2]int{'N': {1, 1}, 'L': {1, 5}, 'H': {5, 7}}
)

// cell is one input of the damages' rule.
type cell struct {
	criticality, sensitivity, availability string
	// cia is the CVE's C, I and A, "" for no usable CVSS v3 vector.
	cia string
}

// cells are 4 criticalities × 4 sensitivities × 4 availability
// requirements × the 27 values C, I and A take together and no vector.
func cells() []cell {
	var out []cell
	for _, bc := range criticalities {
		for _, ds := range sensitivities {
			for _, ar := range availabilities {
				for _, c := range "NLH" {
					for _, i := range "NLH" {
						for _, a := range "NLH" {
							out = append(out, cell{bc, ds, ar, string([]rune{c, i, a})})
						}
					}
				}
				out = append(out, cell{bc, ds, ar, ""})
			}
		}
	}
	return out
}

// technicalBand is OWASP's band of the highest technical level the literal
// tables give the cell, high with no vector, whose three levels are 9.
func (c cell) technicalBand() int {
	if c.cia == "" {
		return 2
	}
	column := func(on bool) int {
		if on {
			return 1
		}
		return 0
	}
	sensitive := column(c.sensitivity == "high" || c.sensitivity == "critical")
	primary := column(c.availability == "high" || c.availability == "critical")
	return bandOf(float64(max(cellLC[c.cia[0]][sensitive], cellLI[c.cia[1]], cellLAV[c.cia[2]][primary])))
}

// bandOf is OWASP's band, written apart from pkg/owasp's: 0 under 3, 1 under
// 6, 2 from 6.
func bandOf(x float64) int {
	switch {
	case x < 3:
		return 0
	case x < 6:
		return 1
	}
	return 2
}

func (c cell) compute(t *testing.T) Levels {
	t.Helper()
	d := base()
	d.BusinessCriticality = Setting{Value: c.criticality, Meaning: riskconfig.BusinessCriticality.Meaning(c.criticality)}
	d.DataSensitivity.Value = c.sensitivity
	d.AvailabilityRequirement = ptr(c.availability)
	cve := impactCVE("", "", "")
	if c.cia != "" {
		cve = impactCVE(c.cia[:1], c.cia[1:2], c.cia[2:])
	}
	return computeFor(t, d, cve, Answers{}, nil)
}

// damageTable is each cell's Financial damage and Reputation damage as the
// rules compute them.
func damageTable(t *testing.T) map[cell][2]int {
	t.Helper()
	table := map[cell][2]int{}
	for _, c := range cells() {
		l := c.compute(t)
		table[c] = [2]int{int(l.Vector.FD), int(l.Vector.RD)}
	}
	return table
}

// Over every cell, Financial damage and Reputation damage are on OWASP's
// options and equal to the decision's table at the band of the highest
// technical impact; they come from business_criticality, and no question
// reads or counts them.
func TestDamagesOverEveryCell(t *testing.T) {
	all := cells()
	if len(all) != 1792 {
		t.Fatalf("%d cells, want 4 × 4 × 4 × 28 = 1792", len(all))
	}
	for _, c := range all {
		l := c.compute(t)
		fd, rd := int(l.Vector.FD), int(l.Vector.RD)
		if !slices.Contains(financialOptions, fd) || !slices.Contains(reputationOptions, rd) {
			t.Errorf("%+v: FD %d, RD %d, off OWASP's options", c, fd, rd)
		}
		want, band := wantDamage[c.criticality], c.technicalBand()
		if fd != want[0][band] || rd != want[1][band] {
			t.Errorf("%+v: FD %d, RD %d, want %d and %d at technical band %d", c, fd, rd, want[0][band], want[1][band], band)
		}
		for _, f := range []Factor{FD, RD} {
			if _, read := l.Readings[f]; read || l.Sources[f] != SourceCriticality {
				t.Errorf("%+v: %s read %v from %v, want from criticality, not read", c, f, l.Readings[f], l.Sources[f])
			}
		}
		if i := slices.IndexFunc(l.Counters, func(n string) bool {
			return strings.Contains(n, "financial") || strings.Contains(n, "reputation")
		}); i >= 0 {
			t.Errorf("%+v: counts %s", c, l.Counters[i])
		}
	}
}

// Raising one input a step, business_criticality, data_sensitivity,
// availability_requirement or one of C, I and A, never lowers Financial
// damage or Reputation damage, and no vector is never below a vector.
func TestDamagesNeverFallAsAnInputRises(t *testing.T) {
	table := damageTable(t)
	for c, before := range table {
		var raised []cell
		raise := func(list []string, value string, set func(*cell, string)) {
			if i := slices.Index(list, value); i+1 < len(list) {
				r := c
				set(&r, list[i+1])
				raised = append(raised, r)
			}
		}
		raise(criticalities, c.criticality, func(r *cell, v string) { r.criticality = v })
		raise(sensitivities, c.sensitivity, func(r *cell, v string) { r.sensitivity = v })
		raise(availabilities, c.availability, func(r *cell, v string) { r.availability = v })
		if c.cia != "" {
			for axis := range 3 {
				if i := strings.IndexByte("NLH", c.cia[axis]); i < 2 {
					r, cia := c, []byte(c.cia)
					cia[axis] = "NLH"[i+1]
					r.cia = string(cia)
					raised = append(raised, r)
				}
			}
			r := c
			r.cia = ""
			raised = append(raised, r)
		}
		for _, r := range raised {
			if after := table[r]; after[0] < before[0] || after[1] < before[1] {
				t.Errorf("%+v to %+v: FD %d to %d, RD %d to %d", c, r, before[0], after[0], before[1], after[1])
			}
		}
	}
}

// The business impact's band, over every cell and every Non-compliance and
// Privacy violation level, never falls as business_criticality rises.
func TestBusinessBandNeverFallsAsCriticalityRises(t *testing.T) {
	table := damageTable(t)
	for c := range table {
		if c.criticality != criticalities[0] {
			continue
		}
		for _, nc := range []int{2, 5, 7} {
			for _, pv := range []int{3, 5, 7, 9} {
				var bands []int
				for _, bc := range criticalities {
					r := c
					r.criticality = bc
					d := table[r]
					bands = append(bands, bandOf(float64(d[0]+d[1]+nc+pv)/4))
				}
				if !slices.IsSorted(bands) {
					t.Errorf("%+v, NC %d, PV %d: business bands %v from low to critical", c, nc, pv, bands)
				}
			}
		}
	}
}

// What the decision discloses with the rule, held over every cell: with no
// framework, Non-compliance 2, the business impact is HIGH only for critical
// at a high technical impact with Privacy violation at 5 or more; a high
// service with no framework tops out at 5.75, MEDIUM; low never reaches HIGH;
// and a C:H CVE on public data in a critical service gets FD 9 and RD 9, its
// extensive non-sensitive data disclosed being 6 (:155).
func TestDamageDisclosures(t *testing.T) {
	table := damageTable(t)
	top := map[string]float64{}
	for c, d := range table {
		for _, pv := range []int{3, 5, 7, 9} {
			business := float64(d[0]+d[1]+2+pv) / 4
			want := c.criticality == "critical" && c.technicalBand() == 2 && pv >= 5
			if high := bandOf(business) == 2; high != want {
				t.Errorf("%+v, no framework, PV %d: business %v HIGH %t, want %t", c, pv, business, high, want)
			}
			top[c.criticality] = max(top[c.criticality], business)
			for _, nc := range []int{2, 5, 7} {
				if b := float64(d[0]+d[1]+nc+pv) / 4; c.criticality == "low" && bandOf(b) == 2 {
					t.Errorf("%+v, NC %d, PV %d: low reaches HIGH, %v", c, nc, pv, b)
				}
			}
		}
		if c.criticality == "critical" && c.sensitivity == "low" && strings.HasPrefix(c.cia, "H") && d != [2]int{9, 9} {
			t.Errorf("%+v: FD %d, RD %d, want 9 and 9", c, d[0], d[1])
		}
	}
	if top["high"] != 5.75 || bandOf(top["high"]) != 1 {
		t.Errorf("a high service with no framework tops out at %v, want 5.75, MEDIUM", top["high"])
	}
}

// OWASP's worked example is High on the technical impact and Low on the
// business impact (OWASP_Risk_Rating_Methodology.md:344-347), its business
// average 2.25 (:297). The rule keeps it reachable: a low declaration at a
// high technical impact, with no framework and hundreds of people, gives
// that 2.25, (1+1+2+5)/4, beside a HIGH technical impact at a MEDIUM
// likelihood.
func TestOWASPExampleUnderTheDeclaration(t *testing.T) {
	d := base()
	d.Exposure.Value = "internal"
	d.BusinessCriticality = Setting{Value: "low", Meaning: riskconfig.BusinessCriticality.Meaning("low")}
	d.DataSensitivity.Value = "critical"
	d.DataSubjects = ptr("hundreds")
	a := Answers{M: "low_or_no_reward", O: "full_access_or_expensive_resources_required", EE: "theoretical", LAC: "identified", PV: "hundreds"}
	l := computeFor(t, d, impactCVE("H", "H", "H"), a, nil)
	if got := [4]int{int(l.Vector.FD), int(l.Vector.RD), int(l.Vector.NC), int(l.Vector.PV)}; got != [4]int{1, 1, 2, 5} {
		t.Fatalf("business levels %v, want 1, 1, 2 and 5", got)
	}
	business, err := l.Vector.Rate(owasp.BasisBusiness)
	if err != nil {
		t.Fatal(err)
	}
	technical, err := l.Vector.Rate(owasp.BasisTechnical)
	if err != nil {
		t.Fatal(err)
	}
	if business.Score != 5.25*2.25 || business.Severity != "low" || technical.Severity != "high" || d.ImpactBasis() != owasp.BasisBusiness {
		t.Errorf("business %+v, technical %+v, basis %s: want low at 5.25 × 2.25 on the business basis, high on the technical one",
			business, technical, d.ImpactBasis())
	}
}
