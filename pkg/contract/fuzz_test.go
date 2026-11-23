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
	"bytes"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/venslabs/vens/pkg/owasp"
)

// FuzzCompute drives the rules with any answers, every config state,
// technical impact state, description state and adjustment: whatever the
// replies hold, the vector is one the calculator takes, each level in the set
// its JAR ran, each with its source; its severity and score are OWASP's
// matrix and likelihood × impact recomputed from the vector alone; Motive,
// Opportunity and Ease of exploit are asked only of a CVE a row describes,
// and no adjustment lowers the Opportunity of one no row describes; Loss of
// confidentiality, integrity and availability are the vectors' whatever the
// answers and the adjustment; Privacy violation sits at its floor, not asked,
// where the vectors give C:N; and the readings are the questions asked, and
// for a CVE no row describes the likelihood questions it is not asked for
// want of a description.
func FuzzCompute(f *testing.F) {
	sets := owaspLevelSets(f)
	f.Add([]byte{}, "")
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}, "bogus")
	f.Add(bytes.Repeat([]byte{255}, 32), cannotTell)
	f.Add(bytes.Repeat([]byte{7}, 32), "network")
	f.Add(bytes.Repeat([]byte{1}, 32), keep)
	f.Fuzz(func(t *testing.T, choices []byte, junk string) {
		next := func() int {
			if len(choices) == 0 {
				return 0
			}
			b := choices[0]
			choices = choices[1:]
			return int(b)
		}
		// pick returns one of the list, or the fuzzed string.
		pick := func(list []string) string {
			if i := next() % (len(list) + 1); i < len(list) {
				return list[i]
			}
			return junk
		}
		optional := func(list []string) *string {
			if i := next() % (len(list) + 1); i < len(list) {
				return ptr(list[i])
			}
			return nil
		}
		d := base()
		d.Exposure.Value = []string{"internal", "private", "internet"}[next()%3]
		d.DataSensitivity.Value = sensitivities[next()%len(sensitivities)]
		d.Traceability = optional(traceabilities[:])
		d.DataSubjects = optional(ids(privacyViolation)[:5])
		states := detections()
		d.Detection = states[next()%len(states)]
		if next()%2 == 1 {
			d.Frameworks = []string{"PCI-DSS"}
		}
		d.AvailabilityRequirement = optional(availabilities)
		// A first value of "" leaves the CVE with no vector.
		c := impactCVE(impactValues[next()%4], impactValues[next()%3], impactValues[next()%3])
		if next()%2 == 1 {
			c.Rows[0].Description = ""
		}
		a := Answers{
			M: pick(ids(motive)), O: pick(ids(opportunity)), EE: pick(ids(easeOfExploit)),
			LAC: pick(ids(accountability)), FD: pick(ids(financialDamage)), RD: pick(ids(reputationDamage)),
			NC: pick(ids(nonCompliance)), PV: pick(ids(privacyViolation)),
		}
		for range next() % 5 {
			a.ID = append(a.ID, pick(ids(intrusionDetection)))
		}
		var adjusted *Adjusted
		if next()%2 == 1 {
			adjusted = &Adjusted{
				Opportunity:     pick(append([]string{keep}, ids(opportunity)...)),
				Confidentiality: pick([]string{affected, notAffected, cannotTell}),
			}
		}

		l, err := Compute(d, c, a, adjusted)
		if err != nil {
			t.Fatal(err)
		}
		rating, err := l.Vector.Rate()
		if err != nil {
			t.Fatalf("the calculator refuses %+v: %v", l.Vector, err)
		}
		checkRating(t, rating, levels(l.Vector), sets)
		if len(l.Sources) != len(vectorOrder) || slices.Contains(slices.Collect(maps.Values(l.Sources)), 0) {
			t.Errorf("sources %v, want one for each of the 16 levels", l.Sources)
		}
		asked, err := Questions(d, c)
		if err != nil {
			t.Fatal(err)
		}
		read := slices.Clone(asked)
		if !c.Described() {
			read = append(read, M, O, EE)
		}
		if got := slices.Sorted(maps.Keys(l.Readings)); !slices.Equal(got, slices.Sorted(slices.Values(read))) {
			t.Errorf("readings for %v, questions %v", got, asked)
		}
		for _, f := range []Factor{M, O, EE} {
			if slices.Contains(asked, f) != c.Described() {
				t.Errorf("%s asked: %v, described: %v", f, slices.Contains(asked, f), c.Described())
			}
		}
		if !c.Described() && (l.Vector.O != 9 || l.Sources[O] != SourceAnswer) {
			t.Errorf("no description, adjusted by %+v: O %d from %v, want cannot_tell's 9", adjusted, l.Vector.O, l.Sources[O])
		}
		plain, err := Compute(d, c, Answers{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if l.Vector.LC != plain.Vector.LC || l.Vector.LI != plain.Vector.LI || l.Vector.LAV != plain.Vector.LAV {
			t.Errorf("answers %+v and adjustment %+v moved the technical impacts: %+v, the vectors give %+v", a, adjusted, l.Vector, plain.Vector)
		}
		if profileOf(c).noConfidentiality() && (l.Vector.PV != privacyFloor || l.Sources[PV] != SourceFloor || slices.Contains(asked, PV)) {
			t.Errorf("C at N: PV %d from %v, asked %v", l.Vector.PV, l.Sources[PV], asked)
		}
	})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// checkRating reads the levels back from the written vector, each in the set
// the JAR ran, rates them again through owasp, and recomputes the severity
// and the score by OWASP's bands and matrix on the larger impact.
func checkRating(t *testing.T, rating owasp.Rating, want map[string]int, sets map[string][]int) {
	t.Helper()
	var read [16]int
	var sums [3]int
	for i, part := range strings.Split(rating.Vector, "/") {
		name, digit, _ := strings.Cut(part, ":")
		level, err := strconv.Atoi(digit)
		if err != nil || name != vectorOrder[i] || level != want[name] || !slices.Contains(sets[name], level) {
			t.Fatalf("%s in %s: off the levels the JAR ran %v, or not %d", part, rating.Vector, sets[name], want[name])
		}
		read[i] = level
		sums[group3(i)] += level
	}
	again, err := owasp.Vector{
		SL: owasp.SkillLevel(read[0]), M: owasp.Motive(read[1]), O: owasp.Opportunity(read[2]), S: owasp.Size(read[3]),
		ED: owasp.EaseOfDiscovery(read[4]), EE: owasp.EaseOfExploit(read[5]), A: owasp.Awareness(read[6]),
		ID: owasp.IntrusionDetection(read[7]), LC: owasp.LossOfConfidentiality(read[8]), LI: owasp.LossOfIntegrity(read[9]),
		LAV: owasp.LossOfAvailability(read[10]), LAC: owasp.LossOfAccountability(read[11]), FD: owasp.FinancialDamage(read[12]),
		RD: owasp.ReputationDamage(read[13]), NC: owasp.NonCompliance(read[14]), PV: owasp.PrivacyViolation(read[15]),
	}.Rate()
	if err != nil || again != rating {
		t.Errorf("the vector read back rates %+v (%v), want %+v", again, err, rating)
	}
	likelihood := float64(sums[0]) / 8
	impact := max(float64(sums[1]), float64(sums[2])) / 4
	band := func(x float64) int {
		switch {
		case x < 3:
			return 0
		case x < 6:
			return 1
		}
		return 2
	}
	matrix := [3][3]string{{"info", "low", "medium"}, {"low", "medium", "high"}, {"medium", "high", "critical"}}
	if severity := matrix[band(likelihood)][band(impact)]; rating.Severity != severity || severity == "info" {
		t.Errorf("%s rates %s, OWASP's matrix gives %s and vens never info", rating.Vector, rating.Severity, severity)
	}
	if score := likelihood * impact; rating.Score != score {
		t.Errorf("%s scores %v, likelihood × impact is %v", rating.Vector, rating.Score, score)
	}
}

// group3 is the sum a vector position adds to: likelihood, technical or
// business impact.
func group3(i int) int {
	switch {
	case i < 8:
		return 0
	case i < 12:
		return 1
	}
	return 2
}
