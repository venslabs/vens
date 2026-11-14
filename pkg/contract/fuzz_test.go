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
)

// FuzzCompute drives the rules with any answers, every config state,
// Applicability state and adjustment: whatever the replies hold, the vector
// is one the calculator takes, each level in the set its JAR ran, it rates
// never below low, and the readings are the questions asked.
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
		floored := [3]bool{next()%2 == 1, next()%2 == 1, next()%2 == 1}
		a := Answers{
			M: pick(ids(motive)), O: pick(ids(opportunity)), EE: pick(ids(easeOfExploit)),
			LC: pick(ids(confidentiality)), LI: pick(ids(integrity)), LAV: pick(ids(availability)),
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
				Confidentiality: pick(adjustedAxis), Integrity: pick(adjustedAxis), Availability: pick(adjustedAxis),
			}
		}

		l, err := Compute(d, floored, a, adjusted)
		if err != nil {
			t.Fatal(err)
		}
		rating, err := l.Vector.Rate()
		if err != nil {
			t.Fatalf("the calculator refuses %+v: %v", l.Vector, err)
		}
		want := levels(l.Vector)
		for i, part := range strings.Split(rating.Vector, "/") {
			name, digit, _ := strings.Cut(part, ":")
			got, err := strconv.Atoi(digit)
			if err != nil || name != vectorOrder[i] || got != want[name] || !slices.Contains(sets[name], got) {
				t.Errorf("%s in %s: off the levels the JAR ran %v, or not %d", part, rating.Vector, sets[name], want[name])
			}
		}
		if !slices.Contains([]string{"low", "medium", "high", "critical"}, rating.Severity) {
			t.Errorf("%s rates %s", rating.Vector, rating.Severity)
		}
		asked, err := Questions(d, floored)
		if err != nil {
			t.Fatal(err)
		}
		if got := slices.Sorted(maps.Keys(l.Readings)); !slices.Equal(got, slices.Sorted(slices.Values(asked))) {
			t.Errorf("readings for %v, questions %v", got, asked)
		}
	})
}
