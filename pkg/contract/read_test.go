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
	"testing"
)

// answersFor sets factor f's answer, alone, in a set of answers.
func answersFor(f Factor, answer []string) Answers {
	var a Answers
	one := ""
	if len(answer) > 0 {
		one = answer[0]
	}
	switch f {
	case M:
		a.M = one
	case O:
		a.O = one
	case EE:
		a.EE = one
	case ID:
		a.ID = answer
	case LAC:
		a.LAC = one
	case FD:
		a.FD = one
	case RD:
		a.RD = one
	case NC:
		a.NC = one
	case PV:
		a.PV = one
	}
	return a
}

// ReadAnswer reads every answer as Compute does for a CVE a row describes,
// in a deployment that asks every question: each listed id, cannot_tell, an
// id off the list, and for Intrusion detection the sets of the rule.
func TestReadAnswerAgreesWithCompute(t *testing.T) {
	d := base()
	d.Frameworks = []string{"GDPR"}
	d.Detection = &Detection{Network: "logged", Host: "logged_and_reviewed", Application: activeInApplication}
	for _, f := range Order() {
		answers := [][]string{{"bogus"}, {""}}
		for _, id := range table[f].ids {
			answers = append(answers, []string{id})
		}
		if f == ID {
			answers = append(answers, nil, []string{"network", "network"}, []string{cannotTell, "host"}, []string{"host", "bogus"})
		}
		for _, answer := range answers {
			got, err := ReadAnswer(f, answer...)
			if err != nil {
				t.Fatal(err)
			}
			if want := compute(t, d, answersFor(f, answer), nil).Readings[f]; got != want {
				t.Errorf("%s %q: ReadAnswer %v, Compute %v", f, answer, got, want)
			}
		}
	}
}

func TestReadAnswerShapes(t *testing.T) {
	for _, c := range []struct {
		f      Factor
		answer []string
		want   Reading
	}{
		{M, nil, Invalid},
		{M, []string{"high_reward", "high_reward"}, Invalid},
		{M, []string{cannotTell}, CannotTell},
		{ID, []string{"network", "network"}, Answered},
		{ID, []string{}, Invalid},
		{ID, []string{cannotTell, "host"}, CannotTell},
		{ID, []string{"host", "bogus"}, Invalid},
	} {
		if got, err := ReadAnswer(c.f, c.answer...); err != nil || got != c.want {
			t.Errorf("ReadAnswer(%s, %q) = %v, %v; want %v", c.f, c.answer, got, err, c.want)
		}
	}
	for _, f := range []Factor{SL, S, ED, A, LC, LI, LAV, "R", "X"} {
		if _, err := ReadAnswer(f, "high_reward"); err == nil {
			t.Errorf("ReadAnswer(%s) read an answer to a question no call asks", f)
		}
	}
}

func TestFactorNamesAndCounters(t *testing.T) {
	for _, f := range []Factor{SL, M, O, S, ED, EE, A, ID, LC, LI, LAV, LAC, FD, RD, NC, PV} {
		if f.Name() == "" {
			t.Errorf("%s has no name", f)
		}
		if asked := table[f].factor != ""; (f.Counter() != "") != asked || f.Counter() != table[f].counter {
			t.Errorf("%s counts %q, its contract %q", f, f.Counter(), table[f].counter)
		}
	}
	if got := PV.Name(); got != "Privacy violation" {
		t.Errorf("PV is named %q", got)
	}
	for _, f := range []Factor{LC, LI, LAV} {
		if f.Counter() != "" {
			t.Errorf("%s, read from the CVSS vectors, counts %q", f, f.Counter())
		}
	}
	for r, want := range map[Reading]string{Answered: "answered", CannotTell: "cannot_tell", Invalid: "invalid", NoDescription: "no_description", 0: "unknown"} {
		if text, _ := r.MarshalText(); r.String() != want || string(text) != want {
			t.Errorf("reading %d writes %q and %q, want %q", r, r.String(), text, want)
		}
	}
}
