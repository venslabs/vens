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

// Package owasp writes and rates OWASP Risk Rating vectors on the levels of the
// reference calculator, stevespringett/owasp-risk-rating-calculator.
package owasp

import (
	"fmt"
	"slices"
	"strings"
)

// Vector holds one level per factor, in the order the vector writes them.
type Vector struct {
	SL  SkillLevel
	M   Motive
	O   Opportunity
	S   Size
	ED  EaseOfDiscovery
	EE  EaseOfExploit
	A   Awareness
	ID  IntrusionDetection
	LC  LossOfConfidentiality
	LI  LossOfIntegrity
	LAV LossOfAvailability
	LAC LossOfAccountability
	FD  FinancialDamage
	RD  ReputationDamage
	NC  NonCompliance
	PV  PrivacyViolation
}

// Check returns an error naming every level of v that is not one of its
// factor's levels. The calculator refuses a vector holding one.
func (v Vector) Check() error {
	off := slices.Concat(
		offLevel("SL", v.SL, skillLevels),
		offLevel("M", v.M, motives),
		offLevel("O", v.O, opportunities),
		offLevel("S", v.S, sizes),
		offLevel("ED", v.ED, easesOfDiscovery),
		offLevel("EE", v.EE, easesOfExploit),
		offLevel("A", v.A, awarenesses),
		offLevel("ID", v.ID, intrusionDetections),
		offLevel("LC", v.LC, lossesOfConfidentiality),
		offLevel("LI", v.LI, lossesOfIntegrity),
		offLevel("LAV", v.LAV, lossesOfAvailability),
		offLevel("LAC", v.LAC, lossesOfAccountability),
		offLevel("FD", v.FD, financialDamages),
		offLevel("RD", v.RD, reputationDamages),
		offLevel("NC", v.NC, nonCompliances),
		offLevel("PV", v.PV, privacyViolations),
	)
	if len(off) > 0 {
		return fmt.Errorf("owasp: levels off the calculator's enumerations: %s", strings.Join(off, ", "))
	}
	return nil
}

func offLevel[L ~int](abbr string, level L, levels []L) []string {
	if slices.Contains(levels, level) {
		return nil
	}
	return []string{fmt.Sprintf("%s:%d", abbr, level)}
}
