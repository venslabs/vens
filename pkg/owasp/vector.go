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

// Rating is a checked vector as vens publishes it.
type Rating struct {
	// Vector is the 16 levels in the calculator's pattern,
	// SL:9/M:4/O:7/S:9/ED:9/EE:5/A:9/ID:9/LC:6/LI:5/LAV:7/LAC:7/FD:3/RD:4/NC:5/PV:7.
	Vector string
	// Severity is OWASP's overall risk severity in lower case, its Note
	// written as CycloneDX's info.
	Severity string
	// Score is likelihood × impact, a vens extension: OWASP's method stops at
	// the severity.
	Score float64
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

// Rate checks v and, once every level has passed, writes the vector and rates
// it: likelihood, technical and business impact are the calculator's averages
// of their levels. A vector that fails the check gets no rating.
func (v Vector) Rate() (Rating, error) {
	if err := v.Check(); err != nil {
		return Rating{}, err
	}
	likelihood := int(v.SL) + int(v.M) + int(v.O) + int(v.S) + int(v.ED) + int(v.EE) + int(v.A) + int(v.ID)
	technical := int(v.LC) + int(v.LI) + int(v.LAV) + int(v.LAC)
	business := int(v.FD) + int(v.RD) + int(v.NC) + int(v.PV)
	severity, score := rate(float64(likelihood)/8, float64(technical)/4, float64(business)/4)
	return Rating{
		Vector: fmt.Sprintf("SL:%d/M:%d/O:%d/S:%d/ED:%d/EE:%d/A:%d/ID:%d/LC:%d/LI:%d/LAV:%d/LAC:%d/FD:%d/RD:%d/NC:%d/PV:%d",
			v.SL, v.M, v.O, v.S, v.ED, v.EE, v.A, v.ID, v.LC, v.LI, v.LAV, v.LAC, v.FD, v.RD, v.NC, v.PV),
		Severity: severity,
		Score:    score,
	}, nil
}
