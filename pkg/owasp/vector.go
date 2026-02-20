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

package owasp

import (
	"fmt"
	"math"
)

// OwaspRRVector represents an OWASP Risk Rating vector in standard format.
// Format: SL:5/M:4/O:7/S:6/ED:7/EE:5/A:6/ID:8/LC:2/LI:3/LAV:5/LAC:7/FD:1/RD:2/NC:2/PV:3
//
// Vector components (all 0-9):
//   - Threat Agent Factors (4): SL (SkillLevel), M (Motive), O (Opportunity), S (Size)
//   - Vulnerability Factors (4): ED (EaseOfDiscovery), EE (EaseOfExploit), A (Awareness), ID (IntrusionDetection)
//   - Technical Impact Factors (4): LC (LossOfConfidentiality), LI (LossOfIntegrity), LAV (LossOfAvailability), LAC (LossOfAccountability)
//   - Business Impact Factors (4): FD (FinancialDamage), RD (ReputationDamage), NC (NonCompliance), PV (PrivacyViolation)
//
// Reference: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
type OwaspRRVector struct {
	// Threat Agent Factors
	SkillLevel  int // SL: 0-9
	Motive      int // M: 0-9
	Opportunity int // O: 0-9
	Size        int // S: 0-9

	// Vulnerability Factors
	EaseOfDiscovery    int // ED: 0-9
	EaseOfExploit      int // EE: 0-9
	Awareness          int // A: 0-9
	IntrusionDetection int // ID: 0-9

	// Technical Impact Factors
	LossOfConfidentiality int // LC: 0-9
	LossOfIntegrity       int // LI: 0-9
	LossOfAvailability    int // LAV: 0-9
	LossOfAccountability  int // LAC: 0-9

	// Business Impact Factors
	FinancialDamage  int // FD: 0-9
	ReputationDamage int // RD: 0-9
	NonCompliance    int // NC: 0-9
	PrivacyViolation int // PV: 0-9
}

// String returns the vector in standard OWASP RR format.
func (v *OwaspRRVector) String() string {
	return fmt.Sprintf("SL:%d/M:%d/O:%d/S:%d/ED:%d/EE:%d/A:%d/ID:%d/LC:%d/LI:%d/LAV:%d/LAC:%d/FD:%d/RD:%d/NC:%d/PV:%d",
		v.SkillLevel, v.Motive, v.Opportunity, v.Size,
		v.EaseOfDiscovery, v.EaseOfExploit, v.Awareness, v.IntrusionDetection,
		v.LossOfConfidentiality, v.LossOfIntegrity, v.LossOfAvailability, v.LossOfAccountability,
		v.FinancialDamage, v.ReputationDamage, v.NonCompliance, v.PrivacyViolation)
}

// FromAggregatedScores creates an OWASP RR vector from aggregated scores.
// This is a pragmatic approach when detailed 16-factor scoring is not available.
//
// The function distributes the aggregated scores across the individual factors
// to maintain mathematical consistency with the OWASP Risk Rating methodology:
//   - ThreatAgent score (0-9) is distributed across SL, M, O, S
//   - Vulnerability score (0-9) is distributed across ED, EE, A, ID
//   - TechnicalImpact score (0-9) is distributed across LC, LI, LAV, LAC
//   - BusinessImpact score (0-9) is distributed across FD, RD, NC, PV
//
// Note: This produces a valid OWASP RR vector that can be parsed by
// compliant platforms, though it doesn't capture the full granularity of individual factors.
func FromAggregatedScores(threatAgent, vulnerability, technicalImpact, businessImpact float64) *OwaspRRVector {
	// Clamp all scores to 0-9 range
	ta := clamp09(int(math.Round(threatAgent)))
	vul := clamp09(int(math.Round(vulnerability)))
	tech := clamp09(int(math.Round(technicalImpact)))
	bus := clamp09(int(math.Round(businessImpact)))

	return &OwaspRRVector{
		// Threat Agent: distribute evenly across 4 factors
		SkillLevel:  ta,
		Motive:      ta,
		Opportunity: ta,
		Size:        ta,

		// Vulnerability: distribute evenly across 4 factors
		EaseOfDiscovery:    vul,
		EaseOfExploit:      vul,
		Awareness:          vul,
		IntrusionDetection: 9 - vul, // Inverse: high vuln score = low detection

		// Technical Impact: distribute evenly across 4 factors
		LossOfConfidentiality: tech,
		LossOfIntegrity:       tech,
		LossOfAvailability:    tech,
		LossOfAccountability:  tech,

		// Business Impact: distribute evenly across 4 factors
		FinancialDamage:  bus,
		ReputationDamage: bus,
		NonCompliance:    bus,
		PrivacyViolation: bus,
	}
}

// clamp09 ensures a value is within 0-9 range
func clamp09(val int) int {
	if val < 0 {
		return 0
	}
	if val > 9 {
		return 9
	}
	return val
}
