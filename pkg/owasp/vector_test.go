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
	"math/rand/v2"
	"slices"
	"testing"
)

func TestVector_Rate(t *testing.T) {
	tests := []struct {
		name     string
		vector   Vector
		expected Rating
	}{
		{
			name: "lowest_levels",
			vector: Vector{
				SL: SkillLevelNoTechnicalSkills, M: MotiveLowOrNoReward,
				O: OpportunityFullAccessOrExpensiveResourcesRequired, S: SizeDevelopers,
				ED: EaseOfDiscoveryPracticallyImpossible, EE: EaseOfExploitTheoretical,
				A: AwarenessUnknown, ID: IntrusionDetectionActiveDetectionInApplication,
				LC: LossOfConfidentialityMinimalNonSensitiveDataDisclosed, LI: LossOfIntegrityMinimalSlightlyCorruptData,
				LAV: LossOfAvailabilityMinimalSecondaryServicesInterrupted, LAC: LossOfAccountabilityFullyTraceable,
				FD: FinancialDamageLessThanTheCostToFixTheVulnerability, RD: ReputationDamageMinimalDamage,
				NC: NonComplianceMinorViolation, PV: PrivacyViolationOneIndividual,
			},
			// Likelihood 1, impact 1.75: OWASP's Note, written info.
			expected: Rating{
				Vector:   "SL:1/M:1/O:0/S:2/ED:1/EE:1/A:1/ID:1/LC:2/LI:1/LAV:1/LAC:1/FD:1/RD:1/NC:2/PV:3",
				Severity: "info",
				Score:    1.75,
			},
		},
		{
			name: "highest_levels",
			vector: Vector{
				SL: SkillLevelSecurityPenetrationSkills, M: MotiveHighReward,
				O: OpportunityNoAccessOrResourcesRequired, S: SizeAnonymousInternetUsers,
				ED: EaseOfDiscoveryAutomatedToolsAvailable, EE: EaseOfExploitAutomatedToolsAvailable,
				A: AwarenessPublicKnowledge, ID: IntrusionDetectionNotLogged,
				LC: LossOfConfidentialityAllDataDisclosed, LI: LossOfIntegrityAllDataTotallyCorrupt,
				LAV: LossOfAvailabilityAllServicesCompletelyLost, LAC: LossOfAccountabilityCompletelyAnonymous,
				FD: FinancialDamageBankruptcy, RD: ReputationDamageBrandDamage,
				NC: NonComplianceHighProfileViolation, PV: PrivacyViolationMillionsOfPeople,
			},
			expected: Rating{
				Vector:   "SL:9/M:9/O:9/S:9/ED:9/EE:9/A:9/ID:9/LC:9/LI:9/LAV:9/LAC:9/FD:9/RD:9/NC:7/PV:9",
				Severity: "critical",
				Score:    81,
			},
		},
		{
			name: "mixed_values",
			vector: Vector{
				SL: SkillLevelAdvancedComputerUser, M: MotivePossibleReward,
				O: OpportunitySomeAccessOrResourcesRequired, S: SizeAuthenticatedUsers,
				ED: EaseOfDiscoveryEasy, EE: EaseOfExploitEasy,
				A: AwarenessObvious, ID: IntrusionDetectionLoggedWithoutReview,
				LC: LossOfConfidentialityMinimalNonSensitiveDataDisclosed, LI: LossOfIntegrityMinimalSeriouslyCorruptData,
				LAV: LossOfAvailabilityMinimalPrimaryServicesInterrupted, LAC: LossOfAccountabilityPossiblyTraceable,
				FD: FinancialDamageLessThanTheCostToFixTheVulnerability, RD: ReputationDamageMinimalDamage,
				NC: NonComplianceMinorViolation, PV: PrivacyViolationOneIndividual,
			},
			// Likelihood 6, technical 4.25 over business 1.75.
			expected: Rating{
				Vector:   "SL:5/M:4/O:7/S:6/ED:7/EE:5/A:6/ID:8/LC:2/LI:3/LAV:5/LAC:7/FD:1/RD:1/NC:2/PV:3",
				Severity: "high",
				Score:    25.5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.vector.Rate()
			if err != nil {
				t.Fatalf("Rate() error = %v", err)
			}
			if got != tt.expected {
				t.Errorf("Rate() = %+v, want %+v", got, tt.expected)
			}
		})
	}
}

func TestVector_RateRefusesLevelsOffTheEnumerations(t *testing.T) {
	tests := []struct {
		name   string
		vector Vector
		off    string
	}{
		{
			name:   "all_zeros",
			vector: Vector{},
			off:    "SL:0, M:0, S:0, ED:0, EE:0, A:0, ID:0, LC:0, LI:0, LAV:0, LAC:0, FD:0, RD:0, NC:0, PV:0",
		},
		{
			name:   "all_nines",
			vector: vectorOf([16]int{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}),
			off:    "NC:9",
		},
		{
			// OWASP's worked example, which interpolates between the levels.
			name:   "owasp_worked_example",
			vector: vectorOf([16]int{5, 2, 7, 1, 3, 6, 9, 2, 9, 7, 5, 8, 1, 2, 1, 5}),
			off:    "M:2, S:1, EE:6, ID:2, LAC:8, RD:2, NC:1",
		},
		{
			name:   "not_a_digit",
			vector: vectorOf([16]int{-1, 1, 0, 2, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 2, 10}),
			off:    "SL:-1, PV:10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := "owasp: levels off the calculator's enumerations: " + tt.off
			if err := tt.vector.Check(); err == nil || err.Error() != want {
				t.Errorf("Check() = %v, want %q", err, want)
			}
			got, err := tt.vector.Rate()
			if err == nil || err.Error() != want {
				t.Errorf("Rate() error = %v, want %q", err, want)
			}
			if got != (Rating{}) {
				t.Errorf("Rate() wrote %+v for a vector it refused", got)
			}
		})
	}
}

func randomLevels(rng *rand.Rand) [16]int {
	var levels [16]int
	for i, f := range mirrorEnums {
		levels[i] = f.levels[rng.IntN(len(f.levels))].level
	}
	return levels
}

// #340's test (ii): the written vector, read and averaged as the calculator
// does, then max(T, B) and OWASP's matrix, gives the published severity and
// score back.
func TestVector_RateRecomputesFromTheWrittenVector(t *testing.T) {
	rng := rand.New(rand.NewPCG(310, 340))
	for range 20_000 {
		levels := randomLevels(rng)
		got, err := vectorOf(levels).Rate()
		if err != nil {
			t.Fatalf("%s: %v", mirrorVector(levels), err)
		}
		parsed, ok := mirrorParse(got.Vector)
		if !ok || parsed != levels {
			t.Fatalf("Rate().Vector = %q, the calculator reads %v (ok %t), want %v", got.Vector, parsed, ok, levels)
		}
		severity, score, _ := mirrorRate(got.Vector)
		if got.Severity != severity || got.Score != score {
			t.Fatalf("%s: Rate() = %s %v, recomputed %s %v", got.Vector, got.Severity, got.Score, severity, score)
		}
	}
}

// #340's test (i), through the vector: raising any one level never lowers the
// severity or the score.
func TestVector_RaisingALevelNeverLowersTheRating(t *testing.T) {
	rng := rand.New(rand.NewPCG(340, 1))
	for range 500 {
		base := randomLevels(rng)
		for i, f := range mirrorEnums {
			var steps []int
			for _, l := range f.levels {
				steps = append(steps, l.level)
			}
			slices.Sort(steps)
			steps = slices.Compact(steps)

			var prev Rating
			for k, level := range steps {
				levels := base
				levels[i] = level
				got, err := vectorOf(levels).Rate()
				if err != nil {
					t.Fatalf("%s: %v", mirrorVector(levels), err)
				}
				if k > 0 && (severityRank[got.Severity] < severityRank[prev.Severity] || got.Score < prev.Score) {
					t.Fatalf("%s up to %d lowers the rating: %+v after %+v", f.abbr, level, got, prev)
				}
				prev = got
			}
		}
	}
}
