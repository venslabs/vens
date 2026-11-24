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
	"maps"
	"math"
	"testing"
)

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

var bases = []Basis{BasisTechnical, BasisBusiness}

type rateCase struct {
	name                            string
	likelihood, technical, business float64
	basis                           Basis
	severity                        string
	score                           float64
}

func runRateCases(t *testing.T, tests []rateCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			severity, score := rate(tt.likelihood, tt.technical, tt.business, tt.basis)
			if severity != tt.severity || score != tt.score {
				t.Errorf("rate(%v, %v, %v, %s) = %s, %v; want %s, %v",
					tt.likelihood, tt.technical, tt.business, tt.basis, severity, score, tt.severity, tt.score)
			}
		})
	}
}

func TestRate_OWASPMatrix(t *testing.T) {
	for _, basis := range bases {
		t.Run(string(basis), func(t *testing.T) {
			runRateCases(t, []rateCase{
				{"likelihood LOW, impact LOW: Note", 1, 1, 1, basis, "info", 1},
				{"likelihood LOW, impact MEDIUM", 1, 4, 4, basis, "low", 4},
				{"likelihood LOW, impact HIGH", 1, 7, 7, basis, "medium", 7},
				{"likelihood MEDIUM, impact LOW", 4, 1, 1, basis, "low", 4},
				{"likelihood MEDIUM, impact MEDIUM", 4, 4, 4, basis, "medium", 16},
				{"likelihood MEDIUM, impact HIGH", 4, 7, 7, basis, "high", 28},
				{"likelihood HIGH, impact LOW", 7, 1, 1, basis, "medium", 7},
				{"likelihood HIGH, impact MEDIUM", 7, 4, 4, basis, "high", 28},
				{"likelihood HIGH, impact HIGH", 7, 7, 7, basis, "critical", 49},
			})
		})
	}
}

// OWASP's worked example, likelihood 4.375 MEDIUM, technical impact 7.25 HIGH,
// business impact 2.25 LOW (OWASP_Risk_Rating_Methodology.md:257, :295,
// :297): High from a purely technical perspective, Low on the business
// impact (:344-347). Some of its levels are off the calculator's
// enumerations, so its averages are rated.
func TestRate_OWASPWorkedExample(t *testing.T) {
	likelihood, technical, business := mirrorScores([16]int{5, 2, 7, 1, 3, 6, 9, 2, 9, 7, 5, 8, 1, 2, 1, 5})
	if likelihood != 4.375 || technical != 7.25 || business != 2.25 {
		t.Fatalf("the worked example averages %v, %v, %v; OWASP gives 4.375, 7.25, 2.25", likelihood, technical, business)
	}
	runRateCases(t, []rateCase{
		{"on the business impact", 4.375, 7.25, 2.25, BasisBusiness, "low", 9.84375},
		{"on the technical impact", 4.375, 7.25, 2.25, BasisTechnical, "high", 31.71875},
	})
}

// A finding verified as not exploitable here keeps its likelihood and floors its
// impact factors (#310), technical (2+1+1+1)/4 = 1.25 and business
// (1+1+2+3)/4 = 1.75: a LOW impact on either basis, Low at a MEDIUM
// likelihood, Medium at a HIGH one.
func TestVector_VerifiedExclusionIsALowImpact(t *testing.T) {
	excluded := Vector{
		LC: LossOfConfidentialityMinimalNonSensitiveDataDisclosed, LI: LossOfIntegrityMinimalSlightlyCorruptData,
		LAV: LossOfAvailabilityMinimalSecondaryServicesInterrupted, LAC: LossOfAccountabilityFullyTraceable,
		FD: FinancialDamageLessThanTheCostToFixTheVulnerability, RD: ReputationDamageMinimalDamage,
		NC: NonComplianceMinorViolation, PV: PrivacyViolationOneIndividual,
	}

	// The lowest likelihood vens can emit, 34/8 = 4.25.
	medium := excluded
	medium.SL, medium.M, medium.O, medium.S = SkillLevelSecurityPenetrationSkills, MotiveLowOrNoReward,
		OpportunityFullAccessOrExpensiveResourcesRequired, SizeIntranetUsers
	medium.ED, medium.EE, medium.A, medium.ID = EaseOfDiscoveryAutomatedToolsAvailable, EaseOfExploitTheoretical,
		AwarenessPublicKnowledge, IntrusionDetectionActiveDetectionInApplication

	high := excluded
	high.SL, high.M, high.O, high.S = SkillLevelSecurityPenetrationSkills, MotiveHighReward,
		OpportunityNoAccessOrResourcesRequired, SizeAnonymousInternetUsers
	high.ED, high.EE, high.A, high.ID = EaseOfDiscoveryAutomatedToolsAvailable, EaseOfExploitAutomatedToolsAvailable,
		AwarenessPublicKnowledge, IntrusionDetectionNotLogged

	for _, tt := range []struct {
		name     string
		vector   Vector
		basis    Basis
		severity string
		score    float64
	}{
		{"MEDIUM likelihood", medium, BasisTechnical, "low", 5.3125},
		{"MEDIUM likelihood", medium, BasisBusiness, "low", 7.4375},
		{"HIGH likelihood", high, BasisTechnical, "medium", 11.25},
		{"HIGH likelihood", high, BasisBusiness, "medium", 15.75},
	} {
		got, err := tt.vector.Rate(tt.basis)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if got.Severity != tt.severity || got.Score != tt.score || got.Basis != tt.basis {
			t.Errorf("%s: Rate(%s) = %+v, want %s %v", tt.name, tt.basis, got, tt.severity, tt.score)
		}
	}
}

// The impact is the one the basis names, whatever the other: each case puts
// the other impact in another band, so neither max(T, B), min(T, B) nor a
// fixed impact passes.
func TestRate_ReadsTheImpactOfItsBasis(t *testing.T) {
	runRateCases(t, []rateCase{
		{"business above technical, on business", 4.25, 1.25, 8.5, BasisBusiness, "high", 36.125},
		{"business above technical, on technical", 4.25, 1.25, 8.5, BasisTechnical, "low", 5.3125},
		{"technical above business, on business", 4.25, 9, 1.75, BasisBusiness, "low", 7.4375},
		{"technical above business, on technical", 4.25, 9, 1.75, BasisTechnical, "high", 38.25},
	})
}

// OWASP's bands, 0 to under 3 LOW, 3 to under 6 MEDIUM, 6 and up HIGH, each
// edge beside the next value under it on the /8 or /4 grid: the impact's on
// each basis, the other impact in another band, and the likelihood's.
func TestRate_BandEdges(t *testing.T) {
	runRateCases(t, []rateCase{
		{"technical 2.75 is LOW", 4.25, 2.75, 6, BasisTechnical, "low", 11.6875},
		{"technical 3.00 is MEDIUM", 4.25, 3, 1.75, BasisTechnical, "medium", 12.75},
		{"technical 5.75 is MEDIUM", 4.25, 5.75, 6, BasisTechnical, "medium", 24.4375},
		{"technical 6.00 is HIGH", 4.25, 6, 1.75, BasisTechnical, "high", 25.5},
		{"business 2.75 is LOW", 4.25, 6, 2.75, BasisBusiness, "low", 11.6875},
		{"business 3.00 is MEDIUM", 4.25, 1.25, 3, BasisBusiness, "medium", 12.75},
		{"business 5.75 is MEDIUM", 4.25, 6, 5.75, BasisBusiness, "medium", 24.4375},
		{"business 6.00 is HIGH", 4.25, 1.25, 6, BasisBusiness, "high", 25.5},
		{"likelihood 2.875 is LOW", 2.875, 1.25, 1.75, BasisBusiness, "info", 5.03125},
		{"likelihood 3.00 is MEDIUM", 3, 1.25, 1.75, BasisBusiness, "low", 5.25},
		{"likelihood 5.875 is MEDIUM", 5.875, 1.25, 1.75, BasisBusiness, "low", 10.28125},
		{"likelihood 6.00 is HIGH", 6, 1.25, 1.75, BasisBusiness, "medium", 10.5},
	})
}

// Every sum 16 digits can make, a superset of the legal vectors' sums: the
// likelihood 0 to 72, technical and business 0 to 36.
func forEverySum(fn func(sl, st, sb int)) {
	for sl := 0; sl <= 72; sl++ {
		for st := 0; st <= 36; st++ {
			for sb := 0; sb <= 36; sb++ {
				fn(sl, st, sb)
			}
		}
	}
}

func rateSums(sl, st, sb int, basis Basis) (string, float64) {
	return rate(float64(sl)/8, float64(st)/4, float64(sb)/4, basis)
}

// Monotone on the sums, on each basis: raising the likelihood, technical or
// business sum by one never lowers the severity or the score, so no level
// rising can lower a rating.
func TestRate_MonotoneInEverySum(t *testing.T) {
	for _, basis := range bases {
		forEverySum(func(sl, st, sb int) {
			severity, score := rateSums(sl, st, sb, basis)
			if _, ok := severityRank[severity]; !ok {
				t.Fatalf("%s, sums %d, %d, %d: severity %q is not a CycloneDX severity vens writes", basis, sl, st, sb, severity)
			}
			for _, up := range [][3]int{{1, 0, 0}, {0, 1, 0}, {0, 0, 1}} {
				l, tc, b := sl+up[0], st+up[1], sb+up[2]
				if l > 72 || tc > 36 || b > 36 {
					continue
				}
				upSeverity, upScore := rateSums(l, tc, b, basis)
				if severityRank[upSeverity] < severityRank[severity] || upScore < score {
					t.Fatalf("%s: sums %d, %d, %d rate %s %v; %d, %d, %d rate %s %v",
						basis, sl, st, sb, severity, score, l, tc, b, upSeverity, upScore)
				}
			}
		})
	}
}

// With integer levels the score is the likelihood sum times the sum of the
// impact the basis names over 32, exact in float64, so a published score
// recomputes bit for bit from its own vector and basis, which #358 found it
// did not.
func TestRate_ScoreIsExact(t *testing.T) {
	forEverySum(func(sl, st, sb int) {
		for basis, impact := range map[Basis]int{BasisTechnical: st, BasisBusiness: sb} {
			if _, score := rateSums(sl, st, sb, basis); score*32 != float64(sl*impact) {
				t.Fatalf("%s, sums %d, %d, %d: score %v, want %d/32", basis, sl, st, sb, score, sl*impact)
			}
		}
	})
}

// sumCounts gives each sum the factors' levels can make, with the number of
// level combinations that make it.
func sumCounts(sets [][]int) map[int]int {
	counts := map[int]int{0: 1}
	for _, set := range sets {
		next := map[int]int{}
		for sum, n := range counts {
			for _, level := range set {
				next[sum+level] += n
			}
		}
		counts = next
	}
	return counts
}

// Over the product of reachableLevelSets, a superset of the vectors vens can
// emit: no vector rates Note on either basis, the ranges are those of #310
// step 3, and the severities count, on each basis, the product crossed in
// OWASP's matrix. #310 step 3's run crossed the JAR's own bands of the
// likelihood and of max(T, B), which the matrix rates as the higher of the
// two bases' severities: its counts still check both.
func TestRate_ReachableLevelSetsProduct(t *testing.T) {
	sets := levelSets(t)
	likelihood, technical, business := sumCounts(sets[0:8]), sumCounts(sets[8:12]), sumCounts(sets[12:16])

	counts := map[Basis]map[string]int{BasisTechnical: {}, BasisBusiness: {}}
	higher := map[string]int{}
	lowL, highL, lowT, highT, lowB, highB := 72, 0, 36, 0, 36, 0
	lowScore := map[Basis]float64{BasisTechnical: math.Inf(1), BasisBusiness: math.Inf(1)}
	highScore := map[Basis]float64{BasisTechnical: math.Inf(-1), BasisBusiness: math.Inf(-1)}
	for sl, nl := range likelihood {
		lowL, highL = min(lowL, sl), max(highL, sl)
		for st, nt := range technical {
			lowT, highT = min(lowT, st), max(highT, st)
			for sb, nb := range business {
				lowB, highB = min(lowB, sb), max(highB, sb)
				n := nl * nt * nb
				var pair [2]string
				for i, basis := range bases {
					severity, score := rateSums(sl, st, sb, basis)
					counts[basis][severity] += n
					lowScore[basis], highScore[basis] = min(lowScore[basis], score), max(highScore[basis], score)
					pair[i] = severity
				}
				higher[higherSeverity(pair[0], pair[1])] += n
			}
		}
	}

	want := map[Basis]map[string]int{
		BasisTechnical: {"low": 276_672, "medium": 4_083_840, "high": 13_295_808, "critical": 8_885_760},
		BasisBusiness:  {"low": 251_520, "medium": 4_878_720, "high": 15_431_040, "critical": 5_980_800},
	}
	for _, basis := range bases {
		if !maps.Equal(counts[basis], want[basis]) {
			t.Errorf("%s: severities over the product %v, want %v", basis, counts[basis], want[basis])
		}
	}
	if step3 := map[string]int{"low": 11_528, "medium": 2_450_608, "high": 11_805_064, "critical": 12_274_880}; !maps.Equal(higher, step3) {
		t.Errorf("the higher of the two severities over the product %v, #310 step 3 counted %v", higher, step3)
	}
	if lowL != 34 || highL != 72 || lowT != 5 || highT != 36 || lowB != 7 || highB != 34 {
		t.Errorf("likelihood %v to %v, technical %v to %v, business %v to %v; want 4.25 to 9, 1.25 to 9, 1.75 to 8.5",
			float64(lowL)/8, float64(highL)/8, float64(lowT)/4, float64(highT)/4, float64(lowB)/4, float64(highB)/4)
	}
	if lowScore[BasisTechnical] != 5.3125 || highScore[BasisTechnical] != 81 {
		t.Errorf("technical: score %v to %v, want 5.3125 to 81", lowScore[BasisTechnical], highScore[BasisTechnical])
	}
	if lowScore[BasisBusiness] != 7.4375 || highScore[BasisBusiness] != 76.5 {
		t.Errorf("business: score %v to %v, want 7.4375 to 76.5", lowScore[BasisBusiness], highScore[BasisBusiness])
	}
}

func higherSeverity(a, b string) string {
	if severityRank[b] > severityRank[a] {
		return b
	}
	return a
}
