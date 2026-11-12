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

type rateCase struct {
	name                            string
	likelihood, technical, business float64
	severity                        string
	score                           float64
}

func runRateCases(t *testing.T, tests []rateCase) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			severity, score := rate(tt.likelihood, tt.technical, tt.business)
			if severity != tt.severity || score != tt.score {
				t.Errorf("rate(%v, %v, %v) = %s, %v; want %s, %v",
					tt.likelihood, tt.technical, tt.business, severity, score, tt.severity, tt.score)
			}
		})
	}
}

func TestRate_OWASPMatrix(t *testing.T) {
	runRateCases(t, []rateCase{
		{"likelihood LOW, impact LOW: Note", 1, 1, 1, "info", 1},
		{"likelihood LOW, impact MEDIUM", 1, 4, 4, "low", 4},
		{"likelihood LOW, impact HIGH", 1, 7, 7, "medium", 7},
		{"likelihood MEDIUM, impact LOW", 4, 1, 1, "low", 4},
		{"likelihood MEDIUM, impact MEDIUM", 4, 4, 4, "medium", 16},
		{"likelihood MEDIUM, impact HIGH", 4, 7, 7, "high", 28},
		{"likelihood HIGH, impact LOW", 7, 1, 1, "medium", 7},
		{"likelihood HIGH, impact MEDIUM", 7, 4, 4, "high", 28},
		{"likelihood HIGH, impact HIGH", 7, 7, 7, "critical", 49},
	})
}

// #340's test (iii). OWASP rates its worked example Low on the business
// impact; vens takes the larger impact and says High, the declared divergence.
func TestRate_OWASPWorkedExample(t *testing.T) {
	likelihood, technical, business := mirrorScores([16]int{5, 2, 7, 1, 3, 6, 9, 2, 9, 7, 5, 8, 1, 2, 1, 5})
	if likelihood != 4.375 || technical != 7.25 || business != 2.25 {
		t.Fatalf("the worked example averages %v, %v, %v; OWASP gives 4.375, 7.25, 2.25", likelihood, technical, business)
	}
	runRateCases(t, []rateCase{{"worked example", 4.375, 7.25, 2.25, "high", 31.71875}})
}

// #340's test (iv): a verified exclusion floors the impact factors, technical
// (2+1+1+1)/4 = 1.25 and business (1+1+2+3)/4 = 1.75, a LOW impact: Low at a
// MEDIUM likelihood, Medium at a HIGH one.
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
		severity string
		score    float64
	}{
		{"MEDIUM likelihood", medium, "low", 7.4375},
		{"HIGH likelihood", high, "medium", 15.75},
	} {
		got, err := tt.vector.Rate()
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if got.Severity != tt.severity || got.Score != tt.score {
			t.Errorf("%s: Rate() = %+v, want %s %v", tt.name, got, tt.severity, tt.score)
		}
	}
}

// #340's test (v). Business above technical rules out always-technical,
// technical above business always-business, and both rule out the mean.
func TestRate_TakesTheLargerImpact(t *testing.T) {
	runRateCases(t, []rateCase{
		{"business above technical", 4.25, 1.25, 8.5, "high", 36.125},
		{"technical above business", 4.25, 9, 1.75, "high", 38.25},
		{"tie", 4.25, 4.5, 4.5, "medium", 19.125},
	})
}

// #340's test (vi): OWASP's bands, 0 to under 3 LOW, 3 to under 6 MEDIUM,
// 6 and up HIGH, each edge beside the reachable value under it.
func TestRate_BandEdges(t *testing.T) {
	runRateCases(t, []rateCase{
		{"impact 2.75 is LOW", 4.25, 2.75, 1.75, "low", 11.6875},
		{"impact 3.00 is MEDIUM", 4.25, 3, 1.75, "medium", 12.75},
		{"impact 5.75 is MEDIUM", 4.25, 5.75, 1.75, "medium", 24.4375},
		{"impact 6.00 is HIGH", 4.25, 6, 1.75, "high", 25.5},
		{"business impact 3.00 is MEDIUM", 4.25, 1.25, 3, "medium", 12.75},
		{"business impact 6.00 is HIGH", 4.25, 1.25, 6, "high", 25.5},
		{"likelihood 2.875 is LOW", 2.875, 1.25, 1.75, "info", 5.03125},
		{"likelihood 3.00 is MEDIUM", 3, 1.25, 1.75, "low", 5.25},
		{"likelihood 5.875 is MEDIUM", 5.875, 1.25, 1.75, "low", 10.28125},
		{"likelihood 6.00 is HIGH", 6, 1.25, 1.75, "medium", 10.5},
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

func rateSums(sl, st, sb int) (string, float64) {
	return rate(float64(sl)/8, float64(st)/4, float64(sb)/4)
}

// #340's test (i) on the sums: raising the likelihood, technical or business
// sum by one never lowers the severity or the score.
func TestRate_MonotoneInEverySum(t *testing.T) {
	forEverySum(func(sl, st, sb int) {
		severity, score := rateSums(sl, st, sb)
		if _, ok := severityRank[severity]; !ok {
			t.Fatalf("sums %d, %d, %d: severity %q is not a CycloneDX severity vens writes", sl, st, sb, severity)
		}
		for _, up := range [][3]int{{1, 0, 0}, {0, 1, 0}, {0, 0, 1}} {
			l, tc, b := sl+up[0], st+up[1], sb+up[2]
			if l > 72 || tc > 36 || b > 36 {
				continue
			}
			upSeverity, upScore := rateSums(l, tc, b)
			if severityRank[upSeverity] < severityRank[severity] || upScore < score {
				t.Fatalf("sums %d, %d, %d rate %s %v; %d, %d, %d rate %s %v",
					sl, st, sb, severity, score, l, tc, b, upSeverity, upScore)
			}
		}
	})
}

// With integer levels the score is the likelihood sum times the larger impact
// sum over 32, exact in float64, so a published score recomputes bit for bit
// from its vector (#358).
func TestRate_ScoreIsExact(t *testing.T) {
	forEverySum(func(sl, st, sb int) {
		if _, score := rateSums(sl, st, sb); score*32 != float64(sl*max(st, sb)) {
			t.Fatalf("sums %d, %d, %d: score %v, want %d/32", sl, st, sb, score, sl*max(st, sb))
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

// step3.out B1 and java/java3.out (#310 step 3), over the product of the
// JAVA_ARGS sets, a superset of the vectors vens can emit: no vector rates
// Note, and the severities count what the calculator's own bands counted.
func TestRate_JavaArgsProduct(t *testing.T) {
	sets := javaArgsSets(t)
	likelihood, technical, business := sumCounts(sets[0:8]), sumCounts(sets[8:12]), sumCounts(sets[12:16])

	counts := map[string]int{}
	lowL, highL, lowT, highT, lowB, highB := 72, 0, 36, 0, 36, 0
	lowScore, highScore := math.Inf(1), math.Inf(-1)
	for sl, nl := range likelihood {
		lowL, highL = min(lowL, sl), max(highL, sl)
		for st, nt := range technical {
			lowT, highT = min(lowT, st), max(highT, st)
			for sb, nb := range business {
				lowB, highB = min(lowB, sb), max(highB, sb)
				severity, score := rateSums(sl, st, sb)
				counts[severity] += nl * nt * nb
				lowScore, highScore = min(lowScore, score), max(highScore, score)
			}
		}
	}

	want := map[string]int{"low": 11_528, "medium": 2_450_608, "high": 11_805_064, "critical": 12_274_880}
	if !maps.Equal(counts, want) {
		t.Errorf("severities over the product %v, want %v", counts, want)
	}
	if lowL != 34 || highL != 72 || lowT != 5 || highT != 36 || lowB != 7 || highB != 34 {
		t.Errorf("likelihood %v to %v, technical %v to %v, business %v to %v; want 4.25 to 9, 1.25 to 9, 1.75 to 8.5",
			float64(lowL)/8, float64(highL)/8, float64(lowT)/4, float64(highT)/4, float64(lowB)/4, float64(highB)/4)
	}
	if lowScore != 7.4375 || highScore != 81 {
		t.Errorf("score %v to %v, want 7.4375 to 81", lowScore, highScore)
	}
}
