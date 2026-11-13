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
	"regexp"
	"testing"
)

func TestFromAggregatedScores(t *testing.T) {
	tests := []struct {
		name            string
		threatAgent     float64
		vulnerability   float64
		technicalImpact float64
		businessImpact  float64
		wantPattern     string // Use pattern matching since exact values may vary
	}{
		{
			name:            "medium_scores",
			threatAgent:     5.5,
			vulnerability:   6.0,
			technicalImpact: 7.0,
			businessImpact:  4.0,
			wantPattern:     "^SL:6/M:6/O:6/S:6/ED:6/EE:6/A:6/ID:6/LC:7/LI:7/LAV:7/LAC:7/FD:4/RD:4/NC:4/PV:4$",
		},
		{
			name:            "high_scores",
			threatAgent:     8.0,
			vulnerability:   7.0,
			technicalImpact: 8.0,
			businessImpact:  9.0,
			wantPattern:     "^SL:8/M:8/O:8/S:8/ED:7/EE:7/A:7/ID:7/LC:8/LI:8/LAV:8/LAC:8/FD:9/RD:9/NC:9/PV:9$",
		},
		{
			name:            "low_scores",
			threatAgent:     2.0,
			vulnerability:   3.0,
			technicalImpact: 4.0,
			businessImpact:  3.0,
			wantPattern:     "^SL:2/M:2/O:2/S:2/ED:3/EE:3/A:3/ID:3/LC:4/LI:4/LAV:4/LAC:4/FD:3/RD:3/NC:3/PV:3$",
		},
		{
			name:            "clamp_above_9",
			threatAgent:     12.0, // Should be clamped to 9
			vulnerability:   10.5, // Should be clamped to 9
			technicalImpact: 11.0,
			businessImpact:  15.0,
			wantPattern:     "^SL:9/M:9/O:9/S:9/ED:9/EE:9/A:9/ID:9/LC:9/LI:9/LAV:9/LAC:9/FD:9/RD:9/NC:9/PV:9$",
		},
		{
			name:            "clamp_below_0",
			threatAgent:     -1.0, // Should be clamped to 0
			vulnerability:   -2.0,
			technicalImpact: 0.0,
			businessImpact:  -0.5,
			wantPattern:     "^SL:0/M:0/O:0/S:0/ED:0/EE:0/A:0/ID:0/LC:0/LI:0/LAV:0/LAC:0/FD:0/RD:0/NC:0/PV:0$",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vector := FromAggregatedScores(tt.threatAgent, tt.vulnerability, tt.technicalImpact, tt.businessImpact)
			vectorString := vector.String()

			matched, err := regexp.MatchString(tt.wantPattern, vectorString)
			if err != nil {
				t.Fatalf("Invalid regex pattern: %v", err)
			}
			if !matched {
				t.Errorf("FromAggregatedScores() = %v, want pattern %v", vectorString, tt.wantPattern)
			}

			// Verify it matches standard OWASP RR pattern
			standardPattern := regexp.MustCompile(`^SL:\d/M:\d/O:\d/S:\d/ED:\d/EE:\d/A:\d/ID:\d/LC:\d/LI:\d/LAV:\d/LAC:\d/FD:\d/RD:\d/NC:\d/PV:\d$`)
			if !standardPattern.MatchString(vectorString) {
				t.Errorf("Vector %q does not match standard OWASP RR pattern", vectorString)
			}
		})
	}
}
