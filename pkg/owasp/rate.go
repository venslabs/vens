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

// OWASP's Step 4, likelihood band by impact band, in lower case; its Note is
// CycloneDX's info.
var severities = [3][3]string{
	{"info", "low", "medium"},
	{"low", "medium", "high"},
	{"medium", "high", "critical"},
}

// band is OWASP's level of a likelihood or an impact: under 3 LOW, 3 to
// under 6 MEDIUM, 6 and up HIGH.
func band(x float64) int {
	switch {
	case x < 3:
		return 0
	case x < 6:
		return 1
	default:
		return 2
	}
}

// rate takes the larger of the technical and business impacts (#340). OWASP
// rates on the business impact when the assessor holds good business
// information, and vens cannot tell that its business levels are that, so it
// takes the worse of OWASP's two choices.
//
// From integer levels the averages are k/8 and j/4 and the score k*j/32, all
// exact in float64, so nothing here is rounded (#358).
func rate(likelihood, technical, business float64) (severity string, score float64) {
	impact := max(technical, business)
	return severities[band(likelihood)][band(impact)], likelihood * impact
}
