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

// Basis is the impact a rating is read on, written as vens publishes it.
type Basis string

const (
	BasisTechnical Basis = "technical"
	BasisBusiness  Basis = "business"
)

// OWASP's Step 4, likelihood band by impact band, in lower case; its Note is
// CycloneDX's info.
var severities = [3][3]string{
	{"info", "low", "medium"},
	{"low", "medium", "high"},
	{"medium", "high", "critical"},
}

// Band is OWASP's level of a value on its 0 to 9 scale, a likelihood, an
// impact or a factor's level: 0 LOW under 3, 1 MEDIUM from 3 to under 6, 2
// HIGH from 6 (OWASP_Risk_Rating_Methodology.md:188-207).
func Band(x float64) int {
	switch {
	case x < 3:
		return 0
	case x < 6:
		return 1
	default:
		return 2
	}
}

// rate reads the severity and the score on the business impact when basis is
// BasisBusiness, on the technical impact otherwise. OWASP holds the business
// impact the more important and rates on it when the assessor has good
// business impact information; without it, the technical impact is the next
// best thing (OWASP_Risk_Rating_Methodology.md:142-145, :305-307). Which one
// holds is the deployment owner's declaration, read from the config, not a
// judgment of vens's.
//
// From integer levels the averages are k/8 and j/4 and the score k*j/32, all
// exact in float64, so nothing here is rounded and a published score always
// recomputes from its own vector and basis (#358).
func rate(likelihood, technical, business float64, basis Basis) (severity string, score float64) {
	impact := technical
	if basis == BasisBusiness {
		impact = business
	}
	return severities[Band(likelihood)][Band(impact)], likelihood * impact
}
