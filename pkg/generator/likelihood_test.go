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

package generator

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/owasp"
	"github.com/venslabs/vens/pkg/riskconfig"
)

func likelihood(v owasp.Vector) float64 {
	return float64(int(v.SL)+int(v.M)+int(v.O)+int(v.S)+int(v.ED)+int(v.EE)+int(v.A)+int(v.ID)) / 8
}

// choices lists a question's closed answers as its schema writes them.
func choices(t *testing.T, f contract.Factor) []string {
	t.Helper()
	schema, err := contract.Schema(f, []string{"CVE-X"})
	require.NoError(t, err)
	return readSchema(schema).choices
}

// With Skill level, Ease of discovery and Awareness at 9, the scorer gives
// no likelihood below 4.25: walked over every exposure, every declared
// detection and every legal answer of Motive, Opportunity, Ease of exploit
// and Intrusion detection, the minimum is 4.25 internal, 4.5 private and
// 4.875 internet, each from the lowest answers, and OWASP's LOW band, under
// 3, is out of reach. Size at its lowest, the rest of that minimum kept,
// gives 4.0; Skill level and Size at their lowest give 3.0, still MEDIUM.
func TestMinimumLikelihood(t *testing.T) {
	detections := []*contract.Detection{nil}
	levels := []string{"not_logged", "logged", "logged_and_reviewed"}
	for _, n := range levels {
		for _, h := range levels {
			for _, a := range append(levels, "active_in_application") {
				detections = append(detections, &contract.Detection{Network: n, Host: h, Application: a})
			}
		}
	}
	var sets [][]string
	channels := []string{"network", "host", "application"}
	for mask := 1; mask < 1<<len(channels); mask++ {
		var set []string
		for i, c := range channels {
			if mask&(1<<i) != 0 {
				set = append(set, c)
			}
		}
		sets = append(sets, set)
	}
	sets = append(sets, []string{cannotTell})
	c := contract.CVE{ID: "CVE-X", Rows: []contract.Row{{PkgName: "a", Description: "Described.",
		CVSS: []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")}}}}

	want := map[string]float64{"internal": 4.25, "private": 4.5, "internet": 4.875}
	var lowest owasp.Vector
	for _, exposure := range []string{"internal", "private", "internet"} {
		min, walked := math.Inf(1), 0
		var at owasp.Vector
		for _, det := range detections {
			d := deploymentOf(testConfig())
			d.Exposure = setting(riskconfig.Exposure, exposure)
			d.Detection = det
			for _, m := range choices(t, contract.M) {
				for _, o := range choices(t, contract.O) {
					for _, ee := range choices(t, contract.EE) {
						for _, id := range sets {
							l, err := contract.Compute(d, c, contract.Answers{M: m, O: o, EE: ee, ID: id}, nil)
							require.NoError(t, err)
							require.Equal(t, [3]int{9, 9, 9}, [3]int{int(l.Vector.SL), int(l.Vector.ED), int(l.Vector.A)})
							walked++
							if got := likelihood(l.Vector); got < min {
								min, at = got, l.Vector
							}
						}
					}
				}
			}
		}
		t.Logf("%s: minimum likelihood %.3f over %d answer sets, at SL %d M %d O %d S %d ED %d EE %d A %d ID %d",
			exposure, min, walked, at.SL, at.M, at.O, at.S, at.ED, at.EE, at.A, at.ID)
		assert.Equal(t, want[exposure], min, exposure)
		assert.Equal(t, []int{1, 0, 1, 1}, []int{int(at.M), int(at.O), int(at.EE), int(at.ID)}, "%s: the lowest answers", exposure)
		if exposure == "internal" {
			lowest = at
		}
	}

	corner := lowest
	corner.S = owasp.SizeDevelopers
	t.Logf("Size at its lowest, %d: likelihood %.3f", corner.S, likelihood(corner))
	assert.Equal(t, 4.0, likelihood(corner))
	corner.SL = owasp.SkillLevelNoTechnicalSkills
	t.Logf("Skill level and Size at their lowest, %d and %d: likelihood %.3f", corner.SL, corner.S, likelihood(corner))
	assert.Equal(t, 3.0, likelihood(corner))
	rating, err := corner.Rate()
	require.NoError(t, err)
	assert.NotEqual(t, "info", rating.Severity, "a MEDIUM likelihood never rates info")
}
