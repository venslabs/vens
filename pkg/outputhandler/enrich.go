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

package outputhandler

import (
	"fmt"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/fahedouch/vens/pkg/api/types"
)

// EnrichTrivyReportWithVEX takes a Trivy report and enriches it with data from a CycloneDX VEX.
func EnrichTrivyReportWithVEX(report *types.Report, vex *cyclonedx.BOM) error {
	if vex.Vulnerabilities == nil {
		return nil
	}

	// Map VEX vulnerabilities by ID and affected component
	vexMap := make(map[string]cyclonedx.VulnerabilityRating)
	for _, v := range *vex.Vulnerabilities {
		if v.Ratings == nil || len(*v.Ratings) == 0 {
			continue
		}
		// We take the first rating
		rating := (*v.Ratings)[0]

		key := v.ID
		if v.Affects != nil && len(*v.Affects) > 0 {
			// In CycloneDX VEX, Affects[0].Ref is usually the PURL or BomRef
			key = fmt.Sprintf("%s@%s", v.ID, (*v.Affects)[0].Ref)
		}
		vexMap[key] = rating
	}

	for i := range report.Results {
		for j := range report.Results[i].Vulnerabilities {
			v := &report.Results[i].Vulnerabilities[j]

			key := v.VulnerabilityID
			if v.PkgID != "" {
				key = fmt.Sprintf("%s@%s", v.VulnerabilityID, v.PkgID)
			}

			if rating, ok := vexMap[key]; ok {
				v.VensRating = &types.VensRating{
					Score:         *rating.Score,
					Severity:      string(rating.Severity),
					Justification: rating.Justification,
				}
			} else if rating, ok := vexMap[v.VulnerabilityID]; ok {
				v.VensRating = &types.VensRating{
					Score:         *rating.Score,
					Severity:      string(rating.Severity),
					Justification: rating.Justification,
				}
			}
		}
	}

	return nil
}
