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

package scanner

import (
	"encoding/json"
	"fmt"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/venslabs/vens/pkg/generator"
)

// TrivyScanner parses Trivy JSON vulnerability reports
type TrivyScanner struct{}

// Parse converts a Trivy report to common Vulnerability format
func (s *TrivyScanner) Parse(data []byte) ([]generator.Vulnerability, error) {
	var report trivytypes.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse Trivy report: %w", err)
	}

	purlCounts := make(map[string]int)
	var vulns []generator.Vulnerability

	for _, result := range report.Results {
		for _, v := range result.Vulnerabilities {
			if v.PkgIdentifier.PURL != nil {
				purl := v.PkgIdentifier.PURL.ToString()
				purlCounts[purl]++
			}

			// Calculate BOMRef using Trivy's logic
			bomRef := calculateTrivyBOMRef(v.PkgIdentifier, v.PkgID, purlCounts)

			vuln := generator.Vulnerability{
				VulnID:           v.VulnerabilityID,
				PkgID:            v.PkgID,
				PkgName:          v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				BOMRef:           bomRef,
				Title:            v.Title,
				Description:      v.Description,
				Severity:         v.Severity,
			}
			if v.DataSource != nil {
				vuln.SourceName = trivyDataSourceToSourceName(string(v.DataSource.ID), v.VulnerabilityID)
				vuln.SourceURL = v.DataSource.URL
			}
			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}

// Name returns the scanner identifier
func (s *TrivyScanner) Name() string {
	return string(ScannerTrivy)
}

// calculateTrivyBOMRef calculates the BOM-Ref using Trivy's logic.
// This follows the same algorithm as Trivy to ensure VEX compatibility.
//
// Logic (from Trivy pkg/sbom/core/bom.go):
//  1. If BOMRef is already set, use it
//  2. If no PURL, use fallback identifier (PkgID)
//  3. If PURL is not unique (appears multiple times), use fallback identifier
//  4. Otherwise, use PURL
//
// See: https://github.com/aquasecurity/trivy/blob/v0.69.0/pkg/sbom/core/bom.go#L364
func calculateTrivyBOMRef(pkgIdentifier ftypes.PkgIdentifier, pkgID string, purlCounts map[string]int) string {
	// 1. If BOMRef is already set, use it
	if pkgIdentifier.BOMRef != "" {
		return pkgIdentifier.BOMRef
	}

	// 2. If no PURL, use fallback identifier
	if pkgIdentifier.PURL == nil {
		return pkgID
	}

	purl := pkgIdentifier.PURL.ToString()

	// 3. If PURL is not unique (appears multiple times), use fallback identifier
	if purlCounts[purl] > 1 {
		return pkgID
	}

	// 4. Otherwise, use PURL
	return purl
}

func trivyDataSourceToSourceName(dataSourceID string, vulnID string) string {
	if src := SourceFromVulnID(vulnID); src != "" {
		return src
	}
	id := strings.ToLower(dataSourceID)
	switch {
	case strings.HasPrefix(id, "nvd"):
		return SourceNVD
	case strings.HasPrefix(id, "ghsa"), strings.HasPrefix(id, "github"):
		return SourceGITHUB
	case strings.HasPrefix(id, "osv"):
		return SourceOSV
	case strings.HasPrefix(id, "npm"):
		return SourceNPM
	case strings.HasPrefix(id, "ossindex"):
		return SourceOSSINDEX
	case strings.HasPrefix(id, "snyk"):
		return SourceSNYK
	case strings.HasPrefix(id, "vulndb"):
		return SourceVULNDB
	}
	return SourceUNKNOWN
}
