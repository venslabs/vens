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
	"slices"
	"strings"

	grypemodels "github.com/anchore/grype/grype/presenter/models"
	"github.com/package-url/packageurl-go"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/generator"
)

// GrypeScanner parses Grype JSON vulnerability reports
type GrypeScanner struct{}

// Parse converts a Grype report to common Vulnerability format
func (s *GrypeScanner) Parse(data []byte) ([]generator.Vulnerability, error) {
	var report grypemodels.Document
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse Grype report: %w", err)
	}

	var vulns []generator.Vulnerability

	for _, match := range report.Matches {
		vuln := match.Vulnerability

		// Calculate BOMRef using Grype's logic
		bomRef := calculateBOMRef(match.Artifact)

		// Extract fixed version from match details
		fixedVersion := extractFixedVersion(match)

		v := generator.Vulnerability{
			VulnID:           vuln.ID,
			PkgID:            match.Artifact.ID,
			PkgName:          match.Artifact.Name,
			InstalledVersion: match.Artifact.Version,
			FixedVersion:     fixedVersion,
			BOMRef:           bomRef,
			Title:            "", // Grype doesn't provide a separate title
			Description:      vuln.Description,
			Severity:         vuln.Severity,
			SourceName:       grypeNamespaceToSourceName(vuln.Namespace, vuln.ID),
			SourceURL:        vuln.DataSource,
			CVSS:             grypeVectors(match),
			SeveritySource:   vuln.Namespace,
			VendorSeverities: grypeVendorSeverities(match.RelatedVulnerabilities),
		}
		vulns = append(vulns, v)
	}

	return vulns, nil
}

// Name returns the scanner identifier
func (s *GrypeScanner) Name() string {
	return string(ScannerGrype)
}

// grypeVectors lists the matched record's vectors, then each related
// record's, each distinct vector once.
func grypeVectors(match grypemodels.Match) []cvss.Vector {
	var vectors []cvss.Vector
	add := func(scores []grypemodels.Cvss) {
		for _, c := range scores {
			v := cvss.Vector{Source: c.Source, Version: c.Version, Vector: c.Vector}
			if !slices.Contains(vectors, v) {
				vectors = append(vectors, v)
			}
		}
	}
	add(match.Vulnerability.Cvss)
	for _, related := range match.RelatedVulnerabilities {
		add(related.Cvss)
	}
	return vectors
}

// grypeVendorSeverities lists each related record's namespace and severity,
// in namespace order, each distinct pair once.
func grypeVendorSeverities(related []grypemodels.VulnerabilityMetadata) []generator.VendorSeverity {
	var severities []generator.VendorSeverity
	for _, r := range related {
		s := generator.VendorSeverity{Source: r.Namespace, Severity: r.Severity}
		if !slices.Contains(severities, s) {
			severities = append(severities, s)
		}
	}
	slices.SortStableFunc(severities, func(a, b generator.VendorSeverity) int {
		return strings.Compare(a.Source, b.Source)
	})
	return severities
}

// calculateBOMRef calculates the BOM-Ref for Grype artifacts.
// This is the exact logic from Grype's deriveBomRef function.
//
// See: https://github.com/anchore/grype/blob/v0.109.1/grype/presenter/cyclonedx/vulnerability.go#L186-L197
func calculateBOMRef(p grypemodels.Package) string {
	// try and parse the PURL if possible and append syft id to it, to make
	// the purl unique in the BOM.
	// TODO: In the future we may want to dedupe by PURL and combine components with
	// the same PURL while preserving their unique metadata.
	if parsedPURL, err := packageurl.FromString(p.PURL); err == nil {
		parsedPURL.Qualifiers = append(parsedPURL.Qualifiers, packageurl.Qualifier{Key: "package-id", Value: p.ID})
		return parsedPURL.ToString()
	}
	// fallback is to use strictly the ID if there is no valid pURL
	return p.ID
}

// grypeNamespaceToSourceName maps a Grype namespace (e.g., "nvd:cpe",
// "github:language:go") to a well-known source name.
func grypeNamespaceToSourceName(namespace string, vulnID string) string {
	if src := SourceFromVulnID(vulnID); src != "" {
		return src
	}
	ns := strings.ToLower(namespace)
	switch {
	case strings.HasPrefix(ns, "nvd"):
		return SourceNVD
	case strings.HasPrefix(ns, "github"):
		return SourceGITHUB
	case strings.HasPrefix(ns, "osv"):
		return SourceOSV
	}
	return SourceUNKNOWN
}

// extractFixedVersion extracts the fixed version from Grype match details.
// Prioritizes SuggestedVersion from MatchDetails (calculated by Grype) over raw Fix.Versions.
//
// See: https://github.com/anchore/grype/blob/v0.109.1/grype/presenter/models/match.go#L84-L91
func extractFixedVersion(match grypemodels.Match) string {
	// Priority 1: Use SuggestedVersion from MatchDetails (best version calculated by Grype)
	for _, detail := range match.MatchDetails {
		if detail.Fix != nil && detail.Fix.SuggestedVersion != "" {
			return detail.Fix.SuggestedVersion
		}
	}

	// Priority 2: Fallback to first fixed version if available
	if match.Vulnerability.Fix.State == "fixed" && len(match.Vulnerability.Fix.Versions) > 0 {
		return match.Vulnerability.Fix.Versions[0]
	}

	return ""
}
