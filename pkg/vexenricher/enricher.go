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

package vexenricher

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	cdx "github.com/CycloneDX/cyclonedx-go"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
)

// VEXEnricher enriches Trivy reports with VEX ratings using simple Vulnerability ID matching
type VEXEnricher struct {
	// Map of VulnerabilityID to OWASP Score
	OWASPScorePerVulnID map[string]float64
	// Map of VulnerabilityID to OWASP Risk Rating vector string
	OWASPVectorPerVulnID map[string]string
	// Map of VulnerabilityID to OWASP severity band (critical/high/medium/low/info).
	// The band is what downstream gates should read; the raw score is on a
	// vens-internal scale.
	OWASPSeverityPerVulnID map[string]string
	// Map of VulnerabilityID to the vens:impact-provenance property of the
	// vulnerability whose OWASP rating is kept: cvss-v3, or
	// missing-cvss-v3-fallback when the missing-input rule supplied the three
	// technical impacts. Absent when the VEX carries none.
	ImpactProvenancePerVulnID map[string]string
	// Map of VulnerabilityID to the vens:impact-basis property of the
	// vulnerability whose OWASP rating is kept: technical or business, the
	// impact its severity and score are read on. Absent when the VEX carries
	// none.
	ImpactBasisPerVulnID map[string]string
}

// The properties vens generate writes on each VEX vulnerability
// (outputhandler.ImpactProvenanceProperty, outputhandler.ImpactBasisProperty).
const (
	impactProvenanceProperty = "vens:impact-provenance"
	impactBasisProperty      = "vens:impact-basis"
)

// New creates a new VEXEnricher from VEX data
func New(vexData []byte) (*VEXEnricher, error) {
	var vexDoc cdx.BOM
	if err := json.Unmarshal(vexData, &vexDoc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal VEX document: %w", err)
	}

	enricher := &VEXEnricher{
		OWASPScorePerVulnID:       make(map[string]float64),
		OWASPVectorPerVulnID:      make(map[string]string),
		OWASPSeverityPerVulnID:    make(map[string]string),
		ImpactProvenancePerVulnID: make(map[string]string),
		ImpactBasisPerVulnID:      make(map[string]string),
	}

	// Parse VEX vulnerabilities - extract OWASP ratings by Vulnerability ID
	if vexDoc.Vulnerabilities != nil {
		for _, vuln := range *vexDoc.Vulnerabilities {
			if vuln.Ratings == nil {
				continue
			}

			for _, rating := range *vuln.Ratings {
				// Enrich only with OWASP score
				if rating.Method != cdx.ScoringMethodOWASP || rating.Score == nil {
					continue
				}

				// Map the score, vector and severity to the vulnerability ID.
				// Note: if multiple entries exist for the same CVE in VEX,
				// we take the last one found.
				enricher.OWASPScorePerVulnID[vuln.ID] = *rating.Score
				enricher.OWASPVectorPerVulnID[vuln.ID] = rating.Vector
				enricher.OWASPSeverityPerVulnID[vuln.ID] = string(rating.Severity)
				if p := propertyValue(vuln, impactProvenanceProperty); p != "" {
					enricher.ImpactProvenancePerVulnID[vuln.ID] = p
				} else {
					delete(enricher.ImpactProvenancePerVulnID, vuln.ID)
				}
				if b := propertyValue(vuln, impactBasisProperty); b != "" {
					enricher.ImpactBasisPerVulnID[vuln.ID] = b
				} else {
					delete(enricher.ImpactBasisPerVulnID, vuln.ID)
				}
			}
		}
	}

	return enricher, nil
}

// EnrichReport enriches a Trivy report with OWASP ratings from VEX
func (e *VEXEnricher) EnrichReport(ctx context.Context, reportData []byte) (*trivytypes.Report, error) {
	var report trivytypes.Report
	if err := json.Unmarshal(reportData, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal Trivy report: %w", err)
	}

	slog.DebugContext(ctx, "Starting simple VEX enrichment",
		"vex_scores_count", len(e.OWASPScorePerVulnID))

	enrichedCount := 0
	for i := range report.Results {
		result := &report.Results[i]
		for j := range result.Vulnerabilities {
			vuln := &result.Vulnerabilities[j]

			if score, ok := e.OWASPScorePerVulnID[vuln.VulnerabilityID]; ok {
				vector := e.OWASPVectorPerVulnID[vuln.VulnerabilityID]
				severity := e.OWASPSeverityPerVulnID[vuln.VulnerabilityID]
				provenance := e.ImpactProvenancePerVulnID[vuln.VulnerabilityID]
				basis := e.ImpactBasisPerVulnID[vuln.VulnerabilityID]
				if e.applyRating(vuln, score, vector, severity, provenance, basis) {
					enrichedCount++
				}
			}
		}
	}

	if enrichedCount > 0 {
		slog.InfoContext(ctx, "Enriched report with VEX ratings", "count", enrichedCount)
	}

	return &report, nil
}

// applyRating sets the OWASP score (and, if present, the OWASP Risk Rating
// vector, severity band, impact provenance and impact basis) in the
// vulnerability's Custom field
func (e *VEXEnricher) applyRating(vuln *trivytypes.DetectedVulnerability, score float64, vector, severity, provenance, basis string) bool {
	if vuln.Custom == nil {
		vuln.Custom = make(map[string]interface{})
	}

	customMap, ok := vuln.Custom.(map[string]interface{})
	if !ok {
		// If Custom is not a map, we try to overwrite it if it's empty,
		// but usually it's better to avoid breaking existing data.
		// However, in Trivy's context, if it's not a map, we can't easily add our field.
		return false
	}

	// Temporary fields until Trivy adds official ones
	customMap["owasp_score"] = score
	if vector != "" {
		customMap["owasp_vector"] = vector
	} else {
		delete(customMap, "owasp_vector")
	}
	// The severity band is the field vens commits to for downstream gates:
	// the raw score lives on a vens-internal scale.
	if severity != "" {
		customMap["owasp_severity"] = severity
	} else {
		delete(customMap, "owasp_severity")
	}
	// Whether the rating's impact was assessed or is the missing-input
	// rule's worst case, as the VEX says: a consumer keeps the second apart.
	if provenance != "" {
		customMap["owasp_impact_provenance"] = provenance
	} else {
		delete(customMap, "owasp_impact_provenance")
	}
	// The impact the severity and score are read on, as the VEX says: the
	// vector alone does not tell a consumer which.
	if basis != "" {
		customMap["owasp_impact_basis"] = basis
	} else {
		delete(customMap, "owasp_impact_basis")
	}
	return true
}

// propertyValue is the value of vuln's property name, "" when it has none.
func propertyValue(vuln cdx.Vulnerability, name string) string {
	if vuln.Properties == nil {
		return ""
	}
	for _, p := range *vuln.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}
