package vexenricher

import (
	"context"
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnrichReport_SimpleMapping(t *testing.T) {
	// Create a mock VEX document
	score := 7.5
	vex := cdx.BOM{
		SpecVersion: cdx.SpecVersion1_5,
		Vulnerabilities: &[]cdx.Vulnerability{
			{
				ID: "CVE-2023-1234",
				Ratings: &[]cdx.VulnerabilityRating{
					{
						Method: cdx.ScoringMethodOWASP,
						Score:  &score,
					},
				},
			},
		},
	}
	vexData, _ := json.Marshal(vex)

	// Create a mock Trivy report
	report := trivytypes.Report{
		Results: trivytypes.Results{
			{
				Target: "test-target",
				Vulnerabilities: []trivytypes.DetectedVulnerability{
					{
						VulnerabilityID: "CVE-2023-1234",
						PkgName:         "lib-a",
					},
					{
						VulnerabilityID: "CVE-2023-5678",
						PkgName:         "lib-b",
					},
				},
			},
		},
	}
	reportData, _ := json.Marshal(report)

	enricher, err := New(vexData)
	require.NoError(t, err)

	enrichedReport, err := enricher.EnrichReport(context.Background(), reportData)
	require.NoError(t, err)

	// Verify the enriched report
	require.Len(t, enrichedReport.Results, 1)
	require.Len(t, enrichedReport.Results[0].Vulnerabilities, 2)

	// First vulnerability should be enriched
	vuln1 := enrichedReport.Results[0].Vulnerabilities[0]
	assert.Equal(t, "CVE-2023-1234", vuln1.VulnerabilityID)
	require.NotNil(t, vuln1.Custom)
	customMap := vuln1.Custom.(map[string]interface{})
	assert.Equal(t, 7.5, customMap["owasp_score"])

	// Second vulnerability should NOT be enriched
	vuln2 := enrichedReport.Results[0].Vulnerabilities[1]
	assert.Equal(t, "CVE-2023-5678", vuln2.VulnerabilityID)
	assert.Nil(t, vuln2.Custom)
}
