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

func TestEnrichReport_VectorMapping(t *testing.T) {
	// Create a mock VEX document with an OWASP rating that carries a vector
	score := 52.0
	vector := "SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:3/LC:7/LI:7/LAV:7/LAC:7/FD:7/RD:7/NC:7/PV:7"
	vex := cdx.BOM{
		SpecVersion: cdx.SpecVersion1_5,
		Vulnerabilities: &[]cdx.Vulnerability{
			{
				ID: "CVE-2023-1234",
				Ratings: &[]cdx.VulnerabilityRating{
					{
						Method: cdx.ScoringMethodOWASP,
						Score:  &score,
						Vector: vector,
					},
				},
			},
			{
				ID: "CVE-2023-9999",
				Ratings: &[]cdx.VulnerabilityRating{
					{
						Method: cdx.ScoringMethodOWASP,
						Score:  &score,
						// No vector supplied for this one.
					},
				},
			},
			{
				ID: "CVE-2023-7777",
				Ratings: &[]cdx.VulnerabilityRating{
					{Method: cdx.ScoringMethodOWASP, Score: &score},
					{
						Method: cdx.ScoringMethodCVSSv31,
						Score:  &score,
						Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
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
						VulnerabilityID: "CVE-2023-9999",
						PkgName:         "lib-b",
					},
					{
						VulnerabilityID: "CVE-2023-7777",
						PkgName:         "lib-c",
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

	require.Len(t, enrichedReport.Results, 1)
	require.Len(t, enrichedReport.Results[0].Vulnerabilities, 3)

	// First vulnerability has a vector - both fields should be present.
	vuln1 := enrichedReport.Results[0].Vulnerabilities[0]
	assert.Equal(t, "CVE-2023-1234", vuln1.VulnerabilityID)
	require.NotNil(t, vuln1.Custom)
	customMap1 := vuln1.Custom.(map[string]interface{})
	assert.Equal(t, score, customMap1["owasp_score"])
	assert.Equal(t, vector, customMap1["owasp_vector"])

	// Second vulnerability has no vector - only the score should be present.
	vuln2 := enrichedReport.Results[0].Vulnerabilities[1]
	assert.Equal(t, "CVE-2023-9999", vuln2.VulnerabilityID)
	require.NotNil(t, vuln2.Custom)
	customMap2 := vuln2.Custom.(map[string]interface{})
	assert.Equal(t, score, customMap2["owasp_score"])
	assert.NotContains(t, customMap2, "owasp_vector")

	// Third vulnerability's OWASP rating has no vector, but a sibling
	// CVSSv31 rating on the same CVE does. The CVSS vector must not leak
	// into owasp_vector: score and vector always come from the same
	// OWASP rating.
	vuln3 := enrichedReport.Results[0].Vulnerabilities[2]
	assert.Equal(t, "CVE-2023-7777", vuln3.VulnerabilityID)
	require.NotNil(t, vuln3.Custom)
	customMap3 := vuln3.Custom.(map[string]interface{})
	assert.Equal(t, score, customMap3["owasp_score"])
	assert.NotContains(t, customMap3, "owasp_vector")
}
