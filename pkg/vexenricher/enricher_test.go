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

func TestEnrichReport_SeverityMapping(t *testing.T) {
	// The enricher copies the rating's severity band into Custom so
	// downstream gates can read the band instead of the raw score.
	score := 45.0
	vex := cdx.BOM{
		SpecVersion: cdx.SpecVersion1_5,
		Vulnerabilities: &[]cdx.Vulnerability{
			{
				ID: "CVE-2023-1234",
				Ratings: &[]cdx.VulnerabilityRating{
					{
						Method:   cdx.ScoringMethodOWASP,
						Score:    &score,
						Severity: cdx.SeverityHigh,
					},
				},
			},
			{
				ID: "CVE-2023-9999",
				Ratings: &[]cdx.VulnerabilityRating{
					{
						Method: cdx.ScoringMethodOWASP,
						Score:  &score,
						// No severity carried: owasp_severity must stay absent.
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
	require.Len(t, enrichedReport.Results[0].Vulnerabilities, 2)

	// Rating carries a severity band: it must land in Custom.
	vuln1 := enrichedReport.Results[0].Vulnerabilities[0]
	assert.Equal(t, "CVE-2023-1234", vuln1.VulnerabilityID)
	require.NotNil(t, vuln1.Custom)
	customMap1 := vuln1.Custom.(map[string]interface{})
	assert.Equal(t, "high", customMap1["owasp_severity"])

	// Rating without a severity band: the key must stay absent.
	vuln2 := enrichedReport.Results[0].Vulnerabilities[1]
	assert.Equal(t, "CVE-2023-9999", vuln2.VulnerabilityID)
	require.NotNil(t, vuln2.Custom)
	customMap2 := vuln2.Custom.(map[string]interface{})
	assert.NotContains(t, customMap2, "owasp_severity")
}

func TestEnrichReport_SeverityProvenance(t *testing.T) {
	// The band must be the OWASP rating's own band, never recomputed from
	// the score, read from another method's rating, or kept from an
	// earlier rating when the last OWASP rating carries none.
	score45 := 45.0
	scoreLow := 12.0
	score10 := 10.0
	score98 := 9.8
	vex := cdx.BOM{
		SpecVersion: cdx.SpecVersion1_5,
		Vulnerabilities: &[]cdx.Vulnerability{
			{
				// #310 can produce score 45 with a critical band; a
				// recompute from the score would give high instead.
				ID: "CVE-2023-4444",
				Ratings: &[]cdx.VulnerabilityRating{
					{
						Method:   cdx.ScoringMethodOWASP,
						Score:    &score45,
						Severity: cdx.SeverityCritical,
					},
				},
			},
			{
				// A CVSSv31 critical rating next to an OWASP low: the
				// band must come from the OWASP rating, not any rating.
				ID: "CVE-2023-5555",
				Ratings: &[]cdx.VulnerabilityRating{
					{
						Method:   cdx.ScoringMethodOWASP,
						Score:    &scoreLow,
						Severity: cdx.SeverityLow,
					},
					{
						Method:   cdx.ScoringMethodCVSSv31,
						Score:    &score98,
						Severity: cdx.SeverityCritical,
					},
				},
			},
			{
				// Two OWASP ratings where the last has no band: the last
				// rating wins wholesale, so no band is written.
				ID: "CVE-2023-6666",
				Ratings: &[]cdx.VulnerabilityRating{
					{
						Method:   cdx.ScoringMethodOWASP,
						Score:    &score45,
						Severity: cdx.SeverityHigh,
					},
					{
						Method: cdx.ScoringMethodOWASP,
						Score:  &score10,
						// No severity carried.
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
						VulnerabilityID: "CVE-2023-4444",
						PkgName:         "lib-a",
					},
					{
						VulnerabilityID: "CVE-2023-5555",
						PkgName:         "lib-b",
					},
					{
						VulnerabilityID: "CVE-2023-6666",
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

	// Copied band survives even when it disagrees with the score's band.
	vuln1 := enrichedReport.Results[0].Vulnerabilities[0]
	assert.Equal(t, "CVE-2023-4444", vuln1.VulnerabilityID)
	require.NotNil(t, vuln1.Custom)
	customMap1 := vuln1.Custom.(map[string]interface{})
	assert.Equal(t, "critical", customMap1["owasp_severity"])
	assert.Equal(t, score45, customMap1["owasp_score"])

	// The band comes from the OWASP rating, not the CVSS one.
	vuln2 := enrichedReport.Results[0].Vulnerabilities[1]
	assert.Equal(t, "CVE-2023-5555", vuln2.VulnerabilityID)
	require.NotNil(t, vuln2.Custom)
	customMap2 := vuln2.Custom.(map[string]interface{})
	assert.Equal(t, "low", customMap2["owasp_severity"])

	// Last OWASP rating has no band: score updates, the key stays absent.
	vuln3 := enrichedReport.Results[0].Vulnerabilities[2]
	assert.Equal(t, "CVE-2023-6666", vuln3.VulnerabilityID)
	require.NotNil(t, vuln3.Custom)
	customMap3 := vuln3.Custom.(map[string]interface{})
	assert.Equal(t, score10, customMap3["owasp_score"])
	assert.NotContains(t, customMap3, "owasp_severity")
}

func TestEnrichReport_SeverityDeleteBranch(t *testing.T) {
	// A rating without a severity band whose key is already in Custom must
	// clear the stale entry: the delete branch in applyRating.
	score := 12.0
	vex := cdx.BOM{
		SpecVersion: cdx.SpecVersion1_5,
		Vulnerabilities: &[]cdx.Vulnerability{
			{
				ID: "CVE-2023-1234",
				Ratings: &[]cdx.VulnerabilityRating{
					{
						Method: cdx.ScoringMethodOWASP,
						Score:  &score,
						// No severity carried.
					},
				},
			},
		},
	}
	vexData, _ := json.Marshal(vex)

	// The report carries a stale band from an earlier enrichment.
	report := trivytypes.Report{
		Results: trivytypes.Results{
			{
				Target: "test-target",
				Vulnerabilities: []trivytypes.DetectedVulnerability{
					{
						VulnerabilityID: "CVE-2023-1234",
						PkgName:         "lib-a",
						Custom: map[string]interface{}{
							"owasp_score":    99.0,
							"owasp_severity": "critical",
						},
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
	require.Len(t, enrichedReport.Results[0].Vulnerabilities, 1)

	vuln := enrichedReport.Results[0].Vulnerabilities[0]
	require.NotNil(t, vuln.Custom)
	customMap := vuln.Custom.(map[string]interface{})
	// The stale band is deleted, and the fresh score is still written.
	assert.NotContains(t, customMap, "owasp_severity")
	assert.Equal(t, score, customMap["owasp_score"])
}
