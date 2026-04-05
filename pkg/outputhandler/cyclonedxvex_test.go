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
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
)

func TestCycloneDxVexWriter_Close_SerialNumber(t *testing.T) {
	var buf bytes.Buffer
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1)

	score := 42.0
	err := h.HandleVulnRatings([]VulnRating{
		{
			VulnID: "CVE-2024-1234",
			BOMRef: "pkg:npm/foo@1.0.0",
			Rating: cyclonedx.VulnerabilityRating{
				Method:   cyclonedx.ScoringMethodOWASP,
				Score:    &score,
				Severity: cyclonedx.SeverityHigh,
			},
			Source: &cyclonedx.Source{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
		},
	})
	if err != nil {
		t.Fatalf("HandleVulnRatings: %v", err)
	}

	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var bom cyclonedx.BOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("unmarshal BOM: %v", err)
	}

	// Verify serialNumber is set and has urn:uuid: prefix
	if bom.SerialNumber == "" {
		t.Error("serialNumber is empty")
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Errorf("serialNumber %q does not start with urn:uuid:", bom.SerialNumber)
	}

	// Verify version matches sbomVersion passed to constructor
	if bom.Version != 1 {
		t.Errorf("version = %d, want 1", bom.Version)
	}
}

func TestCycloneDxVexWriter_Close_VersionFromSBOM(t *testing.T) {
	var buf bytes.Buffer
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 3)

	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var bom cyclonedx.BOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("unmarshal BOM: %v", err)
	}

	if bom.Version != 3 {
		t.Errorf("version = %d, want 3", bom.Version)
	}
}

func TestCycloneDxVexWriter_Close_Metadata(t *testing.T) {
	var buf bytes.Buffer
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1)

	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var bom cyclonedx.BOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("unmarshal BOM: %v", err)
	}

	if bom.Metadata == nil {
		t.Fatal("metadata is nil")
	}

	if bom.Metadata.Timestamp == "" {
		t.Error("metadata.timestamp is empty")
	}

	if bom.Metadata.Tools == nil || bom.Metadata.Tools.Components == nil {
		t.Fatal("metadata.tools.components is nil")
	}

	components := *bom.Metadata.Tools.Components
	if len(components) == 0 {
		t.Fatal("metadata.tools.components is empty")
	}

	found := false
	for _, c := range components {
		if c.Name == "vens" {
			found = true
			break
		}
	}
	if !found {
		t.Error("metadata.tools.components does not contain 'vens'")
	}
}

func TestCycloneDxVexWriter_Close_VulnerabilitySource(t *testing.T) {
	var buf bytes.Buffer
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1)

	score := 42.0
	err := h.HandleVulnRatings([]VulnRating{
		{
			VulnID: "CVE-2024-1234",
			BOMRef: "pkg:npm/foo@1.0.0",
			Rating: cyclonedx.VulnerabilityRating{
				Method:   cyclonedx.ScoringMethodOWASP,
				Score:    &score,
				Severity: cyclonedx.SeverityHigh,
			},
			Source: &cyclonedx.Source{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
		},
		{
			VulnID: "GHSA-abcd-efgh-ijkl",
			BOMRef: "pkg:npm/bar@2.0.0",
			Rating: cyclonedx.VulnerabilityRating{
				Method:   cyclonedx.ScoringMethodOWASP,
				Score:    &score,
				Severity: cyclonedx.SeverityMedium,
			},
			Source: &cyclonedx.Source{Name: "GITHUB", URL: "https://github.com/advisories/GHSA-abcd-efgh-ijkl"},
		},
	})
	if err != nil {
		t.Fatalf("HandleVulnRatings: %v", err)
	}

	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var bom cyclonedx.BOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("unmarshal BOM: %v", err)
	}

	if bom.Vulnerabilities == nil {
		t.Fatal("vulnerabilities is nil")
	}

	vulns := *bom.Vulnerabilities
	if len(vulns) != 2 {
		t.Fatalf("got %d vulnerabilities, want 2", len(vulns))
	}

	// Build lookup map (order is not guaranteed)
	vulnByID := make(map[string]cyclonedx.Vulnerability)
	for _, v := range vulns {
		vulnByID[v.ID] = v
	}

	// Check CVE source
	cve, ok := vulnByID["CVE-2024-1234"]
	if !ok {
		t.Fatal("CVE-2024-1234 not found")
	}
	if cve.Source == nil {
		t.Fatal("CVE vulnerability source is nil")
	}
	if cve.Source.Name != "NVD" {
		t.Errorf("CVE source name = %q, want NVD", cve.Source.Name)
	}
	if !strings.Contains(cve.Source.URL, "nvd.nist.gov") {
		t.Errorf("CVE source URL = %q, want URL containing nvd.nist.gov", cve.Source.URL)
	}

	// Check GHSA source
	ghsa, ok := vulnByID["GHSA-abcd-efgh-ijkl"]
	if !ok {
		t.Fatal("GHSA-abcd-efgh-ijkl not found")
	}
	if ghsa.Source == nil {
		t.Fatal("GHSA vulnerability source is nil")
	}
	if ghsa.Source.Name != "GITHUB" {
		t.Errorf("GHSA source name = %q, want GITHUB", ghsa.Source.Name)
	}
	if !strings.Contains(ghsa.Source.URL, "github.com/advisories") {
		t.Errorf("GHSA source URL = %q, want URL containing github.com/advisories", ghsa.Source.URL)
	}
}

func TestCycloneDxVexWriter_Close_MergesDuplicateVulnIDs(t *testing.T) {
	var buf bytes.Buffer
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1)

	score := 42.0
	err := h.HandleVulnRatings([]VulnRating{
		{
			VulnID: "CVE-2024-1234",
			BOMRef: "pkg:npm/foo@1.0.0",
			Rating: cyclonedx.VulnerabilityRating{
				Method:   cyclonedx.ScoringMethodOWASP,
				Score:    &score,
				Severity: cyclonedx.SeverityHigh,
			},
			Source: &cyclonedx.Source{Name: "NVD", URL: "https://nvd.nist.gov"},
		},
		{
			VulnID: "CVE-2024-1234",
			BOMRef: "pkg:npm/bar@2.0.0",
			Rating: cyclonedx.VulnerabilityRating{
				Method:   cyclonedx.ScoringMethodOWASP,
				Score:    &score,
				Severity: cyclonedx.SeverityHigh,
			},
			Source: &cyclonedx.Source{Name: "NVD", URL: "https://nvd.nist.gov"},
		},
		{
			VulnID: "CVE-2024-5678",
			BOMRef: "pkg:npm/baz@3.0.0",
			Rating: cyclonedx.VulnerabilityRating{
				Method:   cyclonedx.ScoringMethodOWASP,
				Score:    &score,
				Severity: cyclonedx.SeverityMedium,
			},
			Source: &cyclonedx.Source{Name: "NVD", URL: "https://nvd.nist.gov"},
		},
	})
	if err != nil {
		t.Fatalf("HandleVulnRatings: %v", err)
	}

	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var bom cyclonedx.BOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("unmarshal BOM: %v", err)
	}

	if bom.Vulnerabilities == nil {
		t.Fatal("vulnerabilities is nil")
	}

	vulns := *bom.Vulnerabilities
	if len(vulns) != 2 {
		t.Fatalf("got %d vulnerabilities, want 2 (duplicates should be merged)", len(vulns))
	}

	var cve1234 *cyclonedx.Vulnerability
	for i := range vulns {
		if vulns[i].ID == "CVE-2024-1234" {
			cve1234 = &vulns[i]
			break
		}
	}

	if cve1234 == nil {
		t.Fatal("CVE-2024-1234 not found")
	}

	if cve1234.Affects == nil || len(*cve1234.Affects) != 2 {
		t.Errorf("CVE-2024-1234 has %d affects, want 2", len(*cve1234.Affects))
	}
}

func TestCycloneDxVexWriter_Close_DeduplicatesAffectsRefs(t *testing.T) {
	var buf bytes.Buffer
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1)

	score := 42.0
	err := h.HandleVulnRatings([]VulnRating{
		{
			VulnID: "CVE-2024-1234",
			BOMRef: "pkg:npm/foo@1.0.0",
			Rating: cyclonedx.VulnerabilityRating{
				Method:   cyclonedx.ScoringMethodOWASP,
				Score:    &score,
				Severity: cyclonedx.SeverityHigh,
			},
			Source: &cyclonedx.Source{Name: "NVD", URL: "https://nvd.nist.gov"},
		},
		{
			VulnID: "CVE-2024-1234",
			BOMRef: "pkg:npm/foo@1.0.0",
			Rating: cyclonedx.VulnerabilityRating{
				Method:   cyclonedx.ScoringMethodOWASP,
				Score:    &score,
				Severity: cyclonedx.SeverityHigh,
			},
			Source: &cyclonedx.Source{Name: "NVD", URL: "https://nvd.nist.gov"},
		},
	})
	if err != nil {
		t.Fatalf("HandleVulnRatings: %v", err)
	}

	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var bom cyclonedx.BOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("unmarshal BOM: %v", err)
	}

	vulns := *bom.Vulnerabilities
	if len(vulns) != 1 {
		t.Fatalf("got %d vulnerabilities, want 1", len(vulns))
	}

	if vulns[0].Affects == nil || len(*vulns[0].Affects) != 1 {
		t.Errorf("got %d affects, want 1 (duplicate refs should be deduplicated)", len(*vulns[0].Affects))
	}
}

func TestCycloneDxVexWriter_Close_Idempotent(t *testing.T) {
	var buf bytes.Buffer
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1)

	if err := h.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	firstOutput := buf.String()

	// Second close should be a no-op
	if err := h.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if buf.String() != firstOutput {
		t.Error("second Close wrote additional output")
	}
}
