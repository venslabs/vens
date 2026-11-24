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
	"slices"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/venslabs/vens/pkg/owasp"
)

func TestCycloneDxVexWriter_Close_SerialNumber(t *testing.T) {
	var buf bytes.Buffer
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1, "", cyclonedx.SpecVersion1_7)

	score := 42.0
	err := h.HandleVulnRatings([]VulnRating{
		{
			VulnID:           "CVE-2024-1234",
			BOMRef:           "pkg:npm/foo@1.0.0",
			ImpactProvenance: ImpactFromCVSSv3,
			ImpactBasis:      owasp.BasisTechnical,
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
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 3, "", cyclonedx.SpecVersion1_7)

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
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1, "", cyclonedx.SpecVersion1_7)

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
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1, "", cyclonedx.SpecVersion1_7)

	score := 42.0
	err := h.HandleVulnRatings([]VulnRating{
		{
			VulnID:           "CVE-2024-1234",
			BOMRef:           "pkg:npm/foo@1.0.0",
			ImpactProvenance: ImpactFromCVSSv3,
			ImpactBasis:      owasp.BasisTechnical,
			Rating: cyclonedx.VulnerabilityRating{
				Method:   cyclonedx.ScoringMethodOWASP,
				Score:    &score,
				Severity: cyclonedx.SeverityHigh,
			},
			Source: &cyclonedx.Source{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
		},
		{
			VulnID:           "GHSA-abcd-efgh-ijkl",
			BOMRef:           "pkg:npm/bar@2.0.0",
			ImpactProvenance: ImpactFromCVSSv3,
			ImpactBasis:      owasp.BasisTechnical,
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
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1, "", cyclonedx.SpecVersion1_7)

	score := 42.0
	err := h.HandleVulnRatings([]VulnRating{
		{
			VulnID:           "CVE-2024-1234",
			BOMRef:           "pkg:npm/foo@1.0.0",
			ImpactProvenance: ImpactFromCVSSv3,
			ImpactBasis:      owasp.BasisTechnical,
			Rating: cyclonedx.VulnerabilityRating{
				Method:   cyclonedx.ScoringMethodOWASP,
				Score:    &score,
				Severity: cyclonedx.SeverityHigh,
			},
			Source: &cyclonedx.Source{Name: "NVD", URL: "https://nvd.nist.gov"},
		},
		{
			VulnID:           "CVE-2024-1234",
			BOMRef:           "pkg:npm/bar@2.0.0",
			ImpactProvenance: ImpactFromCVSSv3,
			ImpactBasis:      owasp.BasisTechnical,
			Rating: cyclonedx.VulnerabilityRating{
				Method:   cyclonedx.ScoringMethodOWASP,
				Score:    &score,
				Severity: cyclonedx.SeverityHigh,
			},
			Source: &cyclonedx.Source{Name: "NVD", URL: "https://nvd.nist.gov"},
		},
		{
			VulnID:           "CVE-2024-5678",
			BOMRef:           "pkg:npm/baz@3.0.0",
			ImpactProvenance: ImpactFromCVSSv3,
			ImpactBasis:      owasp.BasisTechnical,
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
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1, "", cyclonedx.SpecVersion1_7)

	score := 42.0
	err := h.HandleVulnRatings([]VulnRating{
		{
			VulnID:           "CVE-2024-1234",
			BOMRef:           "pkg:npm/foo@1.0.0",
			ImpactProvenance: ImpactFromCVSSv3,
			ImpactBasis:      owasp.BasisTechnical,
			Rating: cyclonedx.VulnerabilityRating{
				Method:   cyclonedx.ScoringMethodOWASP,
				Score:    &score,
				Severity: cyclonedx.SeverityHigh,
			},
			Source: &cyclonedx.Source{Name: "NVD", URL: "https://nvd.nist.gov"},
		},
		{
			VulnID:           "CVE-2024-1234",
			BOMRef:           "pkg:npm/foo@1.0.0",
			ImpactProvenance: ImpactFromCVSSv3,
			ImpactBasis:      owasp.BasisTechnical,
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
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1, "", cyclonedx.SpecVersion1_7)

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

func TestParseSpecVersion(t *testing.T) {
	tests := []struct {
		in      string
		want    cyclonedx.SpecVersion
		wantErr bool
	}{
		{in: "1.6", want: cyclonedx.SpecVersion1_6},
		{in: "1.7", want: cyclonedx.SpecVersion1_7},
		{in: "1.5", wantErr: true},
		{in: "1.8", wantErr: true},
		{in: "", wantErr: true},
		{in: "v1.7", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseSpecVersion(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseSpecVersion(%q) = %v, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSpecVersion(%q): unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseSpecVersion(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestCycloneDxVexWriter_Close_SpecVersion(t *testing.T) {
	cases := []struct {
		name        string
		specVersion cyclonedx.SpecVersion
		want        string
	}{
		{name: "1.6", specVersion: cyclonedx.SpecVersion1_6, want: "1.6"},
		{name: "1.7", specVersion: cyclonedx.SpecVersion1_7, want: "1.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1, "", tc.specVersion)

			score := 42.0
			const vector = "SL:7/M:7/O:7/S:7/ED:6/EE:6/A:6/ID:3/LC:7/LI:7/LAV:7/LAC:7/FD:7/RD:7/NC:7/PV:7"
			if err := h.HandleVulnRatings([]VulnRating{
				{
					VulnID:           "CVE-2024-1234",
					BOMRef:           "pkg:npm/foo@1.0.0",
					ImpactProvenance: ImpactFromCVSSv3,
					ImpactBasis:      owasp.BasisTechnical,
					Rating: cyclonedx.VulnerabilityRating{
						Method:   cyclonedx.ScoringMethodOWASP,
						Score:    &score,
						Severity: cyclonedx.SeverityHigh,
						Vector:   vector,
					},
					Source: &cyclonedx.Source{Name: "NVD"},
				},
			}); err != nil {
				t.Fatalf("HandleVulnRatings: %v", err)
			}

			if err := h.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			// specVersion is a top-level field of the encoded BOM.
			var doc struct {
				SpecVersion string `json:"specVersion"`
			}
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatalf("unmarshal BOM: %v", err)
			}
			if doc.SpecVersion != tc.want {
				t.Errorf("specVersion = %q, want %q", doc.SpecVersion, tc.want)
			}

			// Decode the emitted BOM back and check the OWASP rating survived
			// the encode at this spec version.
			bom := new(cyclonedx.BOM)
			if err := cyclonedx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cyclonedx.BOMFileFormatJSON).Decode(bom); err != nil {
				t.Fatalf("decode BOM: %v", err)
			}
			if bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 1 {
				t.Fatalf("decoded BOM has %v vulnerabilities, want 1", bom.Vulnerabilities)
			}
			ratings := (*bom.Vulnerabilities)[0].Ratings
			if ratings == nil || len(*ratings) != 1 {
				t.Fatalf("decoded vulnerability has %v ratings, want 1", ratings)
			}
			r := (*ratings)[0]
			if r.Method != cyclonedx.ScoringMethodOWASP {
				t.Errorf("rating method = %q, want %q", r.Method, cyclonedx.ScoringMethodOWASP)
			}
			if r.Score == nil {
				t.Error("rating score is nil, want non-nil")
			}
			if r.Vector != vector {
				t.Errorf("rating vector = %q, want %q", r.Vector, vector)
			}
		})
	}
}

// Score 0 is a valid OWASP rating (info). Consumers that read ratings[].score
// must see 0, not a missing key. Regression for #306.
func TestCycloneDxVexWriter_Close_KeepsZeroOWASPScore(t *testing.T) {
	for _, spec := range []cyclonedx.SpecVersion{cyclonedx.SpecVersion1_6, cyclonedx.SpecVersion1_7} {
		t.Run(spec.String(), func(t *testing.T) {
			var buf bytes.Buffer
			h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1, "", spec)

			score := 0.0
			const vector = "SL:1/M:1/O:1/S:1/ED:0/EE:0/A:0/ID:9/LC:0/LI:0/LAV:0/LAC:0/FD:0/RD:0/NC:0/PV:0"
			if err := h.HandleVulnRatings([]VulnRating{
				{
					VulnID:           "CVE-2026-8376",
					BOMRef:           "pkg:deb/debian/perl-base@5.36.0",
					ImpactProvenance: ImpactFromCVSSv3,
					ImpactBasis:      owasp.BasisTechnical,
					Rating: cyclonedx.VulnerabilityRating{
						Method:   cyclonedx.ScoringMethodOWASP,
						Score:    &score,
						Severity: cyclonedx.SeverityInfo,
						Vector:   vector,
					},
					Source: &cyclonedx.Source{Name: "NVD"},
				},
			}); err != nil {
				t.Fatalf("HandleVulnRatings: %v", err)
			}
			if err := h.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			raw := buf.String()
			if !strings.Contains(raw, `"score"`) {
				t.Fatalf("encoded VEX dropped the score key for a 0.0 rating:\n%s", raw)
			}

			var decoded struct {
				Vulnerabilities []struct {
					Ratings []struct {
						Method   string   `json:"method"`
						Score    *float64 `json:"score"`
						Severity string   `json:"severity"`
						Vector   string   `json:"vector"`
					} `json:"ratings"`
				} `json:"vulnerabilities"`
			}
			if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(decoded.Vulnerabilities) != 1 || len(decoded.Vulnerabilities[0].Ratings) != 1 {
				t.Fatalf("got %+v, want 1 vuln with 1 rating", decoded)
			}
			r := decoded.Vulnerabilities[0].Ratings[0]
			if r.Score == nil {
				t.Fatal("ratings[0].score is null/missing, want 0")
			}
			if *r.Score != 0 {
				t.Errorf("ratings[0].score = %v, want 0", *r.Score)
			}
			if r.Method != "OWASP" {
				t.Errorf("method = %q, want OWASP", r.Method)
			}
			if r.Vector != vector {
				t.Errorf("vector = %q, want %q", r.Vector, vector)
			}
		})
	}
}

// #272: a scored rating with no component fails the run instead of being
// warned about and dropped, so a gate cannot pass on a VEX short of a CVE.
// Nothing is written: Close returns before encoding.
func TestCycloneDxVexWriter_Close_FailsOnUnreferencedVuln(t *testing.T) {
	var buf bytes.Buffer
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1, "", cyclonedx.SpecVersion1_7)

	score := 42.0
	rating := cyclonedx.VulnerabilityRating{
		Method:   cyclonedx.ScoringMethodOWASP,
		Score:    &score,
		Severity: cyclonedx.SeverityHigh,
	}
	if err := h.HandleVulnRatings([]VulnRating{
		{VulnID: "CVE-1", BOMRef: "pkg:npm/foo@1.0.0", Rating: rating, ImpactProvenance: ImpactFromCVSSv3, ImpactBasis: owasp.BasisTechnical},
		{VulnID: "CVE-2", BOMRef: "", Rating: rating, ImpactProvenance: ImpactFromCVSSv3, ImpactBasis: owasp.BasisTechnical},
		{VulnID: "CVE-3", BOMRef: "", Rating: rating, ImpactProvenance: ImpactFromCVSSv3, ImpactBasis: owasp.BasisTechnical},
	}); err != nil {
		t.Fatalf("HandleVulnRatings: %v", err)
	}

	err := h.Close()
	if err == nil {
		t.Fatal("Close: expected an error for vulnerabilities without BOMRef, got nil")
	}
	if want := "cannot emit VEX: 2 vulnerabilities with no component (empty BOMRef): CVE-2, CVE-3"; err.Error() != want {
		t.Errorf("Close() = %v, want %q", err, want)
	}
	if buf.Len() != 0 {
		t.Errorf("no VEX should be written when Close fails, got %d bytes", buf.Len())
	}
}

func TestCycloneDxVexWriter_Close_DeterministicVulnerabilityOrder(t *testing.T) {
	score := 42.0
	rating := cyclonedx.VulnerabilityRating{
		Method:   cyclonedx.ScoringMethodOWASP,
		Score:    &score,
		Severity: cyclonedx.SeverityHigh,
	}
	ratings := []VulnRating{
		{VulnID: "CVE-2024-9999", BOMRef: "pkg:npm/zebra@1.0.0", Rating: rating, ImpactProvenance: ImpactFromCVSSv3, ImpactBasis: owasp.BasisTechnical},
		{VulnID: "CVE-2024-0001", BOMRef: "pkg:npm/alpha@1.0.0", Rating: rating, ImpactProvenance: ImpactFromCVSSv3, ImpactBasis: owasp.BasisTechnical},
		{VulnID: "CVE-2024-1234", BOMRef: "pkg:npm/foo@1.0.0", Rating: rating, ImpactProvenance: ImpactFromCVSSv3, ImpactBasis: owasp.BasisTechnical},
		{VulnID: "CVE-2024-1234", BOMRef: "pkg:npm/bar@2.0.0", Rating: rating, ImpactProvenance: ImpactFromCVSSv3, ImpactBasis: owasp.BasisTechnical},
		{VulnID: "CVE-2024-1234", BOMRef: "pkg:npm/baz@3.0.0", Rating: rating, ImpactProvenance: ImpactFromCVSSv3, ImpactBasis: owasp.BasisTechnical},
		{VulnID: "CVE-2024-5678", BOMRef: "pkg:npm/qux@4.0.0", Rating: rating, ImpactProvenance: ImpactFromCVSSv3, ImpactBasis: owasp.BasisTechnical},
	}

	encode := func(rs []VulnRating) *cyclonedx.BOM {
		var buf bytes.Buffer
		h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1, "", cyclonedx.SpecVersion1_7)
		if err := h.HandleVulnRatings(rs); err != nil {
			t.Fatalf("HandleVulnRatings: %v", err)
		}
		if err := h.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		var bom cyclonedx.BOM
		if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
			t.Fatalf("unmarshal BOM: %v", err)
		}
		return &bom
	}

	// Same ratings fed in different orders must produce the same
	// vulnerabilities[] order: decoded and compared by ID, so the
	// per-document metadata.timestamp can't flake the assertion.
	reversed := make([]VulnRating, len(ratings))
	for i, r := range ratings {
		reversed[len(ratings)-1-i] = r
	}

	// The vulnerabilities[] array must be sorted by ID in both runs.
	want := []string{"CVE-2024-0001", "CVE-2024-1234", "CVE-2024-5678", "CVE-2024-9999"}
	for _, rs := range [][]VulnRating{ratings, reversed} {
		bom := encode(rs)
		if bom.Vulnerabilities == nil {
			t.Fatal("expected vulnerabilities in the VEX")
		}
		got := make([]string, 0, len(*bom.Vulnerabilities))
		for _, v := range *bom.Vulnerabilities {
			got = append(got, v.ID)
		}
		if !slices.Equal(got, want) {
			t.Errorf("vulnerabilities[] order = %v, want sorted %v", got, want)
		}
	}
}

// Each vulnerability carries exactly two properties, vens:impact-provenance
// then vens:impact-basis, its rows' values, whatever the number of rows
// merged into it.
func TestCycloneDxVexWriter_Close_ImpactMarkers(t *testing.T) {
	score := 42.0
	rating := cyclonedx.VulnerabilityRating{Method: cyclonedx.ScoringMethodOWASP, Score: &score, Severity: cyclonedx.SeverityHigh}
	var buf bytes.Buffer
	h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1, "", cyclonedx.SpecVersion1_6)
	if err := h.HandleVulnRatings([]VulnRating{
		{VulnID: "CVE-1", BOMRef: "pkg:npm/a@1", Rating: rating, ImpactProvenance: ImpactFromCVSSv3, ImpactBasis: owasp.BasisTechnical},
		{VulnID: "CVE-1", BOMRef: "pkg:npm/b@1", Rating: rating, ImpactProvenance: ImpactFromCVSSv3, ImpactBasis: owasp.BasisTechnical},
		{VulnID: "CVE-2", BOMRef: "pkg:npm/a@1", Rating: rating, ImpactProvenance: ImpactFromFallback, ImpactBasis: owasp.BasisBusiness},
		{VulnID: "CVE-2", BOMRef: "pkg:npm/c@1", Rating: rating, ImpactProvenance: ImpactFromFallback, ImpactBasis: owasp.BasisBusiness},
	}); err != nil {
		t.Fatalf("HandleVulnRatings: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	type property struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	var doc struct {
		Vulnerabilities []struct {
			ID         string     `json:"id"`
			Properties []property `json:"properties"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := map[string][]property{
		"CVE-1": {{"vens:impact-provenance", "cvss-v3"}, {"vens:impact-basis", "technical"}},
		"CVE-2": {{"vens:impact-provenance", "missing-cvss-v3-fallback"}, {"vens:impact-basis", "business"}},
	}
	if len(doc.Vulnerabilities) != len(want) {
		t.Fatalf("got %d vulnerabilities, want %d", len(doc.Vulnerabilities), len(want))
	}
	for _, v := range doc.Vulnerabilities {
		if !slices.Equal(v.Properties, want[v.ID]) {
			t.Errorf("%s: properties %+v, want %+v", v.ID, v.Properties, want[v.ID])
		}
	}
}

// A rating without one of the two values of a marker, or a CVE whose rows
// disagree on it, fails the run: no VEX is written short of either marker.
func TestCycloneDxVexWriter_Close_FailsOnMissingOrConflictingMarkers(t *testing.T) {
	score := 42.0
	rating := cyclonedx.VulnerabilityRating{Method: cyclonedx.ScoringMethodOWASP, Score: &score, Severity: cyclonedx.SeverityHigh}
	marked := func(id, ref, provenance string, basis owasp.Basis) VulnRating {
		return VulnRating{VulnID: id, BOMRef: ref, Rating: rating, ImpactProvenance: provenance, ImpactBasis: basis}
	}
	for name, c := range map[string]struct {
		ratings []VulnRating
		want    string
	}{
		"provenance missing": {[]VulnRating{
			marked("CVE-1", "pkg:npm/a@1", ImpactFromCVSSv3, owasp.BasisTechnical),
			marked("CVE-2", "pkg:npm/a@1", "", owasp.BasisTechnical),
		}, `cannot emit VEX: CVE-2: impact provenance "" is not cvss-v3 or missing-cvss-v3-fallback`},
		"provenance off the list": {[]VulnRating{
			marked("CVE-1", "pkg:npm/a@1", "cvss-v4", owasp.BasisTechnical),
		}, `cannot emit VEX: CVE-1: impact provenance "cvss-v4" is not cvss-v3 or missing-cvss-v3-fallback`},
		"provenance conflicting": {[]VulnRating{
			marked("CVE-1", "pkg:npm/a@1", ImpactFromCVSSv3, owasp.BasisTechnical),
			marked("CVE-1", "pkg:npm/b@1", ImpactFromFallback, owasp.BasisTechnical),
		}, "cannot emit VEX: CVE-1: rows rated with impact provenance cvss-v3 and missing-cvss-v3-fallback"},
		"basis missing": {[]VulnRating{
			marked("CVE-1", "pkg:npm/a@1", ImpactFromCVSSv3, owasp.BasisBusiness),
			marked("CVE-2", "pkg:npm/a@1", ImpactFromCVSSv3, ""),
		}, `cannot emit VEX: CVE-2: impact basis "" is not technical or business`},
		"basis off the list": {[]VulnRating{
			marked("CVE-1", "pkg:npm/a@1", ImpactFromCVSSv3, "max"),
		}, `cannot emit VEX: CVE-1: impact basis "max" is not technical or business`},
		"basis conflicting": {[]VulnRating{
			marked("CVE-1", "pkg:npm/a@1", ImpactFromCVSSv3, owasp.BasisBusiness),
			marked("CVE-1", "pkg:npm/b@1", ImpactFromCVSSv3, owasp.BasisTechnical),
		}, "cannot emit VEX: CVE-1: rows rated with impact basis business and technical"},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1, "", cyclonedx.SpecVersion1_6)
			if err := h.HandleVulnRatings(c.ratings); err != nil {
				t.Fatalf("HandleVulnRatings: %v", err)
			}
			if err := h.Close(); err == nil || err.Error() != c.want {
				t.Errorf("Close() = %v, want %q", err, c.want)
			}
			if buf.Len() != 0 {
				t.Errorf("no VEX should be written when Close fails, got %d bytes", buf.Len())
			}
		})
	}
}

// The VEX's metadata carries exactly one property, vens:rating-policy 2,
// whatever the spec version and with no vulnerability too.
func TestCycloneDxVexWriter_Close_RatingPolicy(t *testing.T) {
	score := 42.0
	rating := cyclonedx.VulnerabilityRating{Method: cyclonedx.ScoringMethodOWASP, Score: &score, Severity: cyclonedx.SeverityHigh}
	rated := []VulnRating{
		{VulnID: "CVE-1", BOMRef: "pkg:npm/a@1", Rating: rating, ImpactProvenance: ImpactFromCVSSv3, ImpactBasis: owasp.BasisTechnical},
		{VulnID: "CVE-2", BOMRef: "pkg:npm/a@1", Rating: rating, ImpactProvenance: ImpactFromFallback, ImpactBasis: owasp.BasisBusiness},
	}
	type property struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	for _, spec := range SupportedSpecVersions {
		version, err := ParseSpecVersion(spec)
		if err != nil {
			t.Fatal(err)
		}
		for _, ratings := range [][]VulnRating{nil, rated} {
			var buf bytes.Buffer
			h := NewCycloneDxVexOutputHandler(&buf, "test-uuid", 1, "", version)
			if err := h.HandleVulnRatings(ratings); err != nil {
				t.Fatalf("HandleVulnRatings: %v", err)
			}
			if err := h.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			var doc struct {
				Metadata struct {
					Properties []property `json:"properties"`
				} `json:"metadata"`
			}
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if want := []property{{"vens:rating-policy", "2"}}; !slices.Equal(doc.Metadata.Properties, want) {
				t.Errorf("%s, %d ratings: metadata properties %+v, want %+v", spec, len(ratings), doc.Metadata.Properties, want)
			}
		}
	}
}

// Metadata that does not carry the rating policy once, at 2, is refused like
// a vulnerability short of a marker. Close always writes it, so its check is
// reached here through markerError.
func TestMarkerError_RatingPolicy(t *testing.T) {
	ratings := []VulnRating{{VulnID: "CVE-1", BOMRef: "pkg:npm/a@1", ImpactProvenance: ImpactFromCVSSv3, ImpactBasis: owasp.BasisTechnical}}
	carrying := func(properties ...cyclonedx.Property) *cyclonedx.Metadata {
		return &cyclonedx.Metadata{Properties: &properties}
	}
	policy := func(value string) cyclonedx.Property {
		return cyclonedx.Property{Name: RatingPolicyProperty, Value: value}
	}
	for name, c := range map[string]struct {
		metadata *cyclonedx.Metadata
		ratings  []VulnRating
		want     string
	}{
		"no metadata":   {nil, ratings, `cannot emit VEX: rating policy "" is not 2`},
		"no properties": {&cyclonedx.Metadata{}, ratings, `cannot emit VEX: rating policy "" is not 2`},
		"missing":       {carrying(cyclonedx.Property{Name: "vens:policy", Value: "2"}), ratings, `cannot emit VEX: rating policy "" is not 2`},
		"empty":         {carrying(policy("")), ratings, `cannot emit VEX: rating policy "" is not 2`},
		"wrong":         {carrying(policy("1")), ratings, `cannot emit VEX: rating policy "1" is not 2`},
		"twice":         {carrying(policy("2"), policy("2")), ratings, `cannot emit VEX: rating policy "2, 2" is not 2`},
		"with a basis missing": {carrying(policy("3")), []VulnRating{{VulnID: "CVE-1", ImpactProvenance: ImpactFromCVSSv3}},
			`cannot emit VEX: CVE-1: impact basis "" is not technical or business; rating policy "3" is not 2`},
	} {
		t.Run(name, func(t *testing.T) {
			if err := markerError("cannot emit VEX", c.metadata, c.ratings); err == nil || err.Error() != c.want {
				t.Errorf("markerError() = %v, want %q", err, c.want)
			}
		})
	}
	if err := markerError("cannot emit VEX", carrying(policy(RatingPolicy)), ratings); err != nil {
		t.Errorf("markerError() = %v, want nil", err)
	}
}
