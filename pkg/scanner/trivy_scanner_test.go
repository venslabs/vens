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
	"testing"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/package-url/packageurl-go"
)

func TestTrivyScanner_Parse_DataSource(t *testing.T) {
	report := trivytypes.Report{
		Results: []trivytypes.Result{
			{
				Target: "test",
				Vulnerabilities: []trivytypes.DetectedVulnerability{
					{
						VulnerabilityID: "CVE-2024-1234",
						PkgID:           "foo@1.0.0",
						PkgName:         "foo",
						DataSource: &dbtypes.DataSource{
							ID:   "debian-oval",
							Name: "Debian OVAL",
							URL:  "https://www.debian.org/security/oval/",
						},
					},
				},
			},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}

	scanner := &TrivyScanner{}
	vulns, err := scanner.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("got %d vulns, want 1", len(vulns))
	}

	if vulns[0].SourceName != "NVD" {
		t.Errorf("SourceName = %q, want %q", vulns[0].SourceName, "NVD")
	}
	if vulns[0].SourceURL != "https://www.debian.org/security/oval/" {
		t.Errorf("SourceURL = %q, want %q", vulns[0].SourceURL, "https://www.debian.org/security/oval/")
	}
}

func TestTrivyScanner_Parse_NilDataSource(t *testing.T) {
	report := trivytypes.Report{
		Results: []trivytypes.Result{
			{
				Target: "test",
				Vulnerabilities: []trivytypes.DetectedVulnerability{
					{
						VulnerabilityID: "CVE-2024-5678",
						PkgID:           "bar@2.0.0",
						PkgName:         "bar",
						DataSource:      nil,
					},
				},
			},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}

	scanner := &TrivyScanner{}
	vulns, err := scanner.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("got %d vulns, want 1", len(vulns))
	}

	if vulns[0].SourceName != "" {
		t.Errorf("SourceName = %q, want empty", vulns[0].SourceName)
	}
	if vulns[0].SourceURL != "" {
		t.Errorf("SourceURL = %q, want empty", vulns[0].SourceURL)
	}
}

func TestTrivyDataSourceToSourceName(t *testing.T) {
	tests := []struct {
		dataSourceID string
		vulnID       string
		want         string
	}{
		{"nvd", "CVE-2024-1234", "NVD"},
		{"NVD", "CVE-2024-1234", "NVD"},
		{"debian-oval", "CVE-2024-1234", "NVD"},
		{"debian", "CVE-2024-1234", "NVD"},
		{"ghsa", "CVE-2024-1234", "NVD"},
		{"github", "CVE-2024-1234", "NVD"},
		{"ghsa", "GHSA-xxxx-xxxx-xxxx", "GITHUB"},
		{"github", "GHSA-xxxx-xxxx-xxxx", "GITHUB"},
		{"GITHUB", "GHSA-xxxx-xxxx-xxxx", "GITHUB"},
		{"osv", "OSV-2024-1234", "OSV"},
		{"npm", "npm-123", "NPM"},
		{"ossindex", "sonatype-123", "OSSINDEX"},
		{"snyk", "SNYK-123", "SNYK"},
		{"vulndb", "VDB-123", "VULNDB"},
		{"unknown-source", "CVE-2024-5678", "NVD"},
		{"unknown-source", "GHSA-yyyy-yyyy-yyyy", "GITHUB"},
		{"unknown-source", "OTHER-123", "UNKNOWN"},
	}

	for _, tc := range tests {
		t.Run(tc.dataSourceID+"_"+tc.vulnID, func(t *testing.T) {
			got := trivyDataSourceToSourceName(tc.dataSourceID, tc.vulnID)
			if got != tc.want {
				t.Errorf("trivyDataSourceToSourceName(%q, %q) = %q, want %q", tc.dataSourceID, tc.vulnID, got, tc.want)
			}
		})
	}
}

// Several CVEs on one package means several rows with the same PURL. All of them
// must keep that PURL as their ref.
func TestTrivyScanner_Parse_SamePackageKeepsOnePURLRef(t *testing.T) {
	purl, err := packageurl.FromString("pkg:deb/debian/libssl3@3.5.6-1?arch=amd64")
	if err != nil {
		t.Fatalf("FromString: %v", err)
	}
	id := ftypes.PkgIdentifier{PURL: &purl}

	report := trivytypes.Report{
		Results: []trivytypes.Result{
			{
				Target: "img (debian 13)",
				Vulnerabilities: []trivytypes.DetectedVulnerability{
					{VulnerabilityID: "CVE-1", PkgID: "libssl3@3.5.6-1", PkgName: "libssl3", InstalledVersion: "3.5.6-1", PkgIdentifier: id},
					{VulnerabilityID: "CVE-2", PkgID: "libssl3@3.5.6-1", PkgName: "libssl3", InstalledVersion: "3.5.6-1", PkgIdentifier: id},
					{VulnerabilityID: "CVE-3", PkgID: "libssl3@3.5.6-1", PkgName: "libssl3", InstalledVersion: "3.5.6-1", PkgIdentifier: id},
				},
			},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	vulns, err := (&TrivyScanner{}).Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(vulns) != 3 {
		t.Fatalf("got %d vulnerabilities, want 3", len(vulns))
	}

	want := purl.String()
	for _, v := range vulns {
		if v.BOMRef != want {
			t.Errorf("%s: BOMRef = %q, want %q", v.VulnID, v.BOMRef, want)
		}
	}
}

// Two distinct components behind one PURL is the case the fallback exists for.
func TestTrivyScanner_Parse_SharedPURLFallsBackToPkgID(t *testing.T) {
	purl, err := packageurl.FromString("pkg:generic/shared@1.0.0")
	if err != nil {
		t.Fatalf("FromString: %v", err)
	}
	id := ftypes.PkgIdentifier{PURL: &purl}

	report := trivytypes.Report{
		Results: []trivytypes.Result{
			{
				Target: "img",
				Vulnerabilities: []trivytypes.DetectedVulnerability{
					{VulnerabilityID: "CVE-1", PkgID: "shared@1.0.0", PkgName: "shared", InstalledVersion: "1.0.0", PkgIdentifier: id},
					{VulnerabilityID: "CVE-2", PkgID: "shared-alt@1.0.0", PkgName: "shared-alt", InstalledVersion: "1.0.0", PkgIdentifier: id},
				},
			},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	vulns, err := (&TrivyScanner{}).Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, v := range vulns {
		if v.BOMRef != v.PkgID {
			t.Errorf("%s: BOMRef = %q, want the PkgID %q", v.VulnID, v.BOMRef, v.PkgID)
		}
	}
}

// Trivy leaves PkgID empty for pip. Before the fallback used name@version these
// rows came out with no ref at all and were dropped from the VEX.
func TestTrivyScanner_Parse_SharedPURLWithoutPkgIDStillGetsARef(t *testing.T) {
	purl, err := packageurl.FromString("pkg:pypi/pip@25.0.1")
	if err != nil {
		t.Fatalf("FromString: %v", err)
	}
	id := ftypes.PkgIdentifier{PURL: &purl}

	report := trivytypes.Report{
		Results: []trivytypes.Result{
			{
				Target: "Python",
				Vulnerabilities: []trivytypes.DetectedVulnerability{
					{VulnerabilityID: "CVE-1", PkgName: "pip", InstalledVersion: "25.0.1", PkgIdentifier: id},
					{VulnerabilityID: "CVE-2", PkgName: "pip-alt", InstalledVersion: "25.0.1", PkgIdentifier: id},
				},
			},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	vulns, err := (&TrivyScanner{}).Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	want := map[string]string{"CVE-1": "pip@25.0.1", "CVE-2": "pip-alt@25.0.1"}
	for _, v := range vulns {
		if v.BOMRef != want[v.VulnID] {
			t.Errorf("%s: BOMRef = %q, want %q", v.VulnID, v.BOMRef, want[v.VulnID])
		}
	}
}

func TestCalculateTrivyBOMRef_NeverEmptyWhenAnythingIdentifiesTheComponent(t *testing.T) {
	purl, err := packageurl.FromString("pkg:generic/shared@1.0.0")
	if err != nil {
		t.Fatalf("FromString: %v", err)
	}
	shared := ftypes.PkgIdentifier{PURL: &purl}
	counts := map[string]int{purl.String(): 2}

	tests := []struct {
		name string
		v    trivytypes.DetectedVulnerability
		want string
	}{
		{
			name: "no purl, no pkgID",
			v:    trivytypes.DetectedVulnerability{PkgName: "pip", InstalledVersion: "25.0.1"},
			want: "pip@25.0.1",
		},
		{
			name: "ambiguous purl, no pkgID",
			v:    trivytypes.DetectedVulnerability{PkgName: "pip", InstalledVersion: "25.0.1", PkgIdentifier: shared},
			want: "pip@25.0.1",
		},
		{
			name: "ambiguous purl and nothing else, keep the purl",
			v:    trivytypes.DetectedVulnerability{PkgIdentifier: shared},
			want: purl.String(),
		},
		{
			name: "nothing at all",
			v:    trivytypes.DetectedVulnerability{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := calculateTrivyBOMRef(tt.v, counts); got != tt.want {
				t.Errorf("calculateTrivyBOMRef() = %q, want %q", got, tt.want)
			}
		})
	}
}
