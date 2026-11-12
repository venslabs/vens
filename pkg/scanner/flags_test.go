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
	"testing"

	grypemodels "github.com/anchore/grype/grype/presenter/models"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/generator"
)

func TestMaintainerDisputed(t *testing.T) {
	tests := []struct {
		description string
		want        bool
	}{
		{"** DISPUTED ** An issue was discovered in libfoo.", true},
		{"NOTE: the vendor disputes this report.", true},
		{"The maintainer considers it a non-security bug.", true},
		{"Upstream says this is not a security issue.", true},
		{"Upstream says this is NOT A SECURITY ISSUE.", true},
		{"The maintainers see no real threat in it.", true},
		{"An undisputed overflow in the parser.", false},
		{"An indisputable overflow in the parser.", false},
		{"A nonsecurity flag set by mistake.", false},
		{"A security issue in libfoo.", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := maintainerDisputed(tt.description); got != tt.want {
			t.Errorf("maintainerDisputed(%q) = %v, want %v", tt.description, got, tt.want)
		}
	}
}

func TestTrivySeverityContested(t *testing.T) {
	nvd3 := cvss.Vector{Source: "nvd", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
	nvd2 := cvss.Vector{Source: "nvd", Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"}
	redhat3 := cvss.Vector{Source: "redhat", Version: "3.1", Vector: "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"}
	ghsa4 := cvss.Vector{Source: "ghsa", Version: "4.0", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"}
	nvdHigh := []generator.VendorSeverity{{Source: "debian", Severity: "LOW"}, {Source: "nvd", Severity: "HIGH"}}
	row := func(severity, source string, vendor []generator.VendorSeverity, vectors ...cvss.Vector) generator.Vulnerability {
		return generator.Vulnerability{Severity: severity, SeveritySource: source, VendorSeverities: vendor, CVSS: vectors}
	}
	tests := []struct {
		name string
		row  generator.Vulnerability
		want bool
	}{
		{"LOW from debian, NVD HIGH with a v3 vector", row("LOW", "debian", nvdHigh, redhat3, nvd3), true},
		{"the severity in lower case", row("low", "debian", nvdHigh, nvd3), true},
		{"no severity source", row("LOW", "", nvdHigh, nvd3), true},
		{"NVD CRITICAL", row("LOW", "debian", []generator.VendorSeverity{{Source: "nvd", Severity: "CRITICAL"}}, nvd3), true},
		{"NVD's v2 and v3, v3 the newest", row("LOW", "debian", nvdHigh, nvd2, nvd3), true},
		{"MEDIUM", row("MEDIUM", "debian", nvdHigh, nvd3), false},
		{"the severity is NVD's", row("LOW", "nvd", nvdHigh, nvd3), false},
		{"NVD MEDIUM", row("LOW", "debian", []generator.VendorSeverity{{Source: "nvd", Severity: "MEDIUM"}}, nvd3), false},
		{"no NVD severity", row("LOW", "debian", []generator.VendorSeverity{{Source: "redhat", Severity: "HIGH"}}, nvd3), false},
		{"NVD's vector a version behind", row("LOW", "debian", nvdHigh, nvd2, redhat3), false},
		{"NVD's v3 behind a v4", row("LOW", "debian", nvdHigh, nvd3, ghsa4), false},
		{"no NVD vector", row("LOW", "debian", nvdHigh, redhat3), false},
		{"no vector at all", row("LOW", "debian", nvdHigh), false},
		{"NVD's only vector of no known version", row("LOW", "debian", nvdHigh,
			cvss.Vector{Source: "nvd", Vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}), false},
	}
	for _, tt := range tests {
		if got := trivySeverityContested(tt.row); got != tt.want {
			t.Errorf("%s: trivySeverityContested = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestGrypeSeverityContested(t *testing.T) {
	nvdV3 := grypemodels.Cvss{Source: "nvd@nist.gov", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
	nvdV2 := grypemodels.Cvss{Source: "nvd@nist.gov", Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"}
	mitreV3 := grypemodels.Cvss{Source: "cve@mitre.org", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
	cnaV4 := grypemodels.Cvss{Source: "cna@python.org", Version: "4.0",
		Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"}
	record := func(namespace, severity string, scores ...grypemodels.Cvss) grypemodels.VulnerabilityMetadata {
		return grypemodels.VulnerabilityMetadata{ID: "CVE-2024-0001", Namespace: namespace, Severity: severity, Cvss: scores}
	}
	match := func(matched grypemodels.VulnerabilityMetadata, related ...grypemodels.VulnerabilityMetadata) grypemodels.Match {
		return grypemodels.Match{Vulnerability: grypemodels.Vulnerability{VulnerabilityMetadata: matched}, RelatedVulnerabilities: related}
	}
	debianLow := record("debian:distro:debian:13", "Low")
	nvdHigh := record("nvd:cpe", "High", nvdV3)
	tests := []struct {
		name                   string
		match                  grypemodels.Match
		contested, unavailable bool
	}{
		{"Low from debian, NVD High with a v3 vector", match(debianLow, nvdHigh), true, false},
		{"Negligible, read as Low", match(record("debian:distro:debian:13", "Negligible"), nvdHigh), true, false},
		{"NVD Critical", match(debianLow, record("nvd:cpe", "Critical", nvdV3)), true, false},
		{"NVD's High and its vector on two records", match(debianLow, record("nvd:cpe", "High"), record("nvd:cpe", "Medium", nvdV3)), true, false},
		{"Medium", match(record("debian:distro:debian:13", "Medium"), nvdHigh), false, false},
		{"Unknown", match(record("debian:distro:debian:13", "Unknown"), nvdHigh), false, false},
		{"the matched record is NVD's", match(record("nvd:cpe", "Low"), nvdHigh), false, false},
		{"NVD Medium", match(debianLow, record("nvd:cpe", "Medium", nvdV3)), false, false},
		{"NVD's record without a vector", match(debianLow, record("nvd:cpe", "High")), false, false},
		{"NVD's record with another source's vector", match(debianLow, record("nvd:cpe", "High", mitreV3)), false, false},
		{"NVD's vector a version behind", match(record("debian:distro:debian:13", "Low", cnaV4), record("nvd:cpe", "High", nvdV2)), false, false},
		{"NVD's vector on the matched record only", match(record("debian:distro:debian:13", "Low", nvdV3), record("nvd:cpe", "High")), false, false},
		{"NVD's only vector of no known version", match(debianLow, record("nvd:cpe", "High",
			grypemodels.Cvss{Source: "nvd@nist.gov", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"})), false, false},
		{"no related NVD record", match(debianLow, record("github:language:python", "High", nvdV3)), false, true},
		{"no related record at all", match(debianLow), false, true},
		{"an NVD match has no related NVD record", match(record("nvd:cpe", "High", nvdV3)), false, true},
	}
	for _, tt := range tests {
		contested, unavailable := grypeSeverityContested(tt.match, grypeVectors(tt.match))
		if contested != tt.contested || unavailable != tt.unavailable {
			t.Errorf("%s: grypeSeverityContested = %v, %v; want %v, %v", tt.name, contested, unavailable, tt.contested, tt.unavailable)
		}
	}
}

const trivyFlagsReport = `{"Results": [{"Target": "test", "Vulnerabilities": [
  {"VulnerabilityID": "CVE-2024-0001", "PkgID": "a@1", "PkgName": "a", "SeveritySource": "debian",
   "Description": "** DISPUTED ** A flaw in a.", "Severity": "LOW",
   "VendorSeverity": {"debian": 1, "nvd": 3},
   "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}},
  {"VulnerabilityID": "CVE-2024-0002", "PkgID": "b@1", "PkgName": "b", "SeveritySource": "nvd",
   "Description": "A flaw in b.", "Severity": "HIGH",
   "VendorSeverity": {"nvd": 3},
   "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}}
]}]}`

func TestTrivyScanner_Parse_SetsFlags(t *testing.T) {
	rows, err := (&TrivyScanner{}).Parse([]byte(trivyFlagsReport))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []generator.Flags{{MaintainerDisputed: true, SeverityContested: true}, {}}
	for i, w := range want {
		if rows[i].Flags != w {
			t.Errorf("%s: Flags = %+v, want %+v", rows[i].VulnID, rows[i].Flags, w)
		}
	}
}

const grypeFlagsReport = `{"matches": [{
  "vulnerability": {"id": "CVE-2024-0001", "namespace": "debian:distro:debian:13", "severity": "Negligible",
    "description": "NOTE: this is not a security issue."},
  "relatedVulnerabilities": [{"id": "CVE-2024-0001", "namespace": "nvd:cpe", "severity": "High",
    "cvss": [{"source": "nvd@nist.gov", "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}]}],
  "artifact": {"id": "p1", "name": "a", "version": "1"}
}, {
  "vulnerability": {"id": "CVE-2024-0002", "namespace": "nvd:cpe", "severity": "Low", "description": "A flaw in b."},
  "relatedVulnerabilities": [],
  "artifact": {"id": "p2", "name": "b", "version": "1"}
}]}`

func TestGrypeScanner_Parse_SetsFlags(t *testing.T) {
	rows := parseGrype(t, grypeFlagsReport)
	want := []generator.Flags{
		{MaintainerDisputed: true, SeverityContested: true},
		{SeverityContestedUnavailable: true},
	}
	for i, w := range want {
		if rows[i].Flags != w {
			t.Errorf("%s: Flags = %+v, want %+v", rows[i].VulnID, rows[i].Flags, w)
		}
	}
}
