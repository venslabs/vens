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
	"reflect"
	"testing"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/generator"
)

func parseTrivy(t *testing.T, vulns ...trivytypes.DetectedVulnerability) []generator.Vulnerability {
	t.Helper()
	data, err := json.Marshal(trivytypes.Report{Results: []trivytypes.Result{{Target: "test", Vulnerabilities: vulns}}})
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	rows, err := (&TrivyScanner{}).Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return rows
}

func parseGrype(t *testing.T, report string) []generator.Vulnerability {
	t.Helper()
	rows, err := (&GrypeScanner{}).Parse([]byte(report))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return rows
}

func TestTrivyScanner_Parse_KeepsEveryVectorAndSeverity(t *testing.T) {
	rows := parseTrivy(t, trivytypes.DetectedVulnerability{
		VulnerabilityID: "CVE-2024-0001",
		PkgID:           "a@1",
		PkgName:         "a",
		SeveritySource:  "debian",
		Vulnerability: dbtypes.Vulnerability{
			VendorSeverity: dbtypes.VendorSeverity{
				"redhat": dbtypes.SeverityMedium, "nvd": dbtypes.SeverityHigh,
				"debian": dbtypes.SeverityLow, "ghsa": dbtypes.SeverityUnknown,
			},
			CVSS: dbtypes.VendorCVSS{
				"redhat": {V3Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", V3Score: 3.7},
				"nvd": {
					V2Vector:  "AV:N/AC:M/Au:N/C:P/I:N/A:N",
					V3Vector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
					V40Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
				},
			},
		},
	})
	wantCVSS := []cvss.Vector{
		{Source: "nvd", Version: "2.0", Vector: "AV:N/AC:M/Au:N/C:P/I:N/A:N"},
		{Source: "nvd", Version: "3.0", Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"},
		{Source: "nvd", Version: "4.0", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
		{Source: "redhat", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"},
	}
	wantSeverities := []generator.VendorSeverity{
		{Source: "debian", Severity: "LOW"}, {Source: "ghsa", Severity: "UNKNOWN"},
		{Source: "nvd", Severity: "HIGH"}, {Source: "redhat", Severity: "MEDIUM"},
	}
	if !reflect.DeepEqual(rows[0].CVSS, wantCVSS) {
		t.Errorf("CVSS = %+v\nwant   %+v", rows[0].CVSS, wantCVSS)
	}
	if rows[0].SeveritySource != "debian" {
		t.Errorf("SeveritySource = %q, want debian", rows[0].SeveritySource)
	}
	if !reflect.DeepEqual(rows[0].VendorSeverities, wantSeverities) {
		t.Errorf("VendorSeverities = %+v\nwant               %+v", rows[0].VendorSeverities, wantSeverities)
	}
}

func TestTrivyScanner_Parse_EvidenceEdges(t *testing.T) {
	rows := parseTrivy(t,
		trivytypes.DetectedVulnerability{VulnerabilityID: "CVE-2024-0002", PkgID: "b@1", PkgName: "b"},
		trivytypes.DetectedVulnerability{
			VulnerabilityID: "CVE-2024-0003", PkgID: "c@1", PkgName: "c",
			Vulnerability: dbtypes.Vulnerability{
				// A severity past CRITICAL and a v3 vector without its CVSS:
				// prefix are kept as they are; the vector then does not parse.
				VendorSeverity: dbtypes.VendorSeverity{"nvd": 7},
				CVSS:           dbtypes.VendorCVSS{"nvd": {V3Vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}},
			},
		},
	)
	if rows[0].CVSS != nil || rows[0].VendorSeverities != nil || rows[0].SeveritySource != "" {
		t.Errorf("a row with no evidence: CVSS %v, VendorSeverities %v, SeveritySource %q; want none",
			rows[0].CVSS, rows[0].VendorSeverities, rows[0].SeveritySource)
	}
	wantCVSS := []cvss.Vector{{Source: "nvd", Version: "", Vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}}
	if !reflect.DeepEqual(rows[1].CVSS, wantCVSS) {
		t.Errorf("CVSS = %+v, want %+v", rows[1].CVSS, wantCVSS)
	}
	wantSeverities := []generator.VendorSeverity{{Source: "nvd", Severity: "7"}}
	if !reflect.DeepEqual(rows[1].VendorSeverities, wantSeverities) {
		t.Errorf("VendorSeverities = %+v, want %+v", rows[1].VendorSeverities, wantSeverities)
	}
}

const grypeEvidenceReport = `{"matches": [{
  "vulnerability": {
    "id": "CVE-2024-0001", "namespace": "debian:distro:debian:13", "severity": "Negligible",
    "cvss": [{"source": "cna@python.org", "type": "Secondary", "version": "4.0",
      "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"}]
  },
  "relatedVulnerabilities": [
    {"id": "GHSA-aaaa-bbbb-cccc", "namespace": "github:language:python", "severity": "Medium",
     "cvss": [{"source": "cna@python.org", "type": "Secondary", "version": "4.0",
       "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"}]},
    {"id": "CVE-2024-0001", "namespace": "nvd:cpe", "severity": "High",
     "cvss": [
       {"source": "nvd@nist.gov", "type": "Primary", "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
       {"source": "nvd@nist.gov", "type": "Primary", "version": "2.0", "vector": "AV:N/AC:L/Au:N/C:P/I:N/A:N"}
     ]}
  ],
  "artifact": {"id": "p1", "name": "a", "version": "1"}
}, {
  "vulnerability": {"id": "CVE-2024-0002", "namespace": "nvd:cpe", "severity": "Unknown"},
  "relatedVulnerabilities": [],
  "artifact": {"id": "p2", "name": "b", "version": "1"}
}]}`

func TestGrypeScanner_Parse_KeepsEveryVectorAndSeverity(t *testing.T) {
	rows := parseGrype(t, grypeEvidenceReport)
	// The matched record's vectors, then each related record's, each distinct
	// vector once.
	wantCVSS := []cvss.Vector{
		{Source: "cna@python.org", Version: "4.0", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"},
		{Source: "nvd@nist.gov", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
		{Source: "nvd@nist.gov", Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
	}
	wantSeverities := []generator.VendorSeverity{
		{Source: "github:language:python", Severity: "Medium"}, {Source: "nvd:cpe", Severity: "High"},
	}
	if !reflect.DeepEqual(rows[0].CVSS, wantCVSS) {
		t.Errorf("CVSS = %+v\nwant   %+v", rows[0].CVSS, wantCVSS)
	}
	if rows[0].SeveritySource != "debian:distro:debian:13" {
		t.Errorf("SeveritySource = %q, want the matched namespace", rows[0].SeveritySource)
	}
	if !reflect.DeepEqual(rows[0].VendorSeverities, wantSeverities) {
		t.Errorf("VendorSeverities = %+v\nwant               %+v", rows[0].VendorSeverities, wantSeverities)
	}
	if rows[1].CVSS != nil || rows[1].VendorSeverities != nil || rows[1].SeveritySource != "nvd:cpe" {
		t.Errorf("a match with no vector and no related record: CVSS %v, VendorSeverities %v, SeveritySource %q",
			rows[1].CVSS, rows[1].VendorSeverities, rows[1].SeveritySource)
	}
}
