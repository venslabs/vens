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
	trivytypes "github.com/aquasecurity/trivy/pkg/types"
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
						Vulnerability: dbtypes.Vulnerability{
							Severity: "HIGH",
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

	if vulns[0].SourceName != "debian-oval" {
		t.Errorf("SourceName = %q, want %q", vulns[0].SourceName, "debian-oval")
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
						Vulnerability: dbtypes.Vulnerability{
							Severity: "MEDIUM",
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

	if vulns[0].SourceName != "" {
		t.Errorf("SourceName = %q, want empty", vulns[0].SourceName)
	}
	if vulns[0].SourceURL != "" {
		t.Errorf("SourceURL = %q, want empty", vulns[0].SourceURL)
	}
}