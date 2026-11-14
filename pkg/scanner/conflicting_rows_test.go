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
	"reflect"
	"testing"

	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/generator"
)

// Two rows of one CVE that disagree on everything a row carries: the
// description, the severity and its source, the vendor severities, and NVD's
// v3.1 vector. None of the committed reports has such a CVE.
const conflictingRowsReport = `{"Results": [{"Target": "test", "Vulnerabilities": [
  {"VulnerabilityID": "CVE-2024-0001", "PkgID": "liba@1", "PkgName": "liba",
   "Description": "** DISPUTED ** A flaw in liba.", "Severity": "MEDIUM", "SeveritySource": "debian",
   "VendorSeverity": {"debian": 2, "nvd": 3},
   "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}},
  {"VulnerabilityID": "CVE-2024-0001", "PkgID": "libb@1", "PkgName": "libb",
   "Description": "A flaw in libb.", "Severity": "LOW", "SeveritySource": "ubuntu",
   "VendorSeverity": {"ubuntu": 1, "nvd": 4},
   "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"}}}
]}]}`

func TestConflictingRows_EveryRowsEvidenceKept(t *testing.T) {
	rows, err := (&TrivyScanner{}).Parse([]byte(conflictingRowsReport))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}

	a, b := rows[0], rows[1]
	wantA := []cvss.Vector{{Source: "nvd", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}}
	wantB := []cvss.Vector{{Source: "nvd", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"}}
	if !reflect.DeepEqual(a.CVSS, wantA) || !reflect.DeepEqual(b.CVSS, wantB) {
		t.Errorf("CVSS = %+v and %+v, want %+v and %+v", a.CVSS, b.CVSS, wantA, wantB)
	}
	if a.SeveritySource != "debian" || b.SeveritySource != "ubuntu" {
		t.Errorf("SeveritySource = %q and %q, want debian and ubuntu", a.SeveritySource, b.SeveritySource)
	}
	wantSevA := []generator.VendorSeverity{{Source: "debian", Severity: "MEDIUM"}, {Source: "nvd", Severity: "HIGH"}}
	wantSevB := []generator.VendorSeverity{{Source: "nvd", Severity: "CRITICAL"}, {Source: "ubuntu", Severity: "LOW"}}
	if !reflect.DeepEqual(a.VendorSeverities, wantSevA) || !reflect.DeepEqual(b.VendorSeverities, wantSevB) {
		t.Errorf("VendorSeverities = %+v and %+v", a.VendorSeverities, b.VendorSeverities)
	}

	// Each flag fires on its own row, and the CVE carries both.
	if a.Flags != (generator.Flags{MaintainerDisputed: true}) || b.Flags != (generator.Flags{SeverityContested: true}) {
		t.Errorf("row flags = %+v and %+v", a.Flags, b.Flags)
	}
	if got := generator.CVEFlags(rows); got != (generator.Flags{MaintainerDisputed: true, SeverityContested: true}) {
		t.Errorf("CVEFlags = %+v, want both flags", got)
	}

	// Applicability reads both NVD vectors: I is high on the second row only.
	got := generator.CVEApplicability(rows)
	if want := [3]bool{true, false, true}; got.Floored != want || len(got.Missing) != 0 {
		t.Errorf("CVEApplicability = %+v, want floored %v and nothing missing", got, want)
	}
}
