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

package generator

import (
	"testing"

	"github.com/venslabs/vens/pkg/cvss"
)

func TestCVEImpact_ReadsEveryRow(t *testing.T) {
	nvdA := cvss.Vector{Source: "nvd", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}
	// Same source and version as nvdA, another vector: keyed by source or by
	// version, one of the two would be lost.
	nvdB := cvss.Vector{Source: "nvd", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"}
	rows := []Vulnerability{
		{VulnID: "CVE-2024-0001", PkgName: "a", CVSS: []cvss.Vector{nvdA}},
		{VulnID: "CVE-2024-0001", PkgName: "b", CVSS: []cvss.Vector{nvdB}},
		{VulnID: "CVE-2024-0001", PkgName: "c", CVSS: []cvss.Vector{nvdA}},
	}
	got := CVEImpact(rows)
	if want := [3]string{"N", "L", "N"}; got.Values != want || got.Usable != 2 {
		t.Errorf("CVEImpact = %+v, want %v from 2 vectors: I is L on the second row", got, want)
	}
}

// A row without a vector does not stop another row's: the impact reads the
// CVE's vectors, whichever rows carry them, and no vector on any row leaves
// it vectorless.
func TestCVEImpact_RowsWithoutVectors(t *testing.T) {
	if got := CVEImpact([]Vulnerability{{VulnID: "CVE-2024-0002"}, {VulnID: "CVE-2024-0002"}}); !got.Vectorless() {
		t.Errorf("no vector on any row: %+v, want it vectorless", got)
	}
	v := cvss.Vector{Source: "nvd", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
	got := CVEImpact([]Vulnerability{{VulnID: "CVE-2024-0003"}, {VulnID: "CVE-2024-0003", CVSS: []cvss.Vector{v}}})
	if want := [3]string{"H", "N", "N"}; got.Values != want {
		t.Errorf("CVEImpact = %+v, want %v", got, want)
	}
}

func TestCVEFlags(t *testing.T) {
	disputed := Flags{MaintainerDisputed: true}
	contested := Flags{SeverityContested: true}
	unavailable := Flags{SeverityContestedUnavailable: true}
	tests := []struct {
		name    string
		rows    []Flags
		want    Flags
		flagged bool
	}{
		{"no flag", []Flags{{}, {}}, Flags{}, false},
		{"disputed on one row", []Flags{{}, disputed}, disputed, true},
		{"contested on one row", []Flags{contested, {}}, contested, true},
		{"each flag from its own row", []Flags{disputed, contested}, Flags{MaintainerDisputed: true, SeverityContested: true}, true},
		{"unavailable on every row", []Flags{unavailable, unavailable}, unavailable, false},
		{"unavailable on one row only", []Flags{unavailable, {}}, Flags{}, false},
		{"disputed where the check is unavailable", []Flags{{MaintainerDisputed: true, SeverityContestedUnavailable: true}},
			Flags{MaintainerDisputed: true, SeverityContestedUnavailable: true}, true},
		{"no row", nil, Flags{}, false},
	}
	for _, tt := range tests {
		rows := make([]Vulnerability, len(tt.rows))
		for i, f := range tt.rows {
			rows[i] = Vulnerability{VulnID: "CVE-2024-0001", Flags: f}
		}
		got := CVEFlags(rows)
		if got != tt.want || got.Flagged() != tt.flagged {
			t.Errorf("%s: CVEFlags = %+v (flagged %v), want %+v (flagged %v)", tt.name, got, got.Flagged(), tt.want, tt.flagged)
		}
	}
}
