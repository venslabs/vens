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
	"reflect"
	"testing"

	"github.com/venslabs/vens/pkg/cvss"
)

func TestCVEApplicability_ReadsEveryRow(t *testing.T) {
	nvdA := cvss.Vector{Source: "nvd", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}
	// Same source and version as nvdA, another vector: keyed by source or by
	// version, one of the two would be lost.
	nvdB := cvss.Vector{Source: "nvd", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"}
	rows := []Vulnerability{
		{VulnID: "CVE-2024-0001", PkgName: "a", CVSS: []cvss.Vector{nvdA}},
		{VulnID: "CVE-2024-0001", PkgName: "b", CVSS: []cvss.Vector{nvdB}},
		{VulnID: "CVE-2024-0001", PkgName: "c", CVSS: []cvss.Vector{nvdA}},
	}
	got := CVEApplicability(rows)
	if want := [3]bool{true, false, true}; got.Floored != want {
		t.Errorf("Floored = %v, want %v: I is L on the second row", got.Floored, want)
	}
	if len(got.Missing) != 0 {
		t.Errorf("Missing = %v, want none", got.Missing)
	}
}

func TestCVEApplicability_NoVectorOnAnyRow(t *testing.T) {
	got := CVEApplicability([]Vulnerability{{VulnID: "CVE-2024-0002"}, {VulnID: "CVE-2024-0002"}})
	want := cvss.Applicability{Missing: []cvss.Missing{{Cause: cvss.NoVector}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("CVEApplicability = %+v, want %+v", got, want)
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

// A row without a vector does not stop another row's vectors from flooring:
// Applicability reads the CVE's vectors, whichever rows carry them.
func TestCVEApplicability_RowWithoutVector(t *testing.T) {
	v := cvss.Vector{Source: "nvd", Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:N"}
	got := CVEApplicability([]Vulnerability{{VulnID: "CVE-2024-0003"}, {VulnID: "CVE-2024-0003", CVSS: []cvss.Vector{v}}})
	if want := [3]bool{true, true, true}; got.Floored != want || len(got.Missing) != 0 {
		t.Errorf("CVEApplicability = %+v, want every axis floored and nothing missing", got)
	}
}
