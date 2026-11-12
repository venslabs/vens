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

package cvss

import (
	"slices"
	"testing"
)

func TestVector_Tier(t *testing.T) {
	tests := []struct {
		version string
		want    int
	}{
		{"2.0", 2},
		{"2", 2},
		{"3.0", 3},
		{"3.1", 3},
		{"4.0", 4},
		{"", 0},
		{"3", 0},
		{"4", 0},
		{"5.0", 0},
		{"v3.1", 0},
	}
	for _, tt := range tests {
		if got := (Vector{Version: tt.version}).Tier(); got != tt.want {
			t.Errorf("Tier(%q) = %d, want %d", tt.version, got, tt.want)
		}
	}
}

func TestNewest(t *testing.T) {
	v := func(version string) Vector { return Vector{Version: version} }
	tests := []struct {
		name    string
		vectors []Vector
		want    int
	}{
		{"none", nil, 0},
		{"unknown versions only", []Vector{v(""), v("5.0")}, 0},
		{"v2 and v3.0", []Vector{v("2.0"), v("3.0")}, 3},
		{"v4 first", []Vector{v("4.0"), v("2.0"), v("3.1")}, 4},
		{"unknown beside v2", []Vector{v("9.9"), v("2.0")}, 2},
	}
	for _, tt := range tests {
		if got := Newest(tt.vectors); got != tt.want {
			t.Errorf("%s: Newest = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestVector_Parse(t *testing.T) {
	tests := []struct {
		name string
		v    Vector
		want map[string]string
	}{
		{"v2 as Trivy and Grype write it", Vector{Version: "2.0", Vector: "AV:N/AC:M/Au:N/C:P/I:N/A:C"},
			map[string]string{"AV": "N", "AC": "M", "C": "P", "I": "N", "A": "C"}},
		{"v2 with temporal metrics", Vector{Version: "2", Vector: "AV:L/AC:H/Au:S/C:N/I:N/A:P/E:F/RL:OF/RC:C"},
			map[string]string{"AV": "L", "AC": "H", "C": "N", "I": "N", "A": "P"}},
		{"v3.1", Vector{Version: "3.1", Vector: "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:N"},
			map[string]string{"AV": "A", "AC": "H", "PR": "L", "UI": "R", "C": "H", "I": "L", "A": "N"}},
		{"v3.0", Vector{Version: "3.0", Vector: "CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:L"},
			map[string]string{"AV": "P", "AC": "L", "PR": "H", "UI": "N", "C": "N", "I": "H", "A": "L"}},
		{"v3.0 prefix on a 3.1 record: one tier", Vector{Version: "3.1", Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"},
			map[string]string{"AV": "N", "AC": "L", "PR": "N", "UI": "N", "C": "L", "I": "L", "A": "L"}},
		{"v3 without its prefix", Vector{Version: "3.1", Vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			map[string]string{"AV": "N", "AC": "L", "PR": "N", "UI": "N", "C": "H", "I": "H", "A": "H"}},
		{"v4.0", Vector{Version: "4.0", Vector: "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:H/VI:L/VA:N/SC:N/SI:L/SA:H/E:P"},
			map[string]string{"AV": "L", "AC": "H", "AT": "P", "PR": "L", "UI": "A", "VC": "H", "VI": "L", "VA": "N",
				"SC": "N", "SI": "L", "SA": "H"}},
		{"surrounding space", Vector{Version: "3.1", Vector: " CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N\n"},
			map[string]string{"AV": "N", "AC": "L", "PR": "N", "UI": "N", "C": "N", "I": "N", "A": "N"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := tt.v.Parse()
			if err != nil {
				t.Fatalf("Parse(%+v): %v", tt.v, err)
			}
			for _, metric := range allMetrics {
				got, ok := m.Get(metric)
				want, wantOK := tt.want[metric]
				if got != want || ok != wantOK {
					t.Errorf("Get(%s) = %q, %v; want %q, %v", metric, got, ok, want, wantOK)
				}
			}
		})
	}
}

func TestVector_ParseRefuses(t *testing.T) {
	tests := []struct {
		name string
		v    Vector
	}{
		{"no version", Vector{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}},
		{"a version vens does not read", Vector{Version: "5.0", Vector: "AV:N/C:N/I:N/A:N"}},
		{"a v4 prefix on a 3.1 record", Vector{Version: "3.1", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"}},
		{"a v3 prefix on a 2.0 record", Vector{Version: "2.0", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}},
		{"an unknown prefix", Vector{Version: "3.1", Vector: "CVSS:9.9/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}},
		{"empty", Vector{Version: "3.1"}},
		{"blank", Vector{Version: "2.0", Vector: "  "}},
		{"a prefix alone", Vector{Version: "3.1", Vector: "CVSS:3.1"}},
		{"a prefix and a slash", Vector{Version: "3.1", Vector: "CVSS:3.1/"}},
		{"an empty part", Vector{Version: "3.1", Vector: "CVSS:3.1/AV:N//AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}},
		{"a trailing slash", Vector{Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:N/"}},
		{"a part with no colon", Vector{Version: "3.1", Vector: "CVSS:3.1/AVN/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}},
		{"a metric with no value", Vector{Version: "3.1", Vector: "CVSS:3.1/AV:/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}},
		{"a value with no metric", Vector{Version: "3.1", Vector: "CVSS:3.1/:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}},
		{"a metric given twice", Vector{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/C:H"}},
	}
	for _, tt := range tests {
		if _, err := tt.v.Parse(); err == nil {
			t.Errorf("%s: Parse(%+v) succeeded, want an error", tt.name, tt.v)
		}
	}
}

// The metrics vens reads per version and their scales, as pandatix/go-cvss
// v0.6.2 validates them: 20/cvss20.go, 31/cvss31.go (3.0 shares it) and
// 40/cvss40.go. Au, S, the threat, temporal and environmental metrics are not
// read.
var wantScales = map[string]map[string][]string{
	"2.0": {
		"AV": {"L", "A", "N"}, "AC": {"H", "M", "L"},
		"C": {"N", "P", "C"}, "I": {"N", "P", "C"}, "A": {"N", "P", "C"},
	},
	"3.1": {
		"AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "PR": {"N", "L", "H"}, "UI": {"N", "R"},
		"C": {"H", "L", "N"}, "I": {"H", "L", "N"}, "A": {"H", "L", "N"},
	},
	"4.0": {
		"AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "AT": {"N", "P"}, "PR": {"H", "L", "N"}, "UI": {"N", "P", "A"},
		"VC": {"H", "L", "N"}, "VI": {"H", "L", "N"}, "VA": {"H", "L", "N"},
		"SC": {"H", "L", "N"}, "SI": {"H", "L", "N"}, "SA": {"H", "L", "N"},
	},
}

var allMetrics = []string{"AV", "AC", "AT", "PR", "UI", "Au", "S", "C", "I", "A", "VC", "VI", "VA", "SC", "SI", "SA", "E", "CR"}

func TestMetrics_GetScales(t *testing.T) {
	values := []string{"N", "L", "H", "M", "A", "P", "C", "R", "S", "U", "X", "ND", "n"}
	for version, scales := range wantScales {
		absent, err := Vector{Version: version, Vector: "ZZ:N"}.Parse()
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		for _, metric := range allMetrics {
			if got, ok := absent.Get(metric); ok {
				t.Errorf("CVSS %s without %s: Get = %q, true; want false", version, metric, got)
			}
			for _, value := range values {
				v := Vector{Version: version, Vector: metric + ":" + value}
				m, err := v.Parse()
				if err != nil {
					t.Fatalf("Parse(%+v): %v", v, err)
				}
				got, ok := m.Get(metric)
				wantOK := slices.Contains(scales[metric], value)
				if ok != wantOK || (ok && got != value) {
					t.Errorf("CVSS %s %s:%s: Get = %q, %v; want ok %v", version, metric, value, got, ok, wantOK)
				}
			}
		}
	}
}
