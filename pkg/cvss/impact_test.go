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
	"strings"
	"testing"
)

func cia(c, i, a string) [3]string { return [3]string{c, i, a} }

func TestImpactOf_WorstValuePerAxis(t *testing.T) {
	redhat := func(metrics string) Vector {
		return Vector{Source: "redhat", Version: "3.1", Vector: "CVSS:3.1/" + metrics}
	}
	tests := []struct {
		name    string
		vectors []Vector
		want    [3]string
		usable  int
	}{
		{"one vector", []Vector{v31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N")}, cia("H", "L", "N"), 1},
		{"H over L over N, axis by axis", []Vector{
			v31("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H"),
			redhat("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
		}, cia("H", "L", "H"), 2},
		{"3.0 and 3.1 alike", []Vector{
			{Source: "nvd", Version: "3.0", Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"},
			redhat("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
		}, cia("L", "H", "N"), 2},
		// Trivy's V3Vector without its prefix gives the major version only.
		{"no prefix", []Vector{{Source: "nvd", Version: "3", Vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}}, cia("N", "N", "L"), 1},
		{"prefix in any case", []Vector{{Source: "nvd", Version: "3.1", Vector: "cvss:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"}}, cia("L", "L", "L"), 1},
		{"distinct once trimmed", []Vector{
			v31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
			{Source: "redhat", Version: "3.1", Vector: "  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"},
		}, cia("H", "H", "H"), 1},
		{"a rejected vector leaves the usable one", []Vector{
			v31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/C:L"),
			redhat("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"),
		}, cia("N", "L", "N"), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ImpactOf(tt.vectors)
			if got.Values != tt.want || got.Usable != tt.usable || got.Vectorless() {
				t.Errorf("ImpactOf = %+v, want values %v from %d usable vectors", got, tt.want, tt.usable)
			}
		})
	}
}

func TestImpactOf_RejectsWhole(t *testing.T) {
	tests := []struct {
		name   string
		vector Vector
		why    string
	}{
		{"not a metric:value pair", v31("AV:N/garbage"), "not a metric:value pair"},
		{"a trailing slash", v31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/"), "not a metric:value pair"},
		{"a metric twice", v31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/A:L"), "given twice"},
		{"C absent", v31("AV:N/AC:L/PR:N/UI:N/S:U/I:H/A:H"), "C is absent"},
		{"I off the scale", v31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:X/A:H"), "I is absent or off"},
		{"A in lower case", v31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:h"), "A is absent or off"},
		{"prefix of v2", Vector{Source: "nvd", Version: "3.1", Vector: "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"}, "states neither 3.0 nor 3.1"},
		{"prefix stating 3 alone", Vector{Source: "nvd", Version: "3", Vector: "CVSS:3/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, "states neither 3.0 nor 3.1"},
		{"prefix and nothing else", Vector{Source: "nvd", Version: "3.1", Vector: "CVSS:3.1"}, "not a metric:value pair"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ImpactOf([]Vector{tt.vector})
			if !got.Vectorless() || got.Values != cia("", "", "") {
				t.Fatalf("ImpactOf = %+v, want it vectorless", got)
			}
			if len(got.Rejected) != 1 || got.Rejected[0].Vector != tt.vector || !strings.Contains(got.Rejected[0].String(), tt.why) {
				t.Errorf("Rejected = %v, want the vector refused because %s", got.Rejected, tt.why)
			}
		})
	}
}

func TestImpactOf_ReadsV3Alone(t *testing.T) {
	v4 := v40("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
	tests := []struct {
		name    string
		vectors []Vector
		want    Impact
	}{
		{"no vector", nil, Impact{}},
		{"v2 alone", []Vector{v2("AV:N/AC:L/Au:N/C:C/I:C/A:C")}, Impact{}},
		{"v4 alone, counted, not read", []Vector{v4, v4}, Impact{V4: 1}},
		{"an unknown version", []Vector{{Source: "nvd", Version: "3.2", Vector: "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}, Impact{}},
		{"v3 beside v2 and v4", []Vector{
			v2("AV:N/AC:L/Au:N/C:C/I:C/A:C"),
			v31("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"),
			v4,
		}, Impact{Values: cia("N", "N", "L"), Usable: 1, V4: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ImpactOf(tt.vectors)
			if got.Values != tt.want.Values || got.Usable != tt.want.Usable || got.V4 != tt.want.V4 || len(got.Rejected) != 0 {
				t.Errorf("ImpactOf = %+v, want %+v", got, tt.want)
			}
		})
	}
}
