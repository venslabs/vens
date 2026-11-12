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
	"errors"
	"reflect"
	"strings"
	"testing"
)

func v2(vector string) Vector {
	return Vector{Source: "nvd", Version: "2.0", Vector: vector}
}

func v31(vector string) Vector {
	return Vector{Source: "nvd", Version: "3.1", Vector: "CVSS:3.1/" + vector}
}

func v40(vector string) Vector {
	return Vector{Source: "nvd", Version: "4.0", Vector: "CVSS:4.0/" + vector}
}

const (
	v3NNN = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
	v4NNN = "AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
)

func floored(c, i, a bool) [3]bool { return [3]bool{c, i, a} }

func TestApplicabilityOf_Floors(t *testing.T) {
	tests := []struct {
		name    string
		vectors []Vector
		want    [3]bool
	}{
		{"v3, the three axes N", []Vector{v31(v3NNN)}, floored(true, true, true)},
		{"v3, C high", []Vector{v31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")}, floored(false, true, true)},
		{"v3, every axis low", []Vector{v31("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L")}, floored(false, false, false)},
		// v3's scope changes nothing: C and I at L with S:C leave A alone floored.
		{"v3, changed scope", []Vector{v31("AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N")}, floored(false, false, true)},
		{"v2, I partial", []Vector{v2("AV:N/AC:L/Au:N/C:N/I:P/A:N")}, floored(true, false, true)},
		{"v2, A complete", []Vector{v2("AV:N/AC:L/Au:N/C:N/I:N/A:C")}, floored(true, true, false)},
		{"v4, the six impacts N", []Vector{v40(v4NNN)}, floored(true, true, true)},
		// A v4 axis is N only when the vulnerable and the subsequent system's
		// metrics both are: VC with SC, VI with SI, VA with SA.
		{"v4, subsequent systems C and I low", []Vector{v40("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N")},
			floored(false, false, true)},
		{"v4, SA high alone", []Vector{v40("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:H")},
			floored(true, true, false)},
		{"v4, VI high alone", []Vector{v40("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N")},
			floored(true, false, true)},
		{"every vector must give N", []Vector{v31(v3NNN), v2("AV:N/AC:L/Au:N/C:P/I:N/A:N")}, floored(false, true, true)},
		{"across versions", []Vector{v2("AV:N/AC:L/Au:N/C:N/I:N/A:N"), v31(v3NNN), v40(v4NNN)}, floored(true, true, true)},
		{"two sources, one version", []Vector{v31(v3NNN), {Source: "redhat", Version: "3.1",
			Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}}, floored(true, true, false)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ApplicabilityOf(tt.vectors)
			if got.Floored != tt.want {
				t.Errorf("Floored = %v, want %v", got.Floored, tt.want)
			}
			if len(got.Missing) != 0 {
				t.Errorf("Missing = %v, want none", got.Missing)
			}
		})
	}
}

func TestApplicabilityOf_Missing(t *testing.T) {
	unparsable := Vector{Source: "redhat", Version: "3.1", Vector: "CVSS:3.1/AV:N//C:N"}
	noSC := v40("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SI:N/SA:N")
	noC := v31("AV:N/AC:L/PR:N/UI:N/S:U/I:N/A:N")
	offSA := v40("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:S")
	v2Low := v2("AV:N/AC:L/Au:N/C:L/I:N/A:N")
	unknown := Vector{Source: "ghsa", Version: "5.0", Vector: "AV:N/C:N/I:N/A:N"}
	noS := v40("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N")
	twoColons := v31("AV:N:bad/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")

	tests := []struct {
		name    string
		vectors []Vector
		floored [3]bool
		missing []Missing
	}{
		{"no vector", nil, floored(false, false, false), []Missing{{Cause: NoVector}}},
		{"a vector that does not parse leaves every axis", []Vector{v31(v3NNN), unparsable},
			floored(false, false, false), []Missing{{Cause: Unparsable, Vector: unparsable}}},
		{"a part with two colons leaves every axis, its impact metrics all N", []Vector{twoColons},
			floored(false, false, false), []Missing{{Cause: Unparsable, Vector: twoColons}}},
		{"a version vens does not read", []Vector{unknown}, floored(false, false, false),
			[]Missing{{Cause: Unparsable, Vector: unknown}}},
		{"v4 lacking SC leaves C", []Vector{noSC}, floored(false, true, true),
			[]Missing{{Cause: MetricAbsent, Vector: noSC, Metric: "SC"}}},
		{"v3 lacking C leaves C", []Vector{noC}, floored(false, true, true),
			[]Missing{{Cause: MetricAbsent, Vector: noC, Metric: "C"}}},
		{"v4 giving SA off its scale leaves A", []Vector{offSA}, floored(true, true, false),
			[]Missing{{Cause: OffScale, Vector: offSA, Metric: "SA", Value: "S"}}},
		{"v2 giving C on v3's scale leaves C", []Vector{v2Low}, floored(false, true, true),
			[]Missing{{Cause: OffScale, Vector: v2Low, Metric: "C", Value: "L"}}},
		{"every cause, in vector order", []Vector{noC, offSA, noSC}, floored(false, true, false), []Missing{
			{Cause: MetricAbsent, Vector: noC, Metric: "C"},
			{Cause: OffScale, Vector: offSA, Metric: "SA", Value: "S"},
			{Cause: MetricAbsent, Vector: noSC, Metric: "SC"},
		}},
		{"a vector repeated counts once", []Vector{noC, noC}, floored(false, true, true),
			[]Missing{{Cause: MetricAbsent, Vector: noC, Metric: "C"}}},
		{"v4 lacking the three S metrics", []Vector{noS}, floored(false, false, false), []Missing{
			{Cause: MetricAbsent, Vector: noS, Metric: "SC"},
			{Cause: MetricAbsent, Vector: noS, Metric: "SI"},
			{Cause: MetricAbsent, Vector: noS, Metric: "SA"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ApplicabilityOf(tt.vectors)
			if got.Floored != tt.floored {
				t.Errorf("Floored = %v, want %v", got.Floored, tt.floored)
			}
			for i := range got.Missing {
				got.Missing[i].Err = nil
			}
			if !reflect.DeepEqual(got.Missing, tt.missing) {
				t.Errorf("Missing = %+v\nwant      %+v", got.Missing, tt.missing)
			}
		})
	}
}

func TestApplicabilityOf_UnparsableCarriesTheError(t *testing.T) {
	got := ApplicabilityOf([]Vector{{Source: "nvd", Version: "3.1", Vector: "CVSS:3.1/AV:N/AV:L"}})
	if len(got.Missing) != 1 || got.Missing[0].Err == nil {
		t.Fatalf("Missing = %+v, want one cause with its parse error", got.Missing)
	}
}

func TestMissing_String(t *testing.T) {
	v := Vector{Source: "redhat", Version: "4.0", Vector: "CVSS:4.0/AV:N"}
	parseErr := errors.New("metric AV given twice")
	tests := []struct {
		m    Missing
		want []string
	}{
		{Missing{Cause: NoVector}, []string{"no CVSS vector"}},
		{Missing{Cause: Unparsable, Vector: v, Err: parseErr}, []string{"redhat", "CVSS 4.0", "CVSS:4.0/AV:N", "does not parse", parseErr.Error()}},
		{Missing{Cause: MetricAbsent, Vector: v, Metric: "SC"}, []string{"redhat", "CVSS 4.0", "lacks SC"}},
		{Missing{Cause: OffScale, Vector: v, Metric: "SA", Value: "S"}, []string{"redhat", "CVSS 4.0", "SA:S", "off"}},
		{Missing{}, []string{"cause 0"}},
	}
	for _, tt := range tests {
		got := tt.m.String()
		for _, w := range tt.want {
			if !strings.Contains(got, w) {
				t.Errorf("%+v: String() = %q, want it to hold %q", tt.m, got, w)
			}
		}
	}
}
