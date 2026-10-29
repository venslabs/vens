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
//
// See the License for the specific language governing permissions and
// limitations under the License.

package outputhandler

import (
	"slices"
	"testing"
)

func TestUnreferencedError(t *testing.T) {
	if err := UnreferencedError("cannot emit VEX", nil); err != nil {
		t.Fatalf("UnreferencedError(nil) = %v, want nil", err)
	}
	for _, tc := range []struct {
		ids  []string
		want string
	}{
		{[]string{"CVE-9"}, "cannot emit VEX: 1 vulnerability with no component (empty BOMRef): CVE-9"},
		{[]string{"CVE-3", "CVE-2", "CVE-3"}, "cannot emit VEX: 2 vulnerabilities with no component (empty BOMRef): CVE-2, CVE-3"},
	} {
		in := slices.Clone(tc.ids)
		err := UnreferencedError("cannot emit VEX", in)
		if err == nil || err.Error() != tc.want {
			t.Errorf("UnreferencedError(%v) = %v, want %q", tc.ids, err, tc.want)
		}
		if !slices.Equal(in, tc.ids) {
			t.Errorf("UnreferencedError changed its input: %v, was %v", in, tc.ids)
		}
	}
}
