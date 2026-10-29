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

package generate

import (
	"testing"

	"github.com/venslabs/vens/pkg/generator"
)

// #272: every CVE with a row that has no component (empty BOMRef) is named
// once; testdata/script/generate_empty_bomref.txt shows the run stops before
// any LLM call.
func TestCheckBOMRefs(t *testing.T) {
	if err := checkBOMRefs([]generator.Vulnerability{
		{VulnID: "CVE-1", BOMRef: "pkg:npm/foo@1.0.0"},
		{VulnID: "CVE-2", BOMRef: "pkg:npm/bar@2.0.0"},
		{VulnID: "", BOMRef: ""},
	}); err != nil {
		t.Fatalf("checkBOMRefs with refs: %v", err)
	}

	// CVE-4 has a row with a component and one without: it is named all the same.
	err := checkBOMRefs([]generator.Vulnerability{
		{VulnID: "CVE-2", BOMRef: ""},
		{VulnID: "CVE-1", BOMRef: "pkg:npm/foo@1.0.0"},
		{VulnID: "CVE-2", BOMRef: ""},
		{VulnID: "CVE-3", BOMRef: ""},
		{VulnID: "CVE-4", BOMRef: "pkg:npm/baz@1.0.0"},
		{VulnID: "CVE-4", BOMRef: ""},
	})
	want := "cannot generate VEX: 3 vulnerabilities with no component (empty BOMRef): CVE-2, CVE-3, CVE-4"
	if err == nil || err.Error() != want {
		t.Fatalf("checkBOMRefs() = %v, want %q", err, want)
	}

	err = checkBOMRefs([]generator.Vulnerability{{VulnID: "CVE-9"}})
	want = "cannot generate VEX: 1 vulnerability with no component (empty BOMRef): CVE-9"
	if err == nil || err.Error() != want {
		t.Fatalf("checkBOMRefs() = %v, want %q", err, want)
	}

	if err := checkBOMRefs(nil); err != nil {
		t.Fatalf("checkBOMRefs(nil): %v", err)
	}
}
