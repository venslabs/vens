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

import "testing"

func TestSourceFromVulnID(t *testing.T) {
	tests := []struct {
		vulnID string
		want   string
	}{
		{"CVE-2024-1234", SourceNVD},
		{"CVE-2011-3374", SourceNVD},
		{"GHSA-abcd-efgh-ijkl", SourceGITHUB},
		{"GO-2024-0001", SourceOSV},
		{"PYSEC-2024-0001", SourceOSV},
		{"RUSTSEC-2024-0001", SourceOSV},
		{"NPM-123", SourceNPM},
		{"NPMJS-456", SourceNPM},
		{"SNYK-JS-PKG-123", SourceSNYK},
		{"TEMP-0841856-B18BAF", ""},
		{"OTHER-123", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.vulnID, func(t *testing.T) {
			got := SourceFromVulnID(tt.vulnID)
			if got != tt.want {
				t.Errorf("SourceFromVulnID(%q) = %q, want %q", tt.vulnID, got, tt.want)
			}
		})
	}
}
