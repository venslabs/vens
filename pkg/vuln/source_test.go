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

package vuln

import "testing"

func TestSource(t *testing.T) {
	tests := []struct {
		vulnID       string
		wantName     string
		wantURLEmpty bool
	}{
		{
			vulnID:   "CVE-2024-1234",
			wantName: "NVD",
		},
		{
			vulnID:   "CVE-2011-3374",
			wantName: "NVD",
		},
		{
			vulnID:   "GHSA-abcd-efgh-ijkl",
			wantName: "GITHUB",
		},
		{
			vulnID:   "GO-2024-0001",
			wantName: "OSV",
		},
		{
			vulnID:   "PYSEC-2024-0001",
			wantName: "OSV",
		},
		{
			vulnID:   "RUSTSEC-2024-0001",
			wantName: "OSV",
		},
		{
			vulnID:       "UNKNOWN-123",
			wantName:     "UNKNOWN",
			wantURLEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.vulnID, func(t *testing.T) {
			src := Source(tt.vulnID)
			if src == nil {
				t.Fatal("Source returned nil")
			}
			if src.Name != tt.wantName {
				t.Errorf("Source(%q).Name = %q, want %q", tt.vulnID, src.Name, tt.wantName)
			}
			if tt.wantURLEmpty && src.URL != "" {
				t.Errorf("Source(%q).URL = %q, want empty", tt.vulnID, src.URL)
			}
			if !tt.wantURLEmpty && src.URL == "" {
				t.Errorf("Source(%q).URL is empty, want non-empty", tt.vulnID)
			}
		})
	}
}
