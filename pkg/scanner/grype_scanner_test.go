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

func TestGrypeNamespaceToSourceName(t *testing.T) {
	tests := []struct {
		namespace string
		vulnID    string
		want      string
	}{
		{"nvd:cpe", "CVE-2024-1234", "NVD"},
		{"NVD:cpe", "CVE-2024-1234", "NVD"},
		{"github:language:go", "GHSA-xxxx-xxxx-xxxx", "GITHUB"},
		{"github:language:python", "CVE-2024-1234", "NVD"},
		{"GITHUB:language:java", "GHSA-xxxx-xxxx-xxxx", "GITHUB"},
		{"osv:go", "GO-2024-0001", "OSV"},
		{"debian:distro:debian:13", "CVE-2024-1234", "NVD"},
		{"ubuntu:distro:ubuntu:22.04", "CVE-2024-5678", "NVD"},
		{"alpine:distro:alpine:3.18", "GHSA-yyyy-yyyy-yyyy", "GITHUB"},
		{"amazon:distro:amazonlinux:2", "OTHER-123", "UNKNOWN"},
		{"", "CVE-2024-9999", "NVD"},
		{"", "OTHER-456", "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.namespace+"_"+tt.vulnID, func(t *testing.T) {
			got := grypeNamespaceToSourceName(tt.namespace, tt.vulnID)
			if got != tt.want {
				t.Errorf("grypeNamespaceToSourceName(%q, %q) = %q, want %q", tt.namespace, tt.vulnID, got, tt.want)
			}
		})
	}
}
