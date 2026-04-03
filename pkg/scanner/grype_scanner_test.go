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
		want      string
	}{
		{"nvd:cpe", "NVD"},
		{"NVD:cpe", "NVD"},
		{"github:language:go", "GITHUB"},
		{"github:language:python", "GITHUB"},
		{"GITHUB:language:java", "GITHUB"},
		{"osv:go", "OSV"},
		{"debian:distro:debian:13", ""},
		{"ubuntu:distro:ubuntu:22.04", ""},
		{"alpine:distro:alpine:3.18", ""},
		{"amazon:distro:amazonlinux:2", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.namespace, func(t *testing.T) {
			got := grypeNamespaceToSourceName(tt.namespace)
			if got != tt.want {
				t.Errorf("grypeNamespaceToSourceName(%q) = %q, want %q", tt.namespace, got, tt.want)
			}
		})
	}
}
