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

package types

// SBOMComponent holds only the fields we need from CycloneDX components for indexing.
type SBOMComponent struct {
	Type    string `json:"type"`
	Group   string `json:"group,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	// ParentPURL is the purl of metadata.component (the SBOM's top-level component).
	// Filled during SBOM streaming/decoding for easy linkage to the parent.
	// Not part of the original component JSON; kept out of JSON encoding on purpose.
	ParentPURL string `json:"-"`
}
