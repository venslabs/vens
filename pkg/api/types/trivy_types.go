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

// Subset of https://pkg.go.dev/github.com/aquasecurity/trivy@v0.67.2/pkg/types

type Report struct {
	SchemaVersion int      `json:",omitempty"`
	ArtifactName  string   `json:",omitempty"`
	ArtifactType  string   `json:",omitempty"`
	Results       []Result `json:",omitempty"`
}

type Result struct {
	Target          string          `json:",omitempty"`
	Class           string          `json:",omitempty"`
	Type            string          `json:",omitempty"`
	Vulnerabilities []Vulnerability `json:",omitempty"`
}

type Vulnerability struct {
	VulnerabilityID string         `json:",omitempty"`
	PkgID           string         `json:",omitempty"`
	Title           string         `json:",omitempty"`
	Description     string         `json:",omitempty"`
	Severity        string         `json:",omitempty"`
	CweIDs          []string       `json:",omitempty"`
	VendorSeverity  map[string]int `json:",omitempty"`
	VensRating      *VensRating    `json:"vens_rating,omitempty"`
}

type VensRating struct {
	Score         float64 `json:"score"`
	Severity      string  `json:"severity"`
	Justification string  `json:"justification"`
}
