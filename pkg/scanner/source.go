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

import "strings"

// Supported vulnerability source names compatible with Dependency-Track.
// See: https://github.com/DependencyTrack/hyades-apiserver/blob/main/apiserver/src/main/java/org/dependencytrack/model/Vulnerability.java
const (
	SourceNVD      = "NVD"
	SourceGITHUB   = "GITHUB"
	SourceOSV      = "OSV"
	SourceNPM      = "NPM"
	SourceOSSINDEX = "OSSINDEX"
	SourceSNYK     = "SNYK"
	SourceVULNDB   = "VULNDB"
	SourceUNKNOWN  = "UNKNOWN"
)

// SourceFromVulnID returns the vulnerability source based on the vulnerability ID prefix.
// This provides a consistent fallback when the scanner's data source cannot be mapped.
func SourceFromVulnID(vulnID string) string {
	switch {
	case strings.HasPrefix(vulnID, "CVE-"):
		return SourceNVD
	case strings.HasPrefix(vulnID, "GHSA-"):
		return SourceGITHUB
	case strings.HasPrefix(vulnID, "GO-"), strings.HasPrefix(vulnID, "PYSEC-"), strings.HasPrefix(vulnID, "RUSTSEC-"):
		return SourceOSV
	case strings.HasPrefix(vulnID, "NPM-"), strings.HasPrefix(vulnID, "NPMJS-"):
		return SourceNPM
	case strings.HasPrefix(vulnID, "SNYK-"):
		return SourceSNYK
	}
	return ""
}
