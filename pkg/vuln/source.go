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

// Package vuln provides vulnerability metadata utilities.
package vuln

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
)

// Source derives a CycloneDX Source from a vulnerability ID prefix.
// This is used as a fallback when the scanner does not provide source metadata.
// It maps well-known prefixes to their respective databases. Unknown prefixes
// return "UNKNOWN".
func Source(vulnID string) *cyclonedx.Source {
	switch {
	case strings.HasPrefix(vulnID, "CVE-"):
		return &cyclonedx.Source{
			Name: "NVD",
			URL:  "https://nvd.nist.gov/vuln/detail/" + vulnID,
		}
	case strings.HasPrefix(vulnID, "GHSA-"):
		return &cyclonedx.Source{
			Name: "GITHUB",
			URL:  "https://github.com/advisories/" + vulnID,
		}
	case strings.HasPrefix(vulnID, "GO-"):
		return &cyclonedx.Source{
			Name: "OSV",
			URL:  "https://osv.dev/vulnerability/" + vulnID,
		}
	case strings.HasPrefix(vulnID, "PYSEC-"):
		return &cyclonedx.Source{
			Name: "OSV",
			URL:  "https://osv.dev/vulnerability/" + vulnID,
		}
	case strings.HasPrefix(vulnID, "RUSTSEC-"):
		return &cyclonedx.Source{
			Name: "OSV",
			URL:  "https://osv.dev/vulnerability/" + vulnID,
		}
	default:
		return &cyclonedx.Source{
			Name: "UNKNOWN",
		}
	}
}
