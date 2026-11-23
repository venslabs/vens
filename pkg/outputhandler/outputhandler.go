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

// Output handler pattern inspired by github.com/AkihiroSuda/vexllm/pkg/outputhandler

package outputhandler

import (
	"github.com/CycloneDX/cyclonedx-go"
)

type OutputHandler interface {
	// HandleVulnRatings ingests ratings grouped by vulnerability ID (e.g., CVE).
	HandleVulnRatings([]VulnRating) error
	Close() error
}

// ImpactProvenanceProperty names the property each VEX vulnerability carries
// once: where its Loss of confidentiality, integrity and availability came
// from, ImpactFromCVSSv3 or ImpactFromFallback.
const (
	ImpactProvenanceProperty = "vens:impact-provenance"
	// ImpactFromCVSSv3: read from the CVE's usable CVSS v3 vectors.
	ImpactFromCVSSv3 = "cvss-v3"
	// ImpactFromFallback: supplied by the missing-input rule, the CVE having
	// no usable CVSS v3 vector, as cvss_v3_missing counts it.
	ImpactFromFallback = "missing-cvss-v3-fallback"
)

// VulnRating carries a single CycloneDX rating for one vulnerability ID.
type VulnRating struct {
	VulnID string
	BOMRef string
	Rating cyclonedx.VulnerabilityRating
	Source *cyclonedx.Source
	// ImpactProvenance is ImpactFromCVSSv3 or ImpactFromFallback, the same on
	// every row of a vulnerability ID.
	ImpactProvenance string
}
