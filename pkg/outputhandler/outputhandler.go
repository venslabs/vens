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
	"github.com/venslabs/vens/pkg/owasp"
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

// ImpactBasisProperty names the property each VEX vulnerability carries once:
// the impact its severity and score are read on, owasp.BasisTechnical or
// owasp.BasisBusiness. The vector alone does not say which.
const ImpactBasisProperty = "vens:impact-basis"

// RatingPolicyProperty names the property a VEX carries once, in its
// metadata: the version of the rules its ratings follow, RatingPolicy. A VEX
// without it predates version 2.
const (
	RatingPolicyProperty = "vens:rating-policy"
	// RatingPolicy 2: the impact is read on vens:impact-basis, and Financial
	// damage and Reputation damage are set from business_criticality at the
	// CVE's worst technical loss.
	RatingPolicy = "2"
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
	// ImpactBasis is the impact Rating is read on, the same on every row of a
	// vulnerability ID.
	ImpactBasis owasp.Basis
}
