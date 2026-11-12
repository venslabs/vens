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

import (
	"regexp"
	"slices"
	"strings"

	grypemodels "github.com/anchore/grype/grype/presenter/models"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/generator"
)

// disputed is the wording by which a description says its CVE is disputed or
// not a security issue, fixed in #310 step 1.
var disputed = regexp.MustCompile(`(?i)\bdisput|non-security|not a security issue|no real threat`)

func maintainerDisputed(description string) bool {
	return disputed.MatchString(description)
}

// trivySeverityContested: the row's severity is LOW and not NVD's, while NVD
// rates the CVE HIGH or CRITICAL and publishes a vector of the newest CVSS
// version the row carries.
func trivySeverityContested(row generator.Vulnerability) bool {
	if !strings.EqualFold(row.Severity, "LOW") || row.SeveritySource == "nvd" {
		return false
	}
	nvdHigh := slices.ContainsFunc(row.VendorSeverities, func(s generator.VendorSeverity) bool {
		return s.Source == "nvd" && (s.Severity == "HIGH" || s.Severity == "CRITICAL")
	})
	return nvdHigh && hasVectorAt(row.CVSS, "nvd", cvss.Newest(row.CVSS))
}

// grypeSeverityContested is the same check on a Grype match, Negligible read
// as Low and NVD's word taken from the related records in an nvd namespace:
// one such record must both say High or Critical and carry the vector.
// Without such a record the check cannot run: unavailable.
func grypeSeverityContested(match grypemodels.Match, vectors []cvss.Vector) (contested, unavailable bool) {
	tier := cvss.Newest(vectors)
	related, nvdContests := false, false
	for _, r := range match.RelatedVulnerabilities {
		if !strings.HasPrefix(r.Namespace, "nvd") {
			continue
		}
		related = true
		var own []cvss.Vector
		for _, c := range r.Cvss {
			own = append(own, cvss.Vector{Source: c.Source, Version: c.Version, Vector: c.Vector})
		}
		high := r.Severity == "High" || r.Severity == "Critical"
		nvdContests = nvdContests || (high && hasVectorAt(own, "nvd@nist.gov", tier))
	}
	if !related {
		return false, true
	}
	matched := match.Vulnerability
	low := matched.Severity == "Low" || matched.Severity == "Negligible"
	if !low || strings.HasPrefix(matched.Namespace, "nvd") {
		return false, false
	}
	return nvdContests, false
}

// hasVectorAt reports whether source publishes a vector of the given tier;
// with no tier there is none.
func hasVectorAt(vectors []cvss.Vector, source string, tier int) bool {
	return tier > 0 && slices.ContainsFunc(vectors, func(v cvss.Vector) bool {
		return v.Source == source && v.Tier() == tier
	})
}
