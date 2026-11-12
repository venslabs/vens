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

package generator

import "github.com/venslabs/vens/pkg/cvss"

// VendorSeverity is one source's severity for a vulnerability, as the
// scanner report names both.
type VendorSeverity struct {
	Source   string
	Severity string
}

// Flags are the two flags that send a CVE to the adjustment call of #310
// step 3, and whether the second could be checked at all.
type Flags struct {
	// MaintainerDisputed: the description says the CVE is disputed, or not a
	// security issue.
	MaintainerDisputed bool
	// SeverityContested: the severity is low and not NVD's, while NVD rates
	// the CVE high or critical with a vector of the newest CVSS version the
	// row carries.
	SeverityContested bool
	// SeverityContestedUnavailable: the report has no NVD record to check the
	// severity against, so SeverityContested could not fire.
	SeverityContestedUnavailable bool
}

// Flagged reports whether either flag fired.
func (f Flags) Flagged() bool {
	return f.MaintainerDisputed || f.SeverityContested
}

// CVEFlags reads one CVE's flags from its rows: a flag fires when it fires on
// any row, and the second is unavailable only when it is on every row.
func CVEFlags(rows []Vulnerability) Flags {
	f := Flags{SeverityContestedUnavailable: len(rows) > 0}
	for _, r := range rows {
		f.MaintainerDisputed = f.MaintainerDisputed || r.Flags.MaintainerDisputed
		f.SeverityContested = f.SeverityContested || r.Flags.SeverityContested
		f.SeverityContestedUnavailable = f.SeverityContestedUnavailable && r.Flags.SeverityContestedUnavailable
	}
	return f
}

// CVEApplicability reads Applicability over every vector of one CVE's rows.
func CVEApplicability(rows []Vulnerability) cvss.Applicability {
	var vectors []cvss.Vector
	for _, r := range rows {
		vectors = append(vectors, r.CVSS...)
	}
	return cvss.ApplicabilityOf(vectors)
}
