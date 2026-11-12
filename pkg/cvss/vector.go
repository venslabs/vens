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

// Package cvss reads the CVSS vectors a scanner report publishes: their
// version, the base metrics vens uses, and what they say about a CVE's
// confidentiality, integrity and availability.
package cvss

import (
	"fmt"
	"slices"
	"strings"
)

// Vector is one CVSS vector as a scanner report publishes it.
type Vector struct {
	// Source is who published it, as the report names it: "nvd" or "redhat"
	// on Trivy, "nvd@nist.gov" on Grype.
	Source string
	// Version is the CVSS version, "2.0", "3.0", "3.1" or "4.0".
	Version string
	Vector  string
}

// Tier is the vector's major version, 2, 3 or 4, and 0 for a version vens
// does not read. 3.0 and 3.1 are one tier.
func (v Vector) Tier() int {
	return tierOf(v.Version)
}

func tierOf(version string) int {
	switch version {
	case "2.0", "2":
		return 2
	case "3.0", "3.1":
		return 3
	case "4.0":
		return 4
	}
	return 0
}

// Newest returns the newest tier among the vectors, 0 when none has a version
// vens reads.
func Newest(vectors []Vector) int {
	newest := 0
	for _, v := range vectors {
		newest = max(newest, v.Tier())
	}
	return newest
}

// scales holds, per tier, the base metrics vens reads and their values.
// Au and v3's S are base metrics vens does not read.
var scales = map[int]map[string][]string{
	2: {
		"AV": {"L", "A", "N"}, "AC": {"H", "M", "L"},
		"C": {"N", "P", "C"}, "I": {"N", "P", "C"}, "A": {"N", "P", "C"},
	},
	3: {
		"AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "PR": {"N", "L", "H"}, "UI": {"N", "R"},
		"C": {"H", "L", "N"}, "I": {"H", "L", "N"}, "A": {"H", "L", "N"},
	},
	4: {
		"AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "AT": {"N", "P"}, "PR": {"H", "L", "N"}, "UI": {"N", "P", "A"},
		"VC": {"H", "L", "N"}, "VI": {"H", "L", "N"}, "VA": {"H", "L", "N"},
		"SC": {"H", "L", "N"}, "SI": {"H", "L", "N"}, "SA": {"H", "L", "N"},
	},
}

// Metrics are a parsed vector's metric values.
type Metrics struct {
	tier   int
	values map[string]string
}

// Parse splits the vector into its metrics. It refuses a version vens does
// not read, a CVSS: prefix of another tier, and a part that is not one
// metric:value pair or repeats a metric. A parsed vector can still lack a
// metric vens reads or give it off its version's scale.
func (v Vector) Parse() (Metrics, error) {
	tier := v.Tier()
	if tier == 0 {
		return Metrics{}, fmt.Errorf("CVSS version %q is not one vens reads", v.Version)
	}
	body := strings.TrimSpace(v.Vector)
	if rest, ok := strings.CutPrefix(body, "CVSS:"); ok {
		version, metrics, _ := strings.Cut(rest, "/")
		if tierOf(version) != tier {
			return Metrics{}, fmt.Errorf("prefix CVSS:%s on a CVSS %s vector", version, v.Version)
		}
		body = metrics
	}
	values := make(map[string]string)
	for part := range strings.SplitSeq(body, "/") {
		metric, value, _ := strings.Cut(part, ":")
		if metric == "" || value == "" || strings.Contains(value, ":") {
			return Metrics{}, fmt.Errorf("%q is not a metric:value pair", part)
		}
		if _, seen := values[metric]; seen {
			return Metrics{}, fmt.Errorf("metric %s given twice", metric)
		}
		values[metric] = value
	}
	return Metrics{tier: tier, values: values}, nil
}

// Get returns a metric's value when the vector gives one on its version's
// scale; ok is false for a metric absent, off the scale, or not one vens reads
// at this version.
func (m Metrics) Get(metric string) (value string, ok bool) {
	value = m.values[metric]
	if !slices.Contains(scales[m.tier][metric], value) {
		return "", false
	}
	return value, true
}
