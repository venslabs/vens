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

package cvss

import (
	"fmt"
	"slices"
)

// The three axes, indexing Applicability.Floored.
const (
	Confidentiality = iota
	Integrity
	Availability
)

// axisMetrics names, per tier, the metrics each axis reads. A v4 axis reads
// the vulnerable system's metric with the subsequent systems' one: v4 scores
// an impact on subsequent systems alone, so VC:N says nothing while SC is not
// N.
var axisMetrics = map[int][3][]string{
	2: {{"C"}, {"I"}, {"A"}},
	3: {{"C"}, {"I"}, {"A"}},
	4: {{"VC", "SC"}, {"VI", "SI"}, {"VA", "SA"}},
}

// Cause is why a CVE's vectors leave an axis applicable that they might have
// floored.
type Cause int

const (
	// NoVector: the report gives the CVE no CVSS vector at all.
	NoVector Cause = iota + 1
	// Unparsable: a vector does not parse.
	Unparsable
	// MetricAbsent: a vector lacks a metric an axis reads.
	MetricAbsent
	// OffScale: a vector gives an axis metric a value off its version's scale.
	OffScale
)

// Missing is one cause of applicability_missing.
type Missing struct {
	Cause Cause
	// Vector is the vector at fault, zero for NoVector.
	Vector Vector
	// Metric is the axis metric MetricAbsent and OffScale name, Value the
	// value OffScale found.
	Metric string
	Value  string
	// Err is why an Unparsable vector does not parse.
	Err error
}

func (m Missing) String() string {
	at := fmt.Sprintf("%s CVSS %s vector", m.Vector.Source, m.Vector.Version)
	if m.Vector.Version == "" {
		at = m.Vector.Source + " CVSS vector of unknown version"
	}
	switch m.Cause {
	case NoVector:
		return "no CVSS vector in the scanner's report"
	case Unparsable:
		return fmt.Sprintf("%s %q does not parse: %v", at, m.Vector.Vector, m.Err)
	case MetricAbsent:
		return fmt.Sprintf("%s lacks %s", at, m.Metric)
	case OffScale:
		return fmt.Sprintf("%s gives %s:%s, off its version's scale", at, m.Metric, m.Value)
	}
	return fmt.Sprintf("cause %d", m.Cause)
}

// Applicability is what a CVE's CVSS vectors say about its three axes.
type Applicability struct {
	// Floored is true for an axis every vector gives N: its loss factor then
	// takes OWASP's floor and its question is not asked.
	Floored [3]bool
	// Missing lists every cause of applicability_missing in vector order,
	// empty when every vector reads every axis.
	Missing []Missing
}

// ApplicabilityOf reads Applicability over every vector of one CVE, from all
// its rows and sources. An axis is floored when every vector gives it N. A
// vector that does not parse leaves every axis applicable, one that lacks an
// axis metric or gives it off its scale leaves that axis applicable, and no
// vector at all floors nothing; each is a cause of applicability_missing.
func ApplicabilityOf(vectors []Vector) Applicability {
	vectors = distinct(vectors)
	if len(vectors) == 0 {
		return Applicability{Missing: []Missing{{Cause: NoVector}}}
	}
	a := Applicability{Floored: [3]bool{true, true, true}}
	for _, v := range vectors {
		m, err := v.Parse()
		if err != nil {
			a.Floored = [3]bool{}
			a.Missing = append(a.Missing, Missing{Cause: Unparsable, Vector: v, Err: err})
			continue
		}
		for axis, metrics := range axisMetrics[m.tier] {
			for _, metric := range metrics {
				value, given := m.values[metric]
				if value == "N" {
					continue
				}
				a.Floored[axis] = false
				if !given {
					a.Missing = append(a.Missing, Missing{Cause: MetricAbsent, Vector: v, Metric: metric})
				} else if !slices.Contains(scales[m.tier][metric], value) {
					a.Missing = append(a.Missing, Missing{Cause: OffScale, Vector: v, Metric: metric, Value: value})
				}
			}
		}
	}
	return a
}

func distinct(vectors []Vector) []Vector {
	var out []Vector
	for _, v := range vectors {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}
