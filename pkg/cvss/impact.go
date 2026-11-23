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
	"strings"
)

// impactMetrics are the v3 metrics each axis reads, indexed as the axes.
var impactMetrics = [3]string{Confidentiality: "C", Integrity: "I", Availability: "A"}

// worse ranks a v3 impact value: H over L over N.
var worse = map[string]int{"N": 0, "L": 1, "H": 2}

// Impact is what a CVE's CVSS v3 vectors say about its confidentiality,
// integrity and availability. Loss of confidentiality, integrity and
// availability are read from it.
type Impact struct {
	// Values holds, per axis, indexed as the axes, the worst value, H over L
	// over N, among the usable vectors; all three empty when none is usable.
	Values [3]string
	// Usable counts the distinct usable v3 vectors.
	Usable int
	// Rejected lists each distinct v3 vector refused whole, in vector order.
	Rejected []Rejected
	// V4 counts the distinct v4 vectors, which are not read.
	V4 int
}

// Rejected is a v3 vector Impact refused, and why.
type Rejected struct {
	Vector Vector
	Err    error
}

func (r Rejected) String() string {
	return fmt.Sprintf("%s CVSS %s vector %q: %v", r.Vector.Source, r.Vector.Version, r.Vector.Vector, r.Err)
}

// Vectorless reports whether no v3 vector is usable.
func (i Impact) Vectorless() bool {
	return i.Usable == 0
}

// ImpactOf reads Impact over every vector of one CVE, from all its rows and
// sources. A v3 vector is one Tier reads as 3; vectors are distinct once
// trimmed. One is usable when it parses as Parse reads it, any CVSS: prefix
// stating 3.0 or 3.1, and gives C, I and A each on H, L or N; any other is
// refused whole. v2 vectors are not read, and v4 vectors are counted.
func ImpactOf(vectors []Vector) Impact {
	var i Impact
	var seen, seen4 []string
	for _, v := range vectors {
		text := strings.TrimSpace(v.Vector)
		switch v.Tier() {
		case 4:
			if !slices.Contains(seen4, text) {
				seen4 = append(seen4, text)
				i.V4++
			}
			continue
		case 3:
		default:
			continue
		}
		if slices.Contains(seen, text) {
			continue
		}
		seen = append(seen, text)
		values, err := impactValues(v)
		if err != nil {
			i.Rejected = append(i.Rejected, Rejected{Vector: v, Err: err})
			continue
		}
		i.Usable++
		for axis, value := range values {
			if i.Values[axis] == "" || worse[value] > worse[i.Values[axis]] {
				i.Values[axis] = value
			}
		}
	}
	return i
}

// impactValues returns a v3 vector's C, I and A, or why it is not usable.
func impactValues(v Vector) ([3]string, error) {
	var values [3]string
	if version, ok := PrefixVersion(v.Vector); ok && version != "3.0" && version != "3.1" {
		return values, fmt.Errorf("prefix CVSS:%s states neither 3.0 nor 3.1", version)
	}
	m, err := v.Parse()
	if err != nil {
		return values, err
	}
	for axis, metric := range impactMetrics {
		value, ok := m.Get(metric)
		if !ok {
			return values, fmt.Errorf("%s is absent or off H, L and N", metric)
		}
		values[axis] = value
	}
	return values, nil
}
