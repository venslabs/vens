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

import (
	"fmt"
	"slices"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// declaration is what the config's reachability entries say of one CVE: the
// index of each entry that hits it, those asserting it unreachable and those
// asserting it reachable apart. Only declared entries publish a status: no
// model answer and no note does, and an upstream VEX is not read.
type declaration struct {
	unreachable, reachable []int
	entries                []riskconfig.ReachabilityEntry
}

// declared reads the entries for a CVE. An entry asserting unreachability
// hits it when its selector is the CVE's id, or a component every row of the
// CVE names as its package, so that it covers every occurrence the scan
// lists; one asserting reachability hits it when its selector is the CVE's
// id or a component any row names. Both match without regard to case.
func declared(entries []riskconfig.ReachabilityEntry, c contract.CVE) declaration {
	d := declaration{entries: entries}
	for i, e := range entries {
		if !hits(e, c) {
			continue
		}
		if e.Reachable {
			d.reachable = append(d.reachable, i)
		} else {
			d.unreachable = append(d.unreachable, i)
		}
	}
	return d
}

func hits(e riskconfig.ReachabilityEntry, c contract.CVE) bool {
	if e.CVE != "" {
		return strings.EqualFold(e.CVE, c.ID)
	}
	names := func(r contract.Row) bool { return strings.EqualFold(e.Component, r.Package()) }
	if e.Reachable {
		return slices.ContainsFunc(c.Rows, names)
	}
	return len(c.Rows) > 0 && !slices.ContainsFunc(c.Rows, func(r contract.Row) bool { return !names(r) })
}

// vetoed reports whether an entry asserting reachability stands against one
// asserting unreachability.
func (d declaration) vetoed() bool {
	return len(d.unreachable) > 0 && len(d.reachable) > 0
}

// analysis is the VEX status the declaration publishes: not_affected,
// code_not_reachable, with a detail citing each entry that asserts it, when
// one hits and none asserting reachability vetoes it; nil otherwise. It
// leaves the rating as the answers give it.
func (d declaration) analysis() *cyclonedx.VulnerabilityAnalysis {
	if len(d.unreachable) == 0 || d.vetoed() {
		return nil
	}
	cited := make([]string, len(d.unreachable))
	for i, n := range d.unreachable {
		cited[i] = d.cite(n)
	}
	return &cyclonedx.VulnerabilityAnalysis{
		State:         cyclonedx.IASNotAffected,
		Justification: cyclonedx.IAJCodeNotReachable,
		Detail:        strings.Join(cited, "\n"),
	}
}

// cite names entry n as the config writes it, with its provenance.
func (d declaration) cite(n int) string {
	e := d.entries[n]
	return fmt.Sprintf("Declared not reachable by config.yaml reachability[%d] (%s). Provenance: %s", n, e.Selector(), e.Provenance)
}

// selectors names the entries listed, each as "reachability[n] (selector)".
func (d declaration) selectors(list []int) string {
	out := make([]string, len(list))
	for i, n := range list {
		out[i] = fmt.Sprintf("reachability[%d] (%s)", n, d.entries[n].Selector())
	}
	return strings.Join(out, ", ")
}
