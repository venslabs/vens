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
	"context"
	"log/slog"
	"slices"
	"strings"

	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
)

// cve is one vulnerability of the run: every row the scanner reported for it,
// in scanner order, and what Go reads of them before any call.
type cve struct {
	rows []Vulnerability
	// in is the CVE as the questions read it, every row's evidence kept.
	in     contract.CVE
	impact cvss.Impact
	// declared is what the config's reachability entries say of it.
	declared declaration
	// flags are the flags its rows raised, each with its evidence and its
	// row's package; a CVE with none gets no adjustment.
	flags []contract.Flag
	// contestUnchecked: no row's report holds an NVD record to check its
	// severity against.
	contestUnchecked bool
	questions        []contract.Factor
}

func (c *cve) id() string { return c.in.ID }

func (c *cve) asks(f contract.Factor) bool { return slices.Contains(c.questions, f) }

// counters lists the counters the CVE adds one to: those its levels name,
// then severity_contested_unavailable.
func (c *cve) counters(l contract.Levels) []string {
	out := slices.Clone(l.Counters)
	if c.contestUnchecked {
		out = append(out, "severity_contested_unavailable")
	}
	return out
}

// plan groups the rows by CVE and reads, for each CVE, what its CVSS v3
// vectors give the three technical impacts, what the config's reachability
// entries declare of it, the flags of every row, and the questions it gets.
// A flag the adjustment would refuse, such as one whose evidence its row
// cannot quote, stops the run here, before any call is paid.
func (g *Generator) plan(ctx context.Context, vulns []Vulnerability) ([]*cve, error) {
	groups := groupVulnsByCVE(vulns)
	cves := make([]*cve, 0, len(groups))
	for _, rows := range groups {
		c := &cve{
			rows:             rows,
			in:               contractCVE(rows),
			impact:           CVEImpact(rows),
			flags:            rowFlags(rows),
			contestUnchecked: CVEFlags(rows).SeverityContestedUnavailable,
		}
		c.declared = declared(g.o.Config.Reachability, c.in)
		if c.declared.vetoed() {
			slog.WarnContext(ctx, "Reachability entries disagree; one asserting reachability vetoes the status, so none is published",
				"vuln", c.id(),
				"unreachable", c.declared.selectors(c.declared.unreachable),
				"reachable", c.declared.selectors(c.declared.reachable),
			)
		}
		if len(c.flags) > 0 {
			if err := contract.CheckFlags(c.flags, c.in); err != nil {
				return nil, err
			}
		}
		questions, err := contract.Questions(g.deployment, c.in)
		if err != nil {
			return nil, err
		}
		c.questions = questions
		slog.DebugContext(ctx, "planned questions",
			"vuln", c.id(),
			"questions", joinFactors(questions),
			"flagged", len(c.flags) > 0,
		)
		cves = append(cves, c)
	}
	return cves, nil
}

// undescribed lists the CVEs no row describes, which are not asked Motive,
// Opportunity and Ease of exploit.
func undescribed(cves []*cve) []string {
	var ids []string
	for _, c := range cves {
		if !c.in.Described() {
			ids = append(ids, c.id())
		}
	}
	return ids
}

// vectorless lists the CVEs with no usable CVSS v3 vector, whose technical
// impacts take their worst level.
func vectorless(cves []*cve) []string {
	var ids []string
	for _, c := range cves {
		if c.impact.Vectorless() {
			ids = append(ids, c.id())
		}
	}
	return ids
}

// groupVulnsByCVE groups the flat (CVE, component) scanner rows by CVE,
// preserving first-seen scanner order. Batching operates on these groups, so
// a multi-component CVE occupies exactly one prompt entry in exactly one
// batch: the model is asked (and paid) once per CVE instead of once per
// component row. A row without an ID is never asked about, and is not a CVE.
func groupVulnsByCVE(vulns []Vulnerability) [][]Vulnerability {
	var groups [][]Vulnerability
	index := make(map[string]int, len(vulns))
	for _, v := range vulns {
		if v.VulnID == "" {
			continue
		}
		if i, ok := index[v.VulnID]; ok {
			groups[i] = append(groups[i], v)
			continue
		}
		index[v.VulnID] = len(groups)
		groups = append(groups, []Vulnerability{v})
	}
	return groups
}

// contractCVE is a CVE's rows as the questions read them, each row with its
// own vectors, severity source and vendor severities.
func contractCVE(rows []Vulnerability) contract.CVE {
	c := contract.CVE{ID: rows[0].VulnID, Rows: make([]contract.Row, len(rows))}
	for i, r := range rows {
		c.Rows[i] = contractRow(r)
	}
	return c
}

func contractRow(r Vulnerability) contract.Row {
	severities := make([]contract.VendorSeverity, len(r.VendorSeverities))
	for i, s := range r.VendorSeverities {
		severities[i] = contract.VendorSeverity{Source: s.Source, Severity: s.Severity}
	}
	return contract.Row{
		PkgID:            r.PkgID,
		PkgName:          r.PkgName,
		InstalledVersion: r.InstalledVersion,
		FixedVersion:     r.FixedVersion,
		Title:            r.Title,
		Description:      r.Description,
		Severity:         r.Severity,
		SeveritySource:   r.SeveritySource,
		CVSS:             r.CVSS,
		VendorSeverities: severities,
		BOMRef:           r.BOMRef,
	}
}

func cveIDs(cves []*cve) []string {
	ids := make([]string, len(cves))
	for i, c := range cves {
		ids[i] = c.id()
	}
	return ids
}

func contractCVEs(cves []*cve) []contract.CVE {
	out := make([]contract.CVE, len(cves))
	for i, c := range cves {
		out[i] = c.in
	}
	return out
}

func joinFactors(factors []contract.Factor) string {
	names := make([]string, len(factors))
	for i, f := range factors {
		names[i] = string(f)
	}
	return strings.Join(names, ",")
}
