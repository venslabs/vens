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
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/generator"
)

// reportCounts is what #310 step 3 counted on each committed report when it
// designed the scanner's part: rows and CVEs, what one CVE's rows share, the
// newest CVSS version, Applicability and the two flags, per CVE.
type reportCounts struct {
	Rows, CVEs, MultiRowCVEs int
	// Differ counts the CVEs on several rows whose rows differ, per field.
	Differ map[string]int
	// NewestTier counts CVEs by the newest CVSS version among their vectors,
	// 0 for none.
	NewestTier map[int]int
	// DisagreeO and DisagreeEE count CVEs whose vectors at that version
	// disagree on a metric Opportunity, or Ease of exploit, is shown.
	DisagreeO, DisagreeEE int
	// Floored counts CVEs per floored axis, C, I and A; FlooredAxes counts
	// them by the set of axes floored, "-" for none.
	Floored     [3]int
	FlooredAxes map[string]int
	// ApplicabilityMissing counts CVEs with any cause, NoVector those whose
	// one cause is having no vector at all.
	ApplicabilityMissing, NoVector int
	// V4CVEs and V4OnlyCVEs count CVEs with a v4 vector and with v4 vectors
	// only; V4Vectors their distinct v4 vectors, V4AxisNSubsequentNot those
	// with an axis at N while its subsequent-system metric is not, and
	// V4SubsequentUnread those lacking a subsequent-system metric or giving
	// one off the scale.
	V4CVEs, V4OnlyCVEs, V4Vectors, V4AxisNSubsequentNot, V4SubsequentUnread int
	// The flags per CVE, and the CVEs whose rows disagree on one.
	MaintainerDisputed, SeverityContested, Flagged, SeverityContestedUnavailable, FlagSplit int
}

func noDiffer() map[string]int {
	return map[string]int{"title": 0, "description": 0, "severity": 0, "cvss": 0, "severity source": 0, "vendor severities": 0}
}

// The vens-demo scan of 23/09/2026 and the quickstart's two reports, each
// pinned by the sha256 of its uncompressed bytes.
var committedReports = []struct {
	name, path, sha256 string
	scanner            ReportScanner
	want               reportCounts
}{
	{
		// venslabs/vens-demo at 1dd6971, runs/2026-09-23/scan/scan.json byte for byte, then gzip -n -9.
		"vens-demo scan", "testdata/vens-demo-2026-09-23.trivy.json.gz",
		"afc7d20702f270e4dbd43579c67ea295064f42183a3369baf9d4734a91153514", &TrivyScanner{},
		reportCounts{
			Rows: 162, CVEs: 74, MultiRowCVEs: 40, Differ: noDiffer(),
			NewestTier: map[int]int{2: 3, 3: 55, 4: 9, 0: 7}, DisagreeO: 8, DisagreeEE: 8,
			Floored:              [3]int{29, 26, 28},
			FlooredAxes:          map[string]int{"-": 24, "A": 9, "C": 4, "CA": 11, "CI": 14, "I": 4, "IA": 8},
			ApplicabilityMissing: 7, NoVector: 7,
			V4CVEs: 9, V4OnlyCVEs: 0, V4Vectors: 9, V4AxisNSubsequentNot: 0, V4SubsequentUnread: 0,
			MaintainerDisputed: 6, SeverityContested: 4, Flagged: 7, SeverityContestedUnavailable: 0, FlagSplit: 0,
		},
	},
	{
		"quickstart Trivy report", "../../examples/quickstart/reports/python-slim.trivy.json",
		"edc8fede08021d458c6721ea2ed4d137bf23a2162627c796a243872353ebdbf9", &TrivyScanner{},
		reportCounts{
			Rows: 107, CVEs: 45, MultiRowCVEs: 34, Differ: noDiffer(),
			NewestTier: map[int]int{2: 3, 3: 37, 0: 5}, DisagreeO: 4, DisagreeEE: 3,
			Floored:              [3]int{20, 21, 18},
			FlooredAxes:          map[string]int{"-": 12, "A": 4, "C": 1, "CA": 7, "CI": 12, "I": 2, "IA": 7},
			ApplicabilityMissing: 5, NoVector: 5,
			V4CVEs: 0, V4OnlyCVEs: 0, V4Vectors: 0, V4AxisNSubsequentNot: 0, V4SubsequentUnread: 0,
			MaintainerDisputed: 5, SeverityContested: 4, Flagged: 6, SeverityContestedUnavailable: 0, FlagSplit: 0,
		},
	},
	{
		"quickstart Grype report", "../../examples/quickstart/reports/python-slim.grype.json",
		"b3b9f2b05646e6ece49ea7c27e52dd27a38949140f2355ff4eb77f1ede215b2d", &GrypeScanner{},
		reportCounts{
			Rows: 77, CVEs: 33, MultiRowCVEs: 20, Differ: noDiffer(),
			NewestTier: map[int]int{2: 3, 3: 21, 4: 7, 0: 2}, DisagreeO: 1, DisagreeEE: 2,
			Floored:              [3]int{14, 13, 20},
			FlooredAxes:          map[string]int{"-": 6, "A": 5, "CA": 9, "CI": 5, "I": 2, "IA": 6},
			ApplicabilityMissing: 2, NoVector: 2,
			V4CVEs: 7, V4OnlyCVEs: 5, V4Vectors: 8, V4AxisNSubsequentNot: 0, V4SubsequentUnread: 0,
			MaintainerDisputed: 5, SeverityContested: 5, Flagged: 7, SeverityContestedUnavailable: 5, FlagSplit: 0,
		},
	},
}

func TestCommittedReports_Step3Counts(t *testing.T) {
	for _, r := range committedReports {
		t.Run(r.name, func(t *testing.T) {
			data := readReport(t, r.path)
			if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != r.sha256 {
				t.Fatalf("%s is not the report these counts were taken from: sha256 %x", r.path, sum)
			}
			rows, err := r.scanner.Parse(data)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := countReport(rows); !reflect.DeepEqual(got, r.want) {
				t.Errorf("counts\n got %+v\nwant %+v", got, r.want)
			}
		})
	}
}

// readReport returns a report's bytes, uncompressed when it is gzipped.
func readReport(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.HasSuffix(path, ".gz") {
		return data
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gunzip %s: %v", path, err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip %s: %v", path, err)
	}
	if err := zr.Close(); err != nil {
		t.Fatalf("gunzip %s: %v", path, err)
	}
	return raw
}

func groupByCVE(rows []generator.Vulnerability) [][]generator.Vulnerability {
	var ids []string
	byID := make(map[string][]generator.Vulnerability)
	for _, r := range rows {
		if _, seen := byID[r.VulnID]; !seen {
			ids = append(ids, r.VulnID)
		}
		byID[r.VulnID] = append(byID[r.VulnID], r)
	}
	cves := make([][]generator.Vulnerability, len(ids))
	for i, id := range ids {
		cves[i] = byID[id]
	}
	return cves
}

func countReport(rows []generator.Vulnerability) reportCounts {
	c := reportCounts{Rows: len(rows), Differ: noDiffer(), NewestTier: map[int]int{}, FlooredAxes: map[string]int{}}
	for _, cve := range groupByCVE(rows) {
		c.CVEs++
		if len(cve) > 1 {
			c.MultiRowCVEs++
			countDiffer(c.Differ, cve)
		}
		var vectors []cvss.Vector
		for _, r := range cve {
			vectors = append(vectors, r.CVSS...)
		}
		countTiers(&c, vectors)

		a := generator.CVEApplicability(cve)
		axes := ""
		for i, name := range []string{"C", "I", "A"} {
			if a.Floored[i] {
				c.Floored[i]++
				axes += name
			}
		}
		if axes == "" {
			axes = "-"
		}
		c.FlooredAxes[axes]++
		if len(a.Missing) > 0 {
			c.ApplicabilityMissing++
		}
		if reflect.DeepEqual(a.Missing, []cvss.Missing{{Cause: cvss.NoVector}}) {
			c.NoVector++
		}

		f := generator.CVEFlags(cve)
		c.MaintainerDisputed += btoi(f.MaintainerDisputed)
		c.SeverityContested += btoi(f.SeverityContested)
		c.Flagged += btoi(f.Flagged())
		c.SeverityContestedUnavailable += btoi(f.SeverityContestedUnavailable)
		for _, r := range cve[1:] {
			if r.Flags.MaintainerDisputed != cve[0].Flags.MaintainerDisputed || r.Flags.SeverityContested != cve[0].Flags.SeverityContested {
				c.FlagSplit++
				break
			}
		}
	}
	return c
}

func countDiffer(differ map[string]int, cve []generator.Vulnerability) {
	fields := map[string]func(generator.Vulnerability) any{
		"title":             func(r generator.Vulnerability) any { return r.Title },
		"description":       func(r generator.Vulnerability) any { return r.Description },
		"severity":          func(r generator.Vulnerability) any { return r.Severity },
		"cvss":              func(r generator.Vulnerability) any { return r.CVSS },
		"severity source":   func(r generator.Vulnerability) any { return r.SeveritySource },
		"vendor severities": func(r generator.Vulnerability) any { return r.VendorSeverities },
	}
	for name, field := range fields {
		for _, r := range cve[1:] {
			if !reflect.DeepEqual(field(r), field(cve[0])) {
				differ[name]++
				break
			}
		}
	}
}

var (
	opportunityMetrics   = []string{"AV", "AT", "PR", "UI"}
	easeOfExploitMetrics = []string{"AC", "AT", "PR", "UI"}
	subsequent           = [3][2]string{{"VC", "SC"}, {"VI", "SI"}, {"VA", "SA"}}
)

func countTiers(c *reportCounts, vectors []cvss.Vector) {
	var distinct []cvss.Vector
	for _, v := range vectors {
		if !slices.Contains(distinct, v) {
			distinct = append(distinct, v)
		}
	}
	newest := cvss.Newest(distinct)
	c.NewestTier[newest]++

	var top []cvss.Metrics
	v4, v4Only := 0, len(distinct) > 0
	for _, v := range distinct {
		m, _ := v.Parse()
		if v.Tier() == newest {
			top = append(top, m)
		}
		if v.Tier() != 4 {
			v4Only = false
			continue
		}
		v4++
		axisNSubsequentNot, subsequentUnread := false, false
		for _, pair := range subsequent {
			value, _ := m.Get(pair[0])
			s, ok := m.Get(pair[1])
			axisNSubsequentNot = axisNSubsequentNot || (value == "N" && s != "N")
			subsequentUnread = subsequentUnread || !ok
		}
		c.V4AxisNSubsequentNot += btoi(axisNSubsequentNot)
		c.V4SubsequentUnread += btoi(subsequentUnread)
	}
	if v4 > 0 {
		c.V4CVEs++
		c.V4Vectors += v4
		c.V4OnlyCVEs += btoi(v4Only)
	}
	if newest > 0 {
		c.DisagreeO += btoi(disagree(top, opportunityMetrics))
		c.DisagreeEE += btoi(disagree(top, easeOfExploitMetrics))
	}
}

func disagree(vectors []cvss.Metrics, metrics []string) bool {
	for _, metric := range metrics {
		values := map[string]bool{}
		for _, m := range vectors {
			v, _ := m.Get(metric)
			values[v] = true
		}
		if len(values) > 1 {
			return true
		}
	}
	return false
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
