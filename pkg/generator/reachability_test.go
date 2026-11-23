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
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/riskconfig"
)

func unreachable(selector, value string) riskconfig.ReachabilityEntry {
	return reachabilityEntry(selector, value, false)
}

func reachabilityEntry(selector, value string, reachable bool) riskconfig.ReachabilityEntry {
	e := riskconfig.ReachabilityEntry{Reachable: reachable, Provenance: "review of " + value}
	if selector == "cve" {
		e.CVE = value
	} else {
		e.Component = value
	}
	return e
}

// twoPackages is a CVE the scan lists on two packages.
var twoPackages = contract.CVE{ID: "CVE-2024-0001", Rows: []contract.Row{{PkgName: "libssl3"}, {PkgName: "libcrypto3"}}}

// An entry declaring a CVE unreachable hits it by its id, or by a component
// every package the scan lists for it names, both without regard to case:
// one package of two is not enough. An entry declaring it reachable hits it
// by its id or by any of its packages, and vetoes the status.
func TestDeclared_HitRules(t *testing.T) {
	sameName := contract.CVE{ID: "CVE-2024-0001", Rows: []contract.Row{{PkgName: "openssl", PkgID: "openssl@1"}, {PkgName: "OpenSSL", PkgID: "openssl@2"}}}
	nameless := contract.CVE{ID: "CVE-2024-0001", Rows: []contract.Row{{PkgName: "openssl"}, {PkgID: "openssl@3"}}}
	for name, tc := range map[string]struct {
		entries                []riskconfig.ReachabilityEntry
		cve                    contract.CVE
		unreachable, reachable []int
		published              bool
	}{
		"by the CVE id":                     {[]riskconfig.ReachabilityEntry{unreachable("cve", "CVE-2024-0001")}, twoPackages, []int{0}, nil, true},
		"by the CVE id, in another case":    {[]riskconfig.ReachabilityEntry{unreachable("cve", "cve-2024-0001")}, twoPackages, []int{0}, nil, true},
		"another CVE":                       {[]riskconfig.ReachabilityEntry{unreachable("cve", "CVE-2024-0002")}, twoPackages, nil, nil, false},
		"a component on one package of two": {[]riskconfig.ReachabilityEntry{unreachable("component", "libssl3")}, twoPackages, nil, nil, false},
		"one entry per package":             {[]riskconfig.ReachabilityEntry{unreachable("component", "libssl3"), unreachable("component", "libcrypto3")}, twoPackages, nil, nil, false},
		"a component on every package":      {[]riskconfig.ReachabilityEntry{unreachable("component", "openssl")}, sameName, []int{0}, nil, true},
		"a component past a nameless row":   {[]riskconfig.ReachabilityEntry{unreachable("component", "openssl")}, nameless, nil, nil, false},
		"a component another package names": {[]riskconfig.ReachabilityEntry{unreachable("component", "zlib")}, twoPackages, nil, nil, false},
		"vetoed by the CVE id": {[]riskconfig.ReachabilityEntry{
			unreachable("cve", "CVE-2024-0001"), reachabilityEntry("cve", "CVE-2024-0001", true),
		}, twoPackages, []int{0}, []int{1}, false},
		"vetoed by one of its packages": {[]riskconfig.ReachabilityEntry{
			reachabilityEntry("component", "LIBCRYPTO3", true), unreachable("cve", "CVE-2024-0001"),
		}, twoPackages, []int{1}, []int{0}, false},
		"a reachable entry on another CVE": {[]riskconfig.ReachabilityEntry{
			unreachable("cve", "CVE-2024-0001"), reachabilityEntry("cve", "CVE-2024-0002", true), reachabilityEntry("component", "zlib", true),
		}, twoPackages, []int{0}, nil, true},
		"a reachable entry alone": {[]riskconfig.ReachabilityEntry{reachabilityEntry("cve", "CVE-2024-0001", true)}, twoPackages, nil, []int{0}, false},
		"no entry":                {nil, twoPackages, nil, nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			d := declared(tc.entries, tc.cve)
			assert.Equal(t, tc.unreachable, d.unreachable)
			assert.Equal(t, tc.reachable, d.reachable)
			assert.Equal(t, tc.published, d.analysis() != nil)
			assert.Equal(t, len(tc.unreachable) > 0 && len(tc.reachable) > 0, d.vetoed())
		})
	}
}

// The status is not_affected, code_not_reachable, its detail citing each
// entry that declares it, by its place in the config, its selector and its
// provenance.
func TestDeclared_AnalysisCitesTheEntries(t *testing.T) {
	entries := []riskconfig.ReachabilityEntry{
		{Component: "zlib", Reachable: true, Provenance: "unrelated"},
		{CVE: "CVE-2024-0001", Provenance: "govulncheck 1.1.4, no call path from main"},
		{Component: "openssl", Provenance: "the TLS stack is the platform's, not this package's"},
	}
	c := contract.CVE{ID: "CVE-2024-0001", Rows: []contract.Row{{PkgName: "openssl"}}}
	got := declared(entries, c).analysis()
	require.NotNil(t, got)
	assert.Equal(t, cyclonedx.IASNotAffected, got.State)
	assert.Equal(t, cyclonedx.IAJCodeNotReachable, got.Justification)
	assert.Equal(t, "Declared not reachable by config.yaml reachability[1] (cve: CVE-2024-0001). Provenance: govulncheck 1.1.4, no call path from main\n"+
		"Declared not reachable by config.yaml reachability[2] (component: openssl). Provenance: the TLS stack is the platform's, not this package's", got.Detail)
	assert.Nil(t, got.Response)
	assert.Empty(t, got.FirstIssued)
}

// declaredConfig declares CVE-2024-0001 unreachable by its id and the
// package of CVE-2024-0002 unreachable.
func declaredConfig() *riskconfig.Config {
	cfg := testConfig()
	cfg.Reachability = []riskconfig.ReachabilityEntry{
		{CVE: "CVE-2024-0001", Provenance: "call graph review"},
		{Component: "pkg-b", Provenance: "feature disabled at build time"},
	}
	return cfg
}

// rated runs the generator over vulns under cfg, the model answering through
// m, and returns the ratings, rows in scanner order.
func rated(t *testing.T, cfg *riskconfig.Config, m *fakeLLM, debugDir string, vulns []Vulnerability) []outputhandler.VulnRating {
	t.Helper()
	g := newGen(t, Opts{LLM: m, Config: cfg, DebugDir: debugDir})
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, collect(&emitted)))
	return emitted
}

// declaredVulns are three CVEs: one on two packages, one on pkg-b alone, one
// on pkg-c.
func declaredVulns() []Vulnerability {
	v := testVulns(4)
	v[0].VulnID, v[1].VulnID, v[2].VulnID, v[3].VulnID = "CVE-2024-0001", "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"
	v[0].PkgName, v[1].PkgName, v[2].PkgName, v[3].PkgName = "pkg-a", "pkg-b", "pkg-b", "pkg-c"
	return v
}

// A declared CVE's VEX rows carry not_affected, code_not_reachable, every
// row of it, with the detail; a CVE no entry hits carries no status. The
// model is asked the same questions whatever is declared, and no level, the
// rating included, moves: a status is no severity. answers.json records the
// entries that hit and the status they publish.
func TestGenerator_DeclaredStatusLeavesTheRating(t *testing.T) {
	answers := func(c fakeCall, id string) any {
		switch c.factor {
		case contract.O:
			return "some_access_or_resources_required"
		case contract.EE:
			return "automated_tools_available"
		case contract.M:
			return "high_reward"
		}
		return nil
	}
	plain := &fakeLLM{answer: answers}
	before := rated(t, testConfig(), plain, "", declaredVulns())
	parent := t.TempDir()
	logs := withCapturedLogs(t)
	declaring := &fakeLLM{answer: answers}
	after := rated(t, declaredConfig(), declaring, parent, declaredVulns())

	assert.Equal(t, plain.log(), declaring.log(), "the same questions")
	require.Len(t, after, len(before))
	for i := range after {
		assert.Equal(t, before[i].Rating, after[i].Rating, "%s on %s: the rating", after[i].VulnID, after[i].BOMRef)
		assert.Nil(t, before[i].Analysis)
		switch after[i].VulnID {
		case "CVE-2024-0001":
			require.NotNil(t, after[i].Analysis, after[i].BOMRef)
			assert.Equal(t, cyclonedx.VulnerabilityAnalysis{
				State: cyclonedx.IASNotAffected, Justification: cyclonedx.IAJCodeNotReachable,
				Detail: "Declared not reachable by config.yaml reachability[0] (cve: CVE-2024-0001). Provenance: call graph review",
			}, *after[i].Analysis)
		case "CVE-2024-0002":
			require.NotNil(t, after[i].Analysis)
			assert.Equal(t, "Declared not reachable by config.yaml reachability[1] (component: pkg-b). Provenance: feature disabled at build time", after[i].Analysis.Detail)
		default:
			assert.Nil(t, after[i].Analysis, "%s: silence publishes nothing", after[i].VulnID)
		}
	}
	assert.NotEqual(t, "low", string(after[0].Rating.Severity), "the answers rate it above low, status or not")

	logged := logs.find(slog.LevelInfo, "Declared not reachable; the VEX publishes it not_affected, code_not_reachable, with its rating")
	require.Len(t, logged, 2)
	assert.Equal(t, "reachability[0] (cve: CVE-2024-0001)", logged[0].attrs["entries"])

	got, _ := readAnswers(t, parent)
	records := map[string]string{}
	for _, v := range got.Vulnerabilities {
		if v.Declared == nil {
			records[v.VulnID] = "none"
			continue
		}
		require.NotNil(t, v.Declared.Analysis, v.VulnID)
		records[v.VulnID] = strings.Join([]string{v.Declared.Analysis.State, v.Declared.Analysis.Justification}, " ")
		assert.NotEmpty(t, v.Declared.Unreachable, v.VulnID)
		assert.Empty(t, v.Declared.Reachable, v.VulnID)
	}
	assert.Equal(t, map[string]string{
		"CVE-2024-0001": "not_affected code_not_reachable", "CVE-2024-0002": "not_affected code_not_reachable", "CVE-2024-0003": "none",
	}, records)
}

// A component entry on one package of a CVE listed on two publishes nothing
// for it, and an entry declaring a CVE reachable vetoes one declaring it
// unreachable: no status, a WARN naming both, and answers.json listing both
// without an analysis.
func TestGenerator_DeclaredStatusVetoedOrPartial(t *testing.T) {
	cfg := testConfig()
	cfg.Reachability = []riskconfig.ReachabilityEntry{
		{Component: "pkg-a", Provenance: "pkg-a is never loaded"},
		{CVE: "CVE-2024-0002", Provenance: "call graph review"},
		{Component: "PKG-B", Reachable: true, Provenance: "a fuzzing harness reached it"},
	}
	parent := t.TempDir()
	logs := withCapturedLogs(t)
	emitted := rated(t, cfg, &fakeLLM{}, parent, declaredVulns())
	for _, r := range emitted {
		assert.Nil(t, r.Analysis, "%s on %s", r.VulnID, r.BOMRef)
	}

	warned := logs.find(slog.LevelWarn, "Reachability entries disagree; one asserting reachability vetoes the status, so none is published")
	require.Len(t, warned, 1)
	assert.Equal(t, map[string]any{
		"vuln": "CVE-2024-0002", "unreachable": "reachability[1] (cve: CVE-2024-0002)", "reachable": "reachability[2] (component: PKG-B)",
	}, warned[0].attrs)

	got, _ := readAnswers(t, parent)
	declaredBy := map[string][2][]int{}
	for _, v := range got.Vulnerabilities {
		if v.Declared != nil {
			assert.Nil(t, v.Declared.Analysis, v.VulnID)
			declaredBy[v.VulnID] = [2][]int{v.Declared.Unreachable, v.Declared.Reachable}
		}
	}
	assert.Equal(t, map[string][2][]int{
		"CVE-2024-0001": {nil, {2}},
		"CVE-2024-0002": {{1}, {2}},
	}, declaredBy, "pkg-a covers one package of CVE-2024-0001's two; PKG-B names one of them")
}
