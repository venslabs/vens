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
	"bytes"
	"context"
	"encoding/json"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/outputhandler"
)

// orderRows holds three CVEs: one on three packages, one on one, and one
// whose two rows share every package identifier and differ in evidence.
var orderRows = []Vulnerability{
	{VulnID: "CVE-2024-0001", PkgName: "pkg-b", InstalledVersion: "1.0", PkgID: "pkg-b@1.0", Description: "d",
		BOMRef: "b1", CVSS: []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")}},
	{VulnID: "CVE-2024-0001", PkgName: "pkg-a", InstalledVersion: "2.0", PkgID: "pkg-a@2.0", FixedVersion: "2.1",
		Description: "d", BOMRef: "a2", CVSS: []cvss.Vector{v31("redhat", "AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N")}},
	{VulnID: "CVE-2024-0001", PkgName: "pkg-a", InstalledVersion: "1.0", PkgID: "pkg-a@1.0", Description: "d", BOMRef: "a1"},
	{VulnID: "CVE-2024-0002", PkgName: "pkg-c", InstalledVersion: "3.0", Description: "d", BOMRef: "c3"},
	{VulnID: "CVE-2024-0003", PkgName: "lib", InstalledVersion: "1", PkgID: "lib@1", BOMRef: "lib",
		Description: "A flaw in lib. NOTE: the vendor disputes this report.", Severity: "LOW", SeveritySource: "debian",
		Flags: Flags{MaintainerDisputed: true}},
	{VulnID: "CVE-2024-0003", PkgName: "lib", InstalledVersion: "1", PkgID: "lib@1", BOMRef: "lib",
		Description: "A flaw in lib, as another source words it.", Severity: "HIGH", SeveritySource: "ubuntu",
		CVSS: []cvss.Vector{v31("ubuntu", "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H")}},
}

// shuffleRows shuffles the rows, then puts the CVEs back in their first-seen
// order of orderRows, each CVE's rows in the shuffled order.
func shuffleRows(r *rand.Rand) []Vulnerability {
	rank := map[string]int{}
	for _, v := range orderRows {
		if _, ok := rank[v.VulnID]; !ok {
			rank[v.VulnID] = len(rank)
		}
	}
	out := slices.Clone(orderRows)
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	slices.SortStableFunc(out, func(a, b Vulnerability) int { return rank[a.VulnID] - rank[b.VulnID] })
	return out
}

// runOrder rates rows and returns every request the model received, as sent,
// and the VEX's vulnerabilities written from the ratings.
func runOrder(t *testing.T, rows []Vulnerability) ([]string, []byte) {
	t.Helper()
	m := &fakeLLM{}
	g := newGen(t, Opts{LLM: m, BatchSize: 10})
	var buf bytes.Buffer
	h := outputhandler.NewCycloneDxVexOutputHandler(&buf, "sbom", 1, "00000000-0000-0000-0000-000000000001", cyclonedx.SpecVersion1_6)
	require.NoError(t, g.GenerateRiskScore(context.Background(), rows, h.HandleVulnRatings))
	require.NoError(t, h.Close())
	var requests []string
	for _, c := range m.calls {
		requests = append(requests, c.req.System+"\x00"+c.req.Human+"\x00"+string(c.req.Schema))
	}
	var vex struct {
		Vulnerabilities json.RawMessage `json:"vulnerabilities"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &vex))
	return requests, vex.Vulnerabilities
}

// Each CVE's rows are read in one order whatever order the scanner wrote
// them in: shuffled, they give the same requests, flags' evidence included,
// and the same VEX, affects included. Rows sharing every package identifier
// are told apart by their whole content.
func TestGenerator_RowOrderIsCanonical(t *testing.T) {
	wantRequests, wantVEX := runOrder(t, orderRows)
	r := rand.New(rand.NewPCG(310, 1))
	for i := range 25 {
		requests, vex := runOrder(t, shuffleRows(r))
		require.Equal(t, wantRequests, requests, "shuffle %d", i)
		require.JSONEq(t, string(wantVEX), string(vex), "shuffle %d", i)
	}
}

// groupVulnsByCVE keeps the CVEs' first-seen order and sorts each CVE's
// rows by package name, installed version, package ID, fixed version and
// BOM-ref, then by their whole content (here "A flaw in lib," before
// "A flaw in lib.").
func TestGroupVulnsByCVE_SortsEachCVEsRows(t *testing.T) {
	groups := groupVulnsByCVE(shuffleRows(rand.New(rand.NewPCG(310, 2))))
	var ids []string
	var keys [][]string
	for _, g := range groups {
		ids = append(ids, g[0].VulnID)
		var k []string
		for _, v := range g {
			k = append(k, v.PkgName+"@"+v.InstalledVersion+"|"+v.SeveritySource)
		}
		keys = append(keys, k)
	}
	require.Equal(t, []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}, ids)
	require.Equal(t, [][]string{
		{"pkg-a@1.0|", "pkg-a@2.0|", "pkg-b@1.0|"},
		{"pkg-c@3.0|"},
		{"lib@1|ubuntu", "lib@1|debian"},
	}, keys)
}
