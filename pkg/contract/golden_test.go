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

package contract

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/riskconfig"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata from what the renderers write")

// meant is a value the frames show with the meaning the config's one table
// documents for it, the table docs/reference/config-schema.md is checked
// against.
func meant(field riskconfig.Field, value string) Setting {
	return Setting{Value: value, Meaning: field.Meaning(value)}
}

// config builds a deployment from its values: the three required settings
// at one level, as the vens-demo contexts and the quickstart declare them.
func config(name, description, exposure, level, listener, notes string, frameworks []string, controls ...string) Deployment {
	d := Deployment{
		Name:                name,
		Description:         description,
		Notes:               notes,
		Exposure:            meant(riskconfig.Exposure, exposure),
		Listener:            meant(riskconfig.Listener, listener),
		BusinessCriticality: meant(riskconfig.BusinessCriticality, level),
		DataSensitivity:     meant(riskconfig.DataSensitivity, level),
		Frameworks:          frameworks,
	}
	scopes := riskconfig.ControlScopes()
	for _, key := range controls {
		i := slices.IndexFunc(scopes, func(c riskconfig.Control) bool { return c.Key == key })
		d.Controls = append(d.Controls, Control{Key: key, Description: scopes[i].Description, Scope: scopes[i].Scope})
	}
	return d
}

// The vens-demo contexts (vens-demo 1dd6971, contexts/) and the quickstart
// config, with the listener their notes give and the controls Ease of
// exploit shows: ids, siem and edr move nothing and are left out.
var frameConfigs = []struct {
	name       string
	deployment Deployment
}{
	{
		name: "internal",
		deployment: config("nightly-report", "Internal batch job producing an aggregated sales report",
			"internal", "low", "absent",
			"No ingress and no listening socket. Runs once a night, reads a pre-validated CSV from an internal bucket, writes an aggregate to a private database, then exits.",
			nil, "segmentation"),
	},
	{
		name: "internal-api",
		deployment: config("stock-api", "Internal REST API that warehouse and support tools query for stock levels",
			"internal", "medium", "present",
			"Listens on HTTP on the corporate network only: reachable from every employee workstation and internal service, no route from the internet. Callers are not authenticated, so any host on the corporate network can send requests, and the service parses their JSON.",
			nil, "segmentation"),
	},
	{
		name: "internet-facing",
		deployment: config("checkout-api", "Public checkout API handling card payments for the storefront",
			"internet", "critical", "present",
			"Accepts unauthenticated traffic on the payment initiation route and parses attacker-controlled JSON.",
			[]string{"PCI-DSS", "GDPR"}, "waf", "ddos_protection", "segmentation"),
	},
	{
		name: "quickstart",
		deployment: config("python-backend-api", "Python 3.11 backend API service handling customer data",
			"internet", "high", "present",
			"Customer-facing REST API built with FastAPI/Flask running on Python 3.11-slim (Debian). Handles authentication, user data, and payment processing. Uses PostgreSQL database. Deployed in Kubernetes behind load balancer. Container runs as non-root user. SSL/TLS terminated at load balancer. Rate limiting and input validation implemented. Regular security patches applied monthly.",
			[]string{"GDPR", "SOC2"}, "waf", "ddos_protection", "segmentation"),
	},
}

// The two CVEs every frame asks about, as their CVSS lines show them. The
// frames elide the entries.
var frameBatch = []CVE{
	{ID: "CVE-A", Rows: []Row{{PkgName: "libexample", InstalledVersion: "1.0.0", Severity: "HIGH",
		CVSS: []cvss.Vector{v31("nvd", "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")}}}},
	{ID: "CVE-B", Rows: []Row{{PkgName: "libexample", InstalledVersion: "1.0.0", Severity: "MEDIUM",
		CVSS: []cvss.Vector{v31("redhat", "AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H")}}}},
}

// frameFlagged is the flagged CVE whose adjustment the frames show. A row
// describes it: one no row describes is not asked Opportunity.
var frameFlagged = CVE{ID: "CVE-F", Rows: []Row{{PkgName: "libexample", InstalledVersion: "1.0.0", Severity: "LOW",
	Description:      "A crafted request overflows the parser. NOTE: the maintainer disputes it.",
	CVSS:             []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")},
	VendorSeverities: []VendorSeverity{{Source: "nvd", Severity: "HIGH"}}}}}

var frameFlags = []Flag{{Name: MaintainerDisputed, Evidence: "...", Package: "libexample"}}

var frameGiven = Answers{O: "some_access_or_resources_required"}

// frameNumbers keeps each question's file number from the 12 questions of
// b7c0435, so that a frame keeps its name: Loss of confidentiality, integrity
// and availability, 05 to 07, are no longer asked.
var frameNumbers = map[Factor]int{M: 1, O: 2, EE: 3, ID: 4, LAC: 8, FD: 9, RD: 10, NC: 11, PV: 12}

// elide replaces the one occurrence of part in text by its placeholder.
func elide(t *testing.T, text, part, placeholder string) string {
	t.Helper()
	if n := strings.Count(text, part); n != 1 {
		t.Fatalf("the text holds %d copies of the part to elide, want 1", n)
	}
	return strings.Replace(text, part, placeholder, 1)
}

// frames renders what one deployment sends, file by file: the system prompt,
// each question's request and schema over the two CVEs, Non-compliance's
// only with a framework, and a flagged CVE's adjustment. The CVE entries are
// elided.
func frames(t *testing.T, d Deployment) map[string]string {
	t.Helper()
	text, data := text(t), data(t)
	out := map[string]string{"00-system.txt": text(SystemPrompt(d))}
	entries := text(entriesJSON(frameBatch))
	for _, f := range Order() {
		if f == NC && len(d.Frameworks) == 0 {
			continue
		}
		name := fmt.Sprintf("%02d-%s", frameNumbers[f], f)
		out[name+".request.txt"] = elide(t, text(Request(f, d, frameBatch)), entries, "[entries]")
		out[name+".schema.json"] = data(Schema(f, []string{"CVE-A", "CVE-B"}))
	}
	request := text(AdjustmentRequest(d, frameFlagged, frameFlags, frameGiven))
	e, err := newAdjustmentEntry(frameFlagged, frameFlags, frameGiven)
	if err != nil {
		t.Fatal(err)
	}
	out["13-adjustment.request.txt"] = elide(t, request, data(json.Marshal(e)), "[entry]")
	out["13-adjustment.schema.json"] = data(AdjustmentSchema(frameFlagged))
	return out
}

// readLF reads a text file as committed: a Windows checkout turns its LF
// into CRLF.
func readLF(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// checkGolden compares a rendered text, newline-terminated, with its golden
// file, or writes the file under -update.
func checkGolden(t *testing.T, path, got string) {
	t.Helper()
	got += "\n"
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if want := readLF(t, path); got != want {
		t.Errorf("%s: the renderers no longer write it (go test -update rewrites it):\n%s", path, firstDiff(want, got))
	}
}

func firstDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := range max(len(w), len(g)) {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return fmt.Sprintf("line %d\n  golden: %q\n  now:    %q", i+1, wl, gl)
		}
	}
	return "no line differs"
}

// checkGoldenDir checks every rendered file of a directory and that it holds
// no other file. Under -update it removes the others.
func checkGoldenDir(t *testing.T, dir string, rendered map[string]string) {
	t.Helper()
	for _, name := range slices.Sorted(maps.Keys(rendered)) {
		checkGolden(t, filepath.Join(dir, name), rendered[name])
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if _, ok := rendered[f.Name()]; ok {
			continue
		}
		if *update {
			if err := os.Remove(filepath.Join(dir, f.Name())); err != nil {
				t.Fatal(err)
			}
			continue
		}
		t.Errorf("%s: no renderer writes it", filepath.Join(dir, f.Name()))
	}
}

func TestGoldenFrames(t *testing.T) {
	for _, c := range frameConfigs {
		t.Run(c.name, func(t *testing.T) {
			checkGoldenDir(t, filepath.Join("testdata", c.name), frames(t, c.deployment))
		})
	}
}

// The parts the reference frames elide, written out: a batch's entries, its
// first CVE's rows disagreeing, with the CVSS lines of each version, and the
// adjustment's entry of that CVE.
func TestGoldenEntries(t *testing.T) {
	var d Deployment
	for _, c := range frameConfigs {
		if c.name == "internet-facing" {
			d = c.deployment
		}
	}
	flags := []Flag{{Name: MaintainerDisputed, Evidence: "the maintainer disputes it", Package: "libfoo-dev"}}
	checkGoldenDir(t, filepath.Join("testdata", "conflicting-rows"), map[string]string{
		"02-O.request.txt":          text(t)(Request(O, d, cvssBatch)),
		"13-adjustment.request.txt": text(t)(AdjustmentRequest(d, conflicting, flags, frameGiven)),
	})
}

// testdata/SHA256SUMS pins the sha256 of each golden frame of the four
// deployments, as the reference frames reviewed before this code gave them.
// -update leaves the sums alone, so a prompt change updates them on purpose,
// in the same review as the frames.
func TestGoldenFramesMatchPinnedSums(t *testing.T) {
	sums := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(readLF(t, filepath.Join("testdata", "SHA256SUMS"))))
	for scanner.Scan() {
		sum, path, ok := strings.Cut(scanner.Text(), "  ")
		if !ok {
			t.Fatalf("SHA256SUMS line %q is not `sum  path`", scanner.Text())
		}
		sums[path] = sum
	}
	seen := 0
	for _, c := range frameConfigs {
		files, err := os.ReadDir(filepath.Join("testdata", c.name))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			path := c.name + "/" + f.Name()
			sum := sha256.Sum256([]byte(readLF(t, filepath.Join("testdata", c.name, f.Name()))))
			if got := hex.EncodeToString(sum[:]); got != sums[path] {
				t.Errorf("%s: sha256 %s, pinned %q", path, got, sums[path])
			}
			seen++
		}
	}
	if seen != len(sums) {
		t.Errorf("%d golden frames, SHA256SUMS lists %d", seen, len(sums))
	}
}
