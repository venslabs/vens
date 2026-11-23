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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/riskconfig"
)

func ptr(s string) *string { return &s }

// fullConfig declares a framework and detection at levels that differ, so
// that a CVE no vector floors gets all thirteen questions.
func fullConfig() *riskconfig.Config {
	cfg := testConfig()
	cfg.Context.ComplianceRequirements = []string{"GDPR"}
	cfg.Context.Detection = &riskconfig.DetectionCoverage{Network: "logged", Host: "logged_and_reviewed", Application: "active_in_application"}
	return cfg
}

// A batch asks in the declared order, each question of the CVEs that get
// it, whatever the first CVE's vectors: the order never depends on the first
// CVE's questions, and no call asks Loss of confidentiality, integrity or
// availability. The debug files and the evidence's prompt hashes follow the
// calls.
func TestGenerator_AsksInTheDeclaredOrder(t *testing.T) {
	parent := t.TempDir()
	m := &fakeLLM{}
	g := newGen(t, Opts{LLM: m, Config: fullConfig(), DebugDir: parent})
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	g.SetAttestor(at)

	vulns := testVulns(2)
	vulns[0].CVSS = []cvss.Vector{v31("nvd", noImpact)}
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))

	want := []struct {
		factor string
		ids    []string
	}{
		{"M", []string{"CVE-2024-0000", "CVE-2024-0001"}},
		{"O", []string{"CVE-2024-0000", "CVE-2024-0001"}},
		{"EE", []string{"CVE-2024-0000", "CVE-2024-0001"}},
		{"ID", []string{"CVE-2024-0000", "CVE-2024-0001"}},
		{"LAC", []string{"CVE-2024-0000", "CVE-2024-0001"}},
		{"FD", []string{"CVE-2024-0000", "CVE-2024-0001"}},
		{"RD", []string{"CVE-2024-0000", "CVE-2024-0001"}},
		{"NC", []string{"CVE-2024-0000", "CVE-2024-0001"}},
		{"PV", []string{"CVE-2024-0000", "CVE-2024-0001"}},
	}
	require.Len(t, m.calls, len(want))
	dirs, err := filepath.Glob(filepath.Join(parent, "run-*"))
	require.NoError(t, err)
	require.Len(t, dirs, 1)
	hashes := promptHashes(t, at)
	for i, c := range m.calls {
		assert.Equal(t, want[i].factor, string(c.factor), "call %d", i+1)
		assert.Equal(t, want[i].ids, c.ids, "call %d", i+1)
		human := debugFile(t, dirs[0], i+1, "human.prompt")
		assert.Equal(t, c.req.Human, human, "batch-%05d is call %d", i+1, i+1)
		sum := sha256.Sum256([]byte(c.req.System + "\n\n" + human))
		assert.Equal(t, hex.EncodeToString(sum[:]), hashes[i], "evidence-batch-%d is call %d", i+1, i+1)
	}
}

// Non-compliance is asked only with a framework; Intrusion detection only
// with detection at levels that differ; Privacy violation only when
// data_subjects is unset or caps above 3, whatever the vectors give C. A
// question not asked takes the level Go decides and counts no cannot_tell,
// however every asked question is answered.
func TestGenerator_QuestionsNotAsked(t *testing.T) {
	tests := []struct {
		name     string
		config   func(*riskconfig.Config)
		cvss     []cvss.Vector
		notAsked []string
		levels   map[string]int
		counted  []string
	}{
		{
			name:     "every axis at N",
			cvss:     []cvss.Vector{v31("nvd", noImpact)},
			notAsked: []string{"LC", "LI", "LAV", "ID", "NC"},
			levels:   map[string]int{"LC": 2, "LI": 1, "LAV": 1, "PV": 9},
		},
		{
			name:     "no framework, no detection",
			notAsked: []string{"ID", "NC"},
			levels:   map[string]int{"NC": 2, "ID": 9},
			counted:  []string{"detection_undeclared"},
		},
		{
			name: "detection at one level",
			config: func(c *riskconfig.Config) {
				c.Context.Detection = &riskconfig.DetectionCoverage{Network: "logged", Host: "logged", Application: "logged"}
			},
			notAsked: []string{"ID", "NC"},
			levels:   map[string]int{"ID": 8},
		},
		{
			name:     "data_subjects none",
			config:   func(c *riskconfig.Config) { c.Context.DataSubjects = ptr("none") },
			notAsked: []string{"PV", "ID", "NC"},
			levels:   map[string]int{"PV": 3},
		},
		{
			name:     "data_subjects one_individual",
			config:   func(c *riskconfig.Config) { c.Context.DataSubjects = ptr("one_individual") },
			notAsked: []string{"PV", "ID", "NC"},
			levels:   map[string]int{"PV": 3},
		},
		{
			name:     "data_subjects hundreds",
			config:   func(c *riskconfig.Config) { c.Context.DataSubjects = ptr("hundreds") },
			notAsked: []string{"ID", "NC"},
			levels:   map[string]int{"PV": 5},
		},
		{
			name: "a framework and detection at levels that differ",
			config: func(c *riskconfig.Config) {
				*c = *fullConfig()
			},
			levels: map[string]int{"NC": 7, "ID": 8},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			if tt.config != nil {
				tt.config(cfg)
			}
			logs := withCapturedLogs(t)
			m := &fakeLLM{answer: func(c fakeCall, _ string) any {
				if c.factor == contract.ID {
					return []string{cannotTell}
				}
				return cannotTell
			}}
			g := newGen(t, Opts{LLM: m, Config: cfg})
			vulns := testVulns(1)
			vulns[0].CVSS = tt.cvss
			var emitted []outputhandler.VulnRating
			require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, collect(&emitted)))

			asked := m.log()
			for _, f := range tt.notAsked {
				assert.NotContains(t, asked, f, "question %s is not asked", f)
			}
			for f, want := range tt.levels {
				assert.Equal(t, want, vectorLevel(t, emitted[0].Rating.Vector, f), "%s's level", f)
			}
			summary := runSummary(t, logs)
			for _, f := range asked {
				assert.Equal(t, int64(1), summary.attrs["counters."+contract.Factor(f).Counter()], "asked %s counts its cannot_tell", f)
			}
			for _, f := range tt.notAsked {
				assert.NotContains(t, summary.attrs, "counters."+contract.Factor(f).Counter(), "%s, not asked, counts no cannot_tell", f)
			}
			for _, name := range tt.counted {
				assert.Equal(t, int64(1), summary.attrs["counters."+name])
			}
		})
	}
}

// Loss of confidentiality, integrity and availability come from the CVE's
// own vectors, every vector of every row, the worst value per axis, and from
// no answer: no call asks them, and Privacy violation is asked whatever the
// vectors give C. A CVE with no vector takes 9 for each, counted once.
func TestGenerator_TechnicalImpactsFromTheCVEsOwnVectors(t *testing.T) {
	logs := withCapturedLogs(t)
	vulns := []Vulnerability{
		{VulnID: "CVE-2024-0001", PkgName: "a", Description: "d", BOMRef: "a1", CVSS: []cvss.Vector{v31("nvd", noImpact)}},
		{VulnID: "CVE-2024-0001", PkgName: "b", Description: "d", BOMRef: "a2", CVSS: []cvss.Vector{v31("redhat", noImpact)}},
		{VulnID: "CVE-2024-0002", PkgName: "a", Description: "d", BOMRef: "b1", CVSS: []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H")}},
		{VulnID: "CVE-2024-0002", PkgName: "b", Description: "d", BOMRef: "b2", CVSS: []cvss.Vector{v31("redhat", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N")}},
		{VulnID: "CVE-2024-0003", PkgName: "a", Description: "d", BOMRef: "c1"},
	}
	m := &fakeLLM{answer: func(c fakeCall, _ string) any {
		if c.factor == contract.PV {
			return "millions"
		}
		return nil
	}}
	g := newGen(t, Opts{LLM: m})
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, collect(&emitted)))

	assert.Equal(t, []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}, m.of(contract.PV)[0].ids)
	got := byID(emitted)
	for id, want := range map[string]map[string]int{
		"CVE-2024-0001": {"LC": 2, "LI": 1, "LAV": 1, "PV": 9},
		"CVE-2024-0002": {"LC": 7, "LI": 3, "LAV": 7, "PV": 9},
		"CVE-2024-0003": {"LC": 9, "LI": 9, "LAV": 9, "PV": 9},
	} {
		for f, level := range want {
			assert.Equal(t, level, vectorLevel(t, got[id].Rating.Vector, f), "%s %s", id, f)
		}
	}
	assert.Equal(t, int64(1), runSummary(t, logs).attrs["counters.cvss_v3_missing"])
	warned := logs.find(slog.LevelWarn, "No usable CVSS v3 vector in the scanner's report; Loss of confidentiality, integrity and availability take their worst level")
	require.Len(t, warned, 1)
	assert.Equal(t, "CVE-2024-0003", warned[0].attrs["vulns"])
}

// An answer off the list, which only a provider ignoring the schema can
// give, reads as cannot_tell: the worst case, counted, and logged at WARN
// with the value as the reply wrote it. It is not asked again.
func TestGenerator_InvalidAnswerReadsCannotTell(t *testing.T) {
	logs := withCapturedLogs(t)
	m := &fakeLLM{answer: func(c fakeCall, id string) any {
		if c.factor != contract.EE {
			return nil
		}
		if id == "CVE-2024-0000" {
			return "bogus"
		}
		return 7
	}}
	g := newGen(t, Opts{LLM: m})
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), collect(&emitted)))

	for _, r := range emitted {
		assert.Equal(t, 9, vectorLevel(t, r.Rating.Vector, "EE"), r.VulnID)
	}
	warned := map[string]any{}
	for _, r := range logs.find(slog.LevelWarn, "Model gave an answer off the list; reading it as cannot_tell") {
		assert.Equal(t, "EE", r.attrs["question"])
		warned[r.attrs["vuln"].(string)] = r.attrs["answer"]
	}
	assert.Equal(t, map[string]any{"CVE-2024-0000": `"bogus"`, "CVE-2024-0001": "7"}, warned)
	assert.Len(t, m.of(contract.EE), 1, "an invalid answer is an answer: no ask-again")
	assert.Equal(t, int64(2), runSummary(t, logs).attrs["counters.ease_of_exploit_cannot_tell"])
}

// Intrusion detection's reply is a set: a channel listed twice counts once,
// and an empty set, one holding cannot_tell, one with an id off the list or
// a value that is no list read as cannot_tell, the worst declared level.
func TestGenerator_IntrusionDetectionReplies(t *testing.T) {
	logs := withCapturedLogs(t)
	replies := map[string]any{
		"CVE-2024-0000": []string{"network", "network"},
		"CVE-2024-0001": []string{},
		"CVE-2024-0002": []string{cannotTell, "host"},
		"CVE-2024-0003": []string{"bogus"},
		"CVE-2024-0004": "network",
		"CVE-2024-0005": []string{"host", "application"},
	}
	m := &fakeLLM{answer: func(c fakeCall, id string) any {
		if c.factor == contract.ID {
			return replies[id]
		}
		return nil
	}}
	g := newGen(t, Opts{LLM: m, Config: fullConfig()})
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(6), collect(&emitted)))

	got := byID(emitted)
	for id, want := range map[string]int{
		"CVE-2024-0000": 8, "CVE-2024-0001": 8, "CVE-2024-0002": 8,
		"CVE-2024-0003": 8, "CVE-2024-0004": 8, "CVE-2024-0005": 1,
	} {
		assert.Equal(t, want, vectorLevel(t, got[id].Rating.Vector, "ID"), id)
	}
	assert.Equal(t, int64(4), runSummary(t, logs).attrs["counters.intrusion_detection_cannot_tell"])
	var warned []string
	for _, r := range logs.find(slog.LevelWarn, "Model gave an answer off the list; reading it as cannot_tell") {
		warned = append(warned, r.attrs["vuln"].(string))
	}
	assert.ElementsMatch(t, []string{"CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0004"}, warned)
}

// A CVE whose rows disagree is one entry that writes each differing field per
// package; Applicability reads every vector, the CVSS lines show every
// source's, two distinct vectors of one source and version included; a flag
// raised by one row sends the CVE to the adjustment, whose entry lists every
// row's evidence.
func TestGenerator_ConflictingRows(t *testing.T) {
	vulns := []Vulnerability{
		{
			VulnID: "CVE-2024-0007", PkgName: "liba", InstalledVersion: "1", Title: "t", Description: "The parser overflows.",
			Severity: "LOW", SeveritySource: "debian", BOMRef: "a",
			VendorSeverities: []VendorSeverity{{Source: "debian", Severity: "LOW"}, {Source: "nvd", Severity: "HIGH"}},
			CVSS:             []cvss.Vector{v31("nvd", noImpact)},
		},
		{
			VulnID: "CVE-2024-0007", PkgName: "libb", InstalledVersion: "2", Title: "t",
			Description: "The parser overflows. NOTE: the vendor disputes this report.",
			Severity:    "MEDIUM", SeveritySource: "redhat", BOMRef: "b",
			VendorSeverities: []VendorSeverity{{Source: "redhat", Severity: "MEDIUM"}},
			CVSS:             []cvss.Vector{v31("nvd", "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), v31("redhat", "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H")},
			Flags:            Flags{MaintainerDisputed: true},
		},
	}
	m := &fakeLLM{}
	g := newGen(t, Opts{LLM: m})
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))

	entry := requestEntries(t, m.of(contract.M)[0].req.Human)[0]
	assert.NotContains(t, entry, "description")
	assert.NotContains(t, entry, "severity")
	assert.Equal(t, "t", entry["title"])
	packages := entry["packages"].([]any)
	require.Len(t, packages, 2)
	assert.Equal(t, "The parser overflows.", packages[0].(map[string]any)["description"])
	assert.Equal(t, "MEDIUM", packages[1].(map[string]any)["severity"])

	assert.Equal(t, append(append([]string{}, questionsUndeclared...), adjustmentCall), m.log(),
		"whatever the vectors give C, I and A, no call asks them")
	for _, line := range []string{
		"- CVE-2024-0007: CVSS 3.1, nvd: AV:N PR:N UI:N",
		"- CVE-2024-0007: CVSS 3.1, nvd: AV:L PR:L UI:N",
		"- CVE-2024-0007: CVSS 3.1, redhat: AV:N PR:N UI:R",
	} {
		assert.Contains(t, m.of(contract.O)[0].req.Human, line+"\n")
	}

	adjustment := m.calls[len(m.calls)-1]
	assert.Equal(t, map[string][]string{
		"opportunity": {"no_access_or_resources_required", "some_access_or_resources_required", "special_access_or_resources_required", "full_access_or_expensive_resources_required", "keep", cannotTell},
	}, adjustment.fields)
	var shown struct {
		Packages []struct {
			Name           string `json:"name"`
			SeveritySource string `json:"severitySource"`
		} `json:"packages"`
		VendorSeverity []struct {
			Source   string   `json:"source"`
			Packages []string `json:"packages"`
		} `json:"vendorSeverity"`
		CVSS  []cvss.Vector `json:"cvss"`
		Flags []struct {
			Flag, Evidence, Package string
		} `json:"flags"`
	}
	require.NoError(t, json.Unmarshal([]byte(strings.Split(adjustment.req.Human, "\n")[1]), &shown))
	assert.Equal(t, "debian", shown.Packages[0].SeveritySource)
	assert.Equal(t, "redhat", shown.Packages[1].SeveritySource)
	assert.Len(t, shown.VendorSeverity, 3)
	assert.Len(t, shown.CVSS, 3, "every distinct vector of every row")
	require.Len(t, shown.Flags, 1)
	assert.Equal(t, "libb", shown.Flags[0].Package)
	assert.Equal(t, "NOTE: the vendor disputes this report.", shown.Flags[0].Evidence)
}

// A v3 vector Trivy gives without its prefix keeps its version, so the CVSS
// lines show it as the newest beside a v2 vector instead of hiding it.
func TestGenerator_UnprefixedV3VectorShownBesideV2(t *testing.T) {
	vulns := testVulns(1)
	vulns[0].CVSS = []cvss.Vector{
		{Source: "nvd", Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
		{Source: "nvd", Version: "3", Vector: "AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:N"},
	}
	m := &fakeLLM{}
	g := newGen(t, Opts{LLM: m})
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))
	request := m.of(contract.O)[0].req.Human
	assert.Contains(t, request, "- CVE-2024-0000: CVSS 3, nvd: AV:N PR:L UI:N\n")
	assert.NotContains(t, request, "CVSS 2.0")
}

// A key an answer writes twice, at any depth, leaves the answer in doubt,
// where encoding/json would keep the last value without a word: it reads as
// cannot_tell, counted and logged with the answer's text, as an answer off
// the list, and answers.json and the claim show every answer it wrote. An
// answer without one reads as before.
func TestGenerator_KeyWrittenTwiceReadsCannotTell(t *testing.T) {
	const (
		twice  = `{"vulnId":"CVE-2024-0000","answer":"cannot_tell","answer":"low_or_no_reward","reasoning":"r0"}`
		nested = `{"vulnId":"CVE-2024-0001","answer":"low_or_no_reward","reasoning":"r1","detail":{"why":[{"a":1,"a":2}]}}`
		once   = `{"vulnId":"CVE-2024-0002","answer":"low_or_no_reward","reasoning":"r2"}`
	)
	logs := withCapturedLogs(t)
	parent := t.TempDir()
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	m := &fakeLLM{reply: func(c fakeCall) (string, bool) {
		return `{"answers":[` + twice + "," + nested + "," + once + `]}`, c.factor == contract.M
	}}
	g := newGen(t, Opts{LLM: m, DebugDir: parent})
	g.SetAttestor(at)
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(3), collect(&emitted)))

	got := byID(emitted)
	for id, want := range map[string]int{"CVE-2024-0000": 9, "CVE-2024-0001": 9, "CVE-2024-0002": 1} {
		assert.Equal(t, want, vectorLevel(t, got[id].Rating.Vector, "M"), id)
	}
	warned := map[string]any{}
	for _, r := range logs.find(slog.LevelWarn, "Model wrote a key twice; reading the answer as cannot_tell") {
		assert.Equal(t, "M", r.attrs["question"])
		warned[r.attrs["vuln"].(string)] = r.attrs["entry"]
	}
	assert.Equal(t, map[string]any{"CVE-2024-0000": twice, "CVE-2024-0001": nested}, warned)
	assert.Empty(t, logs.find(slog.LevelWarn, "Model gave an answer off the list; reading it as cannot_tell"))
	assert.Len(t, m.of(contract.M), 1, "an answer in doubt is an answer: no ask-again")
	assert.Equal(t, int64(2), runSummary(t, logs).attrs["counters."+contract.M.Counter()])

	answers, _ := readAnswers(t, parent)
	written := map[string][]any{}
	for _, v := range answers.Vulnerabilities {
		for _, f := range v.Factors {
			if f.Factor == "M" {
				written[v.VulnID] = []any{f.Answer, f.Reading}
			}
		}
	}
	assert.Equal(t, map[string][]any{
		"CVE-2024-0000": {[]any{"cannot_tell", "low_or_no_reward"}, "invalid"},
		"CVE-2024-0001": {[]any{"low_or_no_reward"}, "invalid"},
		"CVE-2024-0002": {"low_or_no_reward", "answered"},
	}, written)
	assert.Equal(t, `M (["cannot_tell","low_or_no_reward"]): r0`, strings.Split(claims(t, at)[0].Reasoning, "\n")[0])
}

// A key written twice outside every answer leaves them all in doubt. Here
// the reply writes its list twice and encoding/json keeps the second alone:
// its answer reads as cannot_tell, and the CVE only the first list answers
// is asked again.
func TestGenerator_KeyWrittenTwiceOutsideTheAnswers(t *testing.T) {
	const reply = `{"answers":[{"vulnId":"CVE-2024-0001","answer":"high_reward","reasoning":"r"}],` +
		`"answers":[{"vulnId":"CVE-2024-0000","answer":"low_or_no_reward","reasoning":"r"}]}`
	logs := withCapturedLogs(t)
	m := &fakeLLM{reply: func(c fakeCall) (string, bool) { return reply, c.factor == contract.M && len(c.ids) > 1 }}
	g := newGen(t, Opts{LLM: m})
	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), collect(&emitted)))

	got := byID(emitted)
	assert.Equal(t, 9, vectorLevel(t, got["CVE-2024-0000"].Rating.Vector, "M"))
	assert.Equal(t, 1, vectorLevel(t, got["CVE-2024-0001"].Rating.Vector, "M"), "the fake's answer when asked again")
	assert.Equal(t, []int{2, 1}, sizes(m.of(contract.M)))
	warned := logs.find(slog.LevelWarn, "Model wrote a key twice outside its answers; reading each as cannot_tell")
	require.Len(t, warned, 1)
	assert.Equal(t, reply, warned[0].attrs["reply"])
	assert.Len(t, logs.find(slog.LevelWarn, "Model wrote a key twice; reading the answer as cannot_tell"), 1)
}

func TestRepeatedKeys(t *testing.T) {
	for text, want := range map[string]int{
		`{"a":1,"b":2}`:                     0,
		`{"a":1,"a":2}`:                     1,
		`{"a":1,"a":2,"a":3}`:               2,
		`{"a":{"b":1,"b":2}}`:               1,
		`[{"a":1},{"a":2}]`:                 0,
		`{"a":[{"b":1,"b":2}],"c":{"b":3}}`: 1,
		`{"a":1,"\u0061":2}`:                1,
		`{"a":"{\"b\":1,\"b\":2}"}`:         0,
		`{"a":1e400,"a":2}`:                 1,
		`"a"`:                               0,
		`not json`:                          0,
	} {
		assert.Equal(t, want, repeatedKeys([]byte(text)), text)
	}
}

func promptHashes(t *testing.T, at *attestation.Builder) []string {
	t.Helper()
	var hashes []string
	for _, c := range attestedCalls(t, at) {
		hashes = append(hashes, c.promptHash)
	}
	return hashes
}

func debugFile(t *testing.T, dir string, call int, ext string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, debugName(call)+"."+ext))
	require.NoError(t, err)
	return string(b)
}
