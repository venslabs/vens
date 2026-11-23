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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/internal/testutil"
	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/outputhandler"
)

func debugName(call int) string { return fmt.Sprintf("batch-%05d", call) }

// runDirs lists the run-* directories under a --debug-dir.
func runDirs(t *testing.T, parent string) []string {
	t.Helper()
	dirs, err := filepath.Glob(filepath.Join(parent, "run-*"))
	require.NoError(t, err)
	return dirs
}

func fileNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return names
}

// fileSets lists the debug files of calls 1 to n, each with a response but
// those in noResponse, and answers.json, sorted as a directory lists them.
func fileSets(n int, noResponse ...int) []string {
	names := []string{"answers.json"}
	for call := 1; call <= n; call++ {
		names = append(names, debugName(call)+".human.prompt", debugName(call)+".system.prompt")
		if !slices.Contains(noResponse, call) {
			names = append(names, debugName(call)+".response")
		}
	}
	slices.Sort(names)
	return names
}

type attestedCall struct {
	promptHash  string
	rawResponse string
}

// attestedCalls returns the prompt_hash and the decoded raw_response of every
// evidence entry, in order.
func attestedCalls(t *testing.T, at *attestation.Builder) []attestedCall {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, at.Write(&buf))
	var doc struct {
		Declarations struct {
			Evidence []struct {
				Data []struct {
					Name     string `json:"name"`
					Contents struct {
						Attachment struct {
							Content string `json:"content"`
						} `json:"attachment"`
					} `json:"contents"`
				} `json:"data"`
			} `json:"evidence"`
		} `json:"declarations"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc))

	calls := make([]attestedCall, 0, len(doc.Declarations.Evidence))
	for _, e := range doc.Declarations.Evidence {
		var c attestedCall
		for _, d := range e.Data {
			switch d.Name {
			case "prompt_hash":
				c.promptHash = d.Contents.Attachment.Content
			case "raw_response":
				raw, err := base64.StdEncoding.DecodeString(d.Contents.Attachment.Content)
				require.NoError(t, err)
				c.rawResponse = string(raw)
			}
		}
		calls = append(calls, c)
	}
	return calls
}

// Runs sharing a --debug-dir, here two in parallel, each write into their own
// run-* directory and log it once, so neither overwrites the other's files
// (#359).
func TestDebugDir_OneDirectoryPerRun(t *testing.T) {
	logs := withCapturedLogs(t)
	parent := t.TempDir()

	ids := []string{"CVE-2024-1111", "CVE-2024-2222"}
	gens := make([]*Generator, len(ids))
	for i := range ids {
		gens[i] = newGen(t, Opts{LLM: testutil.NewMockLLM(), DebugDir: parent})
	}
	errs := make([]error, len(gens))
	var wg sync.WaitGroup
	for i, g := range gens {
		wg.Go(func() {
			errs[i] = g.GenerateRiskScore(context.Background(), []Vulnerability{{VulnID: ids[i], PkgName: "pkg", Description: "d"}}, nil)
		})
	}
	wg.Wait()
	require.NoError(t, errors.Join(errs...))

	dirs := runDirs(t, parent)
	require.Len(t, dirs, 2, "one directory per run")
	var logged []string
	for _, r := range logs.find(slog.LevelInfo, "Writing debug files") {
		logged = append(logged, fmt.Sprint(r.attrs["dir"]))
	}
	require.ElementsMatch(t, dirs, logged, "each run logs its directory once")

	got := map[string]bool{}
	for _, dir := range dirs {
		require.Equal(t, fileSets(len(questionsUndeclared)), fileNames(t, dir))
		entries := requestEntries(t, debugFile(t, dir, 1, "human.prompt"))
		require.Len(t, entries, 1)
		id := entries[0]["vulnId"].(string)
		require.Contains(t, debugFile(t, dir, 1, "response"), id, "the response sits beside its own prompt")
		got[id] = true
	}
	require.Equal(t, map[string]bool{"CVE-2024-1111": true, "CVE-2024-2222": true}, got, "each run kept its own prompts")
}

// Files are numbered per call: Motive's two-CVE call, batch-00001, truncates
// and keeps its prompts without a response, its halves are calls of their
// own, and so is the ask-again for the CVE one half left out. The
// attestation records only the calls that returned, so batch-00002 is
// evidence-batch-1, each found by its prompt_hash.
func TestDebugDir_WritesOneFileSetPerCall(t *testing.T) {
	parent := t.TempDir()
	m := &fakeLLM{
		fail: func(c fakeCall) error {
			if c.factor == contract.M {
				return truncateAbove(1)(c)
			}
			return nil
		},
		skip: func(c fakeCall, id string) bool { return c.n == 3 && id == "CVE-2024-0001" },
	}
	g := newGen(t, Opts{LLM: m, BatchSize: 2, DebugDir: parent})
	at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
	g.SetAttestor(at)

	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), nil))
	dirs := runDirs(t, parent)
	require.Len(t, dirs, 1)
	dir := dirs[0]
	calls := 4 + len(questionsUndeclared) - 1
	require.Equal(t, fileSets(calls, 1), fileNames(t, dir), "the truncated call returned nothing, so it has no response")

	asked := func(call int) []any {
		var ids []any
		for _, e := range requestEntries(t, debugFile(t, dir, call, "human.prompt")) {
			ids = append(ids, e["vulnId"])
		}
		return ids
	}
	require.Equal(t, []any{"CVE-2024-0000", "CVE-2024-0001"}, asked(1), "the call the provider truncated")
	require.Equal(t, []any{"CVE-2024-0000"}, asked(2))
	require.Equal(t, []any{"CVE-2024-0001"}, asked(3))
	require.NotContains(t, debugFile(t, dir, 3, "response"), "CVE-2024-0001", "the model skipped it")
	require.Equal(t, []any{"CVE-2024-0001"}, asked(4), "asked again on its own")
	require.Equal(t, debugFile(t, dir, 3, "human.prompt"), debugFile(t, dir, 4, "human.prompt"), "the ask-again repeats its prompt word for word")

	evidence := attestedCalls(t, at)
	require.Len(t, evidence, calls-1, "the truncated call is not attested")
	for i := range evidence {
		call := i + 2
		sum := sha256.Sum256([]byte(debugFile(t, dir, call, "system.prompt") + "\n\n" + debugFile(t, dir, call, "human.prompt")))
		require.Equalf(t, hex.EncodeToString(sum[:]), evidence[i].promptHash, "%s is evidence-batch-%d", debugName(call), i+1)
		require.Equalf(t, debugFile(t, dir, call, "response"), evidence[i].rawResponse, "%s.response is the raw reply", debugName(call))
	}
}

type unparsableLLM struct{}

func (unparsableLLM) Generate(context.Context, llm.Request) (string, error) {
	return "not json", nil
}

// The response is written before it is read, so the reply behind an "unable
// to parse LLM output" error is on disk.
func TestDebugDir_KeepsAReplyThatFailsToParse(t *testing.T) {
	parent := t.TempDir()
	g := newGen(t, Opts{LLM: unparsableLLM{}, DebugDir: parent})

	require.ErrorContains(t, g.GenerateRiskScore(context.Background(), testVulns(1), nil), "unable to parse LLM output")
	dirs := runDirs(t, parent)
	require.Len(t, dirs, 1)
	require.Equal(t, "not json", debugFile(t, dirs[0], 1, "response"))
}

// The files hold the deployment context and the CVE inventory, so the run
// directory and every file in it are for the user only.
func TestDebugDir_FilesArePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits")
	}
	parent := t.TempDir()
	g := newGen(t, Opts{LLM: testutil.NewMockLLM(), DebugDir: parent})
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(1), nil))

	dirs := runDirs(t, parent)
	require.Len(t, dirs, 1)
	info, err := os.Stat(dirs[0])
	require.NoError(t, err)
	require.Equal(t, fs.FileMode(0o700), info.Mode().Perm(), "run directory")

	entries, err := os.ReadDir(dirs[0])
	require.NoError(t, err)
	require.Len(t, entries, 3*len(questionsUndeclared)+1)
	for _, e := range entries {
		info, err := e.Info()
		require.NoError(t, err)
		require.Equalf(t, fs.FileMode(0o600), info.Mode().Perm(), "%s", e.Name())
	}
}

// A debug file that can't be written is logged under one constant message
// naming the file, and the run goes on.
func TestDebugDir_WriteFailureLogsTheFile(t *testing.T) {
	logs := withCapturedLogs(t)
	parent := t.TempDir()
	g := newGen(t, Opts{LLM: testutil.NewMockLLM(), DebugDir: parent})
	dirs := runDirs(t, parent)
	require.Len(t, dirs, 1)
	require.NoError(t, os.RemoveAll(dirs[0]))

	var emitted []outputhandler.VulnRating
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(1), collect(&emitted)))
	require.Len(t, emitted, 1, "a debug file is no reason to fail the run")

	var failed []string
	for _, r := range logs.find(slog.LevelError, "failed to write a debug file") {
		failed = append(failed, fmt.Sprint(r.attrs["file"]))
	}
	var want []string
	for call := 1; call <= len(questionsUndeclared); call++ {
		for _, ext := range []string{"system.prompt", "human.prompt", "response"} {
			want = append(want, filepath.Join(dirs[0], debugName(call)+"."+ext))
		}
	}
	require.Equal(t, append(want, filepath.Join(dirs[0], "answers.json")), failed)
}

type answersJSON struct {
	Vulnerabilities []struct {
		VulnID     string `json:"vulnId"`
		Unrated    bool   `json:"unrated"`
		Adjustment string `json:"adjustment"`
		Factors    []struct {
			Factor   string `json:"factor"`
			Answer   any    `json:"answer"`
			Reading  string `json:"reading"`
			Adjusted string `json:"adjusted"`
			Level    *int   `json:"level"`
			Source   string `json:"source"`
			CVSS     string `json:"cvss"`
		} `json:"factors"`
		Counters []string `json:"counters"`
	} `json:"vulnerabilities"`
	Counters map[string]int `json:"counters"`
	Defects  map[string]int `json:"defects"`
}

func readAnswers(t *testing.T, parent string) (answersJSON, string) {
	t.Helper()
	dirs := runDirs(t, parent)
	require.Len(t, dirs, 1)
	b, err := os.ReadFile(filepath.Join(dirs[0], "answers.json"))
	require.NoError(t, err)
	var got answersJSON
	require.NoError(t, json.Unmarshal(b, &got))
	return got, string(b)
}

// answers.json holds, per factor in the vector's order, the answer as
// replied, how Go read it, the adjustment's answer, the level and where it
// came from, for the three technical impacts the value the CVSS v3 vectors
// give their axis, and for a Privacy violation they floor, C:N; the counters
// per CVE and summed, cvss_v3_missing for a CVE with no usable v3 vector; no
// reachability declaration; and no reasoning, nor CVE text but what an
// answer off its list holds, kept verbatim.
func TestDebugDir_AnswersJSON(t *testing.T) {
	parent := t.TempDir()
	cfg := fullConfig()
	cfg.Context.Traceability, cfg.Context.DataSubjects = ptr("per_individual"), ptr("thousands")
	m := &fakeLLM{
		answer: func(c fakeCall, id string) any {
			switch {
			case c.factor == contract.O:
				return "some_access_or_resources_required"
			case c.factor == contract.EE && id == "CVE-2024-0001":
				return "bogus"
			case c.factor == contract.PV:
				return "millions"
			}
			return nil
		},
		adjust: func(fakeCall) map[string]any {
			return map[string]any{"reasoning": "the evidence", "opportunity": "special_access_or_resources_required"}
		},
	}
	g := newGen(t, Opts{LLM: m, Config: cfg, DebugDir: parent})
	vulns := testVulns(2)
	vulns[0].Description = "This is disputed by the vendor."
	vulns[0].Flags = Flags{MaintainerDisputed: true}
	vulns[0].CVSS = []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:L")}
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))

	got, raw := readAnswers(t, parent)
	require.Len(t, got.Vulnerabilities, 2)
	first := map[string]string{}
	var order []string
	for _, f := range got.Vulnerabilities[0].Factors {
		first[f.Factor] = fmt.Sprintf("%v|%s|%s|%d|%s|%s", f.Answer, f.Reading, f.Adjusted, *f.Level, f.Source, f.CVSS)
		order = append(order, f.Factor)
	}
	assert.Equal(t, []string{"SL", "M", "O", "S", "ED", "EE", "A", "ID", "LC", "LI", "LAV", "LAC", "FD", "RD", "NC", "PV"}, order)
	assert.Equal(t, map[string]string{
		"SL":  "<nil>|||9|constant|",
		"M":   "low_or_no_reward|answered||1|answer|",
		"O":   "some_access_or_resources_required|answered|special_access_or_resources_required|4|adjustment|",
		"S":   "<nil>|||9|config|",
		"ED":  "<nil>|||9|constant|",
		"EE":  "theoretical|answered||1|answer|",
		"A":   "<nil>|||9|constant|",
		"ID":  "[network]|answered||8|answer|",
		"LC":  "<nil>|||2|cvss|N",
		"LI":  "<nil>|||7|cvss|H",
		"LAV": "<nil>|||5|cvss|L",
		"LAC": "identified|answered||1|answer|",
		"FD":  "less_than_cost_to_fix|answered||1|answer|",
		"RD":  "minimal_damage|answered||1|answer|",
		"NC":  "minor_violation|answered||2|answer|",
		"PV":  "<nil>|||3|floor|N",
	}, first)
	assert.Empty(t, got.Vulnerabilities[0].Counters)
	assert.NotContains(t, raw, `"declared"`, "no reachability declaration")

	second := got.Vulnerabilities[1]
	for _, f := range second.Factors {
		switch f.Factor {
		case "EE":
			assert.Equal(t, []any{"bogus", "invalid", 9, "answer"}, []any{f.Answer, f.Reading, *f.Level, f.Source})
		case "PV":
			assert.Equal(t, []any{"millions", 7, "config"}, []any{f.Answer, *f.Level, f.Source}, "capped by thousands")
		case "LC", "LI", "LAV":
			assert.Equal(t, []any{nil, 9, "cvss", ""}, []any{f.Answer, *f.Level, f.Source, f.CVSS}, "no vector: %s", f.Factor)
		}
	}
	assert.Equal(t, []string{"ease_of_exploit_cannot_tell", "cvss_v3_missing"}, second.Counters)
	assert.Equal(t, map[string]int{"ease_of_exploit_cannot_tell": 1, "cvss_v3_missing": 1}, got.Counters)

	assert.NotContains(t, raw, "because of", "no reasoning")
	assert.NotContains(t, raw, "the evidence", "no reasoning")
	assert.NotContains(t, raw, "disputed", "no CVE text")
	assert.NotContains(t, raw, "described vulnerability", "no CVE text")
}

// A failed run writes answers.json too: the CVEs rated before it stopped,
// and, unrated, each CVE of the failing batch it read an answer for, with the
// answers it read and the cannot_tell they count; a CVE no reply answered is
// not listed.
func TestDebugDir_AnswersJSONOnAFailedRun(t *testing.T) {
	parent := t.TempDir()
	m := &fakeLLM{
		answer: func(c fakeCall, id string) any {
			if c.factor == contract.M && id == "CVE-2024-0002" {
				return cannotTell
			}
			return nil
		},
		skip: func(c fakeCall, id string) bool { return c.factor == contract.M && id == "CVE-2024-0003" },
	}
	g := newGen(t, Opts{LLM: m, BatchSize: 2, DebugDir: parent})
	logs := withCapturedLogs(t)
	require.Error(t, g.GenerateRiskScore(context.Background(), testVulns(4), nil))

	got, _ := readAnswers(t, parent)
	var ids []string
	for _, v := range got.Vulnerabilities {
		ids = append(ids, fmt.Sprintf("%s unrated:%t", v.VulnID, v.Unrated))
	}
	assert.Equal(t, []string{"CVE-2024-0000 unrated:false", "CVE-2024-0001 unrated:false", "CVE-2024-0002 unrated:true"}, ids,
		"CVE-2024-0003 was never answered")
	unrated := got.Vulnerabilities[2]
	require.Len(t, unrated.Factors, 1, "Motive, the one question the failing batch was answered")
	f := unrated.Factors[0]
	assert.Equal(t, []any{"M", cannotTell, "cannot_tell"}, []any{f.Factor, f.Answer, f.Reading})
	assert.Nil(t, f.Level, "an unrated CVE has no level")
	assert.Equal(t, []string{"motive_cannot_tell"}, unrated.Counters)
	assert.Equal(t, 2, got.Counters["detection_undeclared"], "the rated CVEs'")
	assert.Equal(t, 1, got.Counters["motive_cannot_tell"])
	assert.Equal(t, int64(1), runSummary(t, logs).attrs["counters.motive_cannot_tell"])
}

// answers.json gives the defects the run summary counts, under the same
// names and with the same totals: only the kinds found, {} on a clean run,
// and on a failed run those counted before it stopped, in the batch it
// rated and in the one it stopped in.
func TestDebugDir_AnswersJSONCountsTheDefects(t *testing.T) {
	offList := func(c fakeCall, _ string) any {
		if c.factor == contract.EE {
			return "bogus"
		}
		return nil
	}
	for name, tc := range map[string]struct {
		m       *fakeLLM
		failed  bool
		defects map[string]int
	}{
		"clean": {&fakeLLM{}, false, map[string]int{}},
		"unreadable and off its list": {&fakeLLM{reply: replyOnce("not json"), answer: offList}, false,
			map[string]int{"reply_unreadable": 1, "answer_off_list": 2}},
		"failed": {&fakeLLM{answer: offList, reply: func(c fakeCall) (string, bool) {
			return "not json", c.factor == contract.LAC && slices.Contains(c.ids, "CVE-2024-0001")
		}}, true, map[string]int{"answer_off_list": 2, "reply_unreadable": 2}},
	} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			logs := withCapturedLogs(t)
			g := newGen(t, Opts{LLM: tc.m, BatchSize: 1, DebugDir: parent})
			err := g.GenerateRiskScore(context.Background(), testVulns(2), nil)
			require.Equal(t, tc.failed, err != nil, "error: %v", err)

			got, raw := readAnswers(t, parent)
			assert.Equal(t, tc.defects, got.Defects)
			assert.Equal(t, tc.defects, defectsOf(runSummary(t, logs)), "the run summary's")
			if len(tc.defects) == 0 {
				assert.Contains(t, raw, `"defects": {}`)
			}
		})
	}
}

// adjustedCVE is the CVE an adjustment call is about.
func adjustedCVE(t *testing.T, c fakeCall) string {
	t.Helper()
	var entry struct {
		VulnID string `json:"vulnId"`
	}
	require.NoError(t, json.Unmarshal([]byte(strings.Split(c.req.Human, "\n")[1]), &entry))
	return entry.VulnID
}

// answers.json says how each CVE's adjustment reply read: not_asked for a CVE
// with no flag, else answered, unreadable, null included, or
// key_written_twice. A failed batch keeps, unrated, the adjustment a CVE was
// given before the run stopped, without levels.
func TestDebugDir_AnswersJSONSaysHowTheAdjustmentRead(t *testing.T) {
	replies := map[string]string{
		"CVE-2024-0001": `{"reasoning":"r","opportunity":"special_access_or_resources_required","confidentiality":"not_affected"}`,
		"CVE-2024-0002": `not json`,
		"CVE-2024-0003": `{"reasoning":"r","opportunity":"keep","opportunity":"keep","confidentiality":"affected"}`,
		"CVE-2024-0004": `null`,
	}
	t.Run("rated", func(t *testing.T) {
		parent := t.TempDir()
		vulns := testVulns(5)
		for i := 1; i < len(vulns); i++ {
			vulns[i] = disputedRow(vulns[i])
		}
		m := &fakeLLM{reply: func(c fakeCall) (string, bool) {
			if !c.adjustment() {
				return "", false
			}
			return replies[adjustedCVE(t, c)], true
		}}
		g := newGen(t, Opts{LLM: m, DebugDir: parent})
		require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))

		got, _ := readAnswers(t, parent)
		readings := map[string]string{}
		for _, v := range got.Vulnerabilities {
			readings[v.VulnID] = v.Adjustment
		}
		assert.Equal(t, map[string]string{
			"CVE-2024-0000": "not_asked", "CVE-2024-0001": "answered",
			"CVE-2024-0002": "unreadable", "CVE-2024-0003": "key_written_twice", "CVE-2024-0004": "unreadable",
		}, readings)
	})
	t.Run("unrated", func(t *testing.T) {
		parent := t.TempDir()
		vulns := []Vulnerability{disputedRow(testVulns(2)[0]), disputedRow(testVulns(2)[1])}
		m := &fakeLLM{
			reply: func(c fakeCall) (string, bool) { return replies["CVE-2024-0001"], c.adjustment() },
			fail: func(c fakeCall) error {
				if c.adjustment() && adjustedCVE(t, c) == "CVE-2024-0001" {
					return errors.New("mock: the provider is down")
				}
				return nil
			},
		}
		g := newGen(t, Opts{LLM: m, DebugDir: parent})
		require.Error(t, g.GenerateRiskScore(context.Background(), vulns, nil))

		got, _ := readAnswers(t, parent)
		require.Len(t, got.Vulnerabilities, 2)
		adjusted := map[string]string{}
		first := got.Vulnerabilities[0]
		assert.Equal(t, []any{"CVE-2024-0000", true, "answered"}, []any{first.VulnID, first.Unrated, first.Adjustment})
		for _, f := range first.Factors {
			assert.Nil(t, f.Level, f.Factor)
			assert.Empty(t, f.Source, f.Factor)
			if f.Adjusted != "" {
				adjusted[f.Factor] = f.Adjusted
			}
		}
		assert.Equal(t, map[string]string{"O": "special_access_or_resources_required", "PV": "not_affected"}, adjusted)
		second := got.Vulnerabilities[1]
		assert.Equal(t, []any{"CVE-2024-0001", true, "not_asked"}, []any{second.VulnID, second.Unrated, second.Adjustment})
		for _, f := range second.Factors {
			assert.Empty(t, f.Adjusted, f.Factor)
		}
	})
}

// answers.json keeps each answer as the reply wrote it, its JSON type kept: a
// number stays a number, a list a list, an object an object.
func TestDebugDir_AnswersJSONKeepsTheRawAnswer(t *testing.T) {
	parent := t.TempDir()
	m := &fakeLLM{answer: func(c fakeCall, _ string) any {
		switch c.factor {
		case contract.EE:
			return 7
		case contract.ID:
			return []string{"network", "host"}
		case contract.LAC:
			return map[string]any{"actor": "identified"}
		}
		return nil
	}}
	g := newGen(t, Opts{LLM: m, Config: fullConfig(), DebugDir: parent})
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(1), nil))

	dirs := runDirs(t, parent)
	b, err := os.ReadFile(filepath.Join(dirs[0], "answers.json"))
	require.NoError(t, err)
	var got struct {
		Vulnerabilities []struct {
			Factors []struct {
				Factor  string          `json:"factor"`
				Answer  json.RawMessage `json:"answer"`
				Reading string          `json:"reading"`
			} `json:"factors"`
		} `json:"vulnerabilities"`
	}
	require.NoError(t, json.Unmarshal(b, &got))
	raw := map[string]string{}
	for _, f := range got.Vulnerabilities[0].Factors {
		var compact bytes.Buffer
		if len(f.Answer) > 0 {
			require.NoError(t, json.Compact(&compact, f.Answer))
		}
		raw[f.Factor] = compact.String() + " " + f.Reading
	}
	assert.Equal(t, "7 invalid", raw["EE"])
	assert.Equal(t, `["network","host"] answered`, raw["ID"])
	assert.Equal(t, `{"actor":"identified"} invalid`, raw["LAC"])
	assert.Equal(t, " ", raw["LC"], "Loss of confidentiality is asked no answer")
	assert.Equal(t, `"low_or_no_reward" answered`, raw["M"])
	assert.Equal(t, " ", raw["SL"], "a factor not asked has no answer")
}
