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
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/llm/llmfactory"
)

// acceptanceEnv names the providers the acceptance test calls,
// comma-separated among openai, anthropic, googleai and ollama, each with
// its own key and model variables. Unset, the test is skipped: it calls real
// models and spends.
const acceptanceEnv = "VENS_PROVIDER_ACCEPTANCE"

// Each provider gets one call per question's schema and one adjustment call,
// and Go reads every reply as written: see acceptanceFailures.
func TestProviderAcceptance(t *testing.T) {
	var providers []string
	for _, name := range strings.Split(os.Getenv(acceptanceEnv), ",") {
		if name = strings.TrimSpace(name); name != "" {
			providers = append(providers, name)
		}
	}
	if len(providers) == 0 {
		t.Skipf("set %s to the providers to call, such as openai,anthropic", acceptanceEnv)
	}
	for _, name := range providers {
		t.Run(name, func(t *testing.T) {
			client, provider, model, err := llmfactory.New(context.Background(), name)
			require.NoError(t, err)
			t.Logf("provider %s, model %s", provider, model)
			assert.Empty(t, acceptanceFailures(t, client))
		})
	}
}

// The acceptance gate passes the mock's clean replies and fails on each
// defect Go can find reading a reply, the mock writing one at a time.
func TestProviderAcceptanceGate(t *testing.T) {
	require.Empty(t, acceptanceFailures(t, &fakeLLM{}), "clean replies pass")

	const first = "CVE-2024-24790"
	const axes = `"confidentiality":"affected","integrity":"affected","availability":"affected"`
	motive := func(c fakeCall, id string) bool { return c.factor == contract.M && id == first }
	// motiveReply writes Motive's reply by hand: each entry clean but the
	// first CVE's, which writes entry, and outside the answers extra.
	motiveReply := func(entry, extra string) func(fakeCall) (string, bool) {
		return func(c fakeCall) (string, bool) {
			if c.factor != contract.M {
				return "", false
			}
			entries := []string{entry}
			for _, id := range c.ids[1:] {
				entries = append(entries, `{"vulnId":"`+id+`","answer":"low_or_no_reward","reasoning":"r"}`)
			}
			return `{"answers":[` + strings.Join(entries, ",") + `]` + extra + `}`, true
		}
	}
	reasoning := func(r any) func(fakeCall, map[string]any) {
		return func(c fakeCall, entry map[string]any) {
			if motive(c, entry["vulnId"].(string)) {
				entry["reasoning"] = r
			}
		}
	}
	adjustment := func(reply string) func(fakeCall) (string, bool) {
		return func(c fakeCall) (string, bool) { return reply, c.adjustment() }
	}
	for name, tc := range map[string]struct {
		m    *fakeLLM
		want string
	}{
		"an answer off its list": {&fakeLLM{answer: func(c fakeCall, id string) any {
			if motive(c, id) {
				return "bogus"
			}
			return nil
		}}, "defects.answer_off_list: 1"},
		"an answer key written twice": {&fakeLLM{reply: motiveReply(
			`{"vulnId":"`+first+`","answer":"cannot_tell","answer":"low_or_no_reward","reasoning":"r"}`, "",
		)}, "defects.answer_key_written_twice: 1"},
		"a key written twice outside the answers": {&fakeLLM{reply: motiveReply(
			`{"vulnId":"`+first+`","answer":"low_or_no_reward","reasoning":"r"}`, `,"note":"a","note":"b"`,
		)}, "defects.answer_key_written_twice: 2"},
		"no reasoning": {&fakeLLM{edit: func(c fakeCall, entry map[string]any) {
			if motive(c, entry["vulnId"].(string)) {
				delete(entry, "reasoning")
			}
		}}, "defects.answer_without_reasoning: 1"},
		"a blank reasoning":         {&fakeLLM{edit: reasoning(" \n ")}, "defects.answer_without_reasoning: 1"},
		"a reasoning that is a map": {&fakeLLM{edit: reasoning(map[string]any{})}, "defects.answer_without_reasoning: 1"},
		"a reasoning that is a number": {&fakeLLM{edit: reasoning(7)},
			"defects.answer_without_reasoning: 1"},
		"a null reasoning": {&fakeLLM{edit: reasoning(nil)}, "defects.answer_without_reasoning: 1"},
		"an answer for a CVE not asked": {&fakeLLM{extra: func(c fakeCall) []map[string]any {
			if c.factor != contract.M {
				return nil
			}
			return []map[string]any{{"vulnId": "CVE-2000-0001", "answer": "low_or_no_reward", "reasoning": "r"}}
		}}, "defects.answer_cve_not_asked: 1"},
		"a CVE answered twice": {&fakeLLM{extra: func(c fakeCall) []map[string]any {
			if c.factor != contract.M {
				return nil
			}
			return []map[string]any{{"vulnId": first, "answer": "high_reward", "reasoning": "r"}}
		}}, "defects.answer_cve_repeated: 1"},
		"a CVE left out": {&fakeLLM{skip: func(c fakeCall, id string) bool {
			return motive(c, id) && c.n == 1
		}}, "calls.M: 2, want 1"},
		"an unreadable adjustment": {&fakeLLM{reply: adjustment(`not json`)}, "defects.adjustment_unreadable: 1"},
		"an adjustment key written twice": {&fakeLLM{reply: adjustment(
			`{"reasoning":"r","opportunity":"keep","opportunity":"keep",` + axes + `}`,
		)}, "defects.adjustment_key_written_twice: 1"},
		"an adjustment answer off its list": {&fakeLLM{reply: adjustment(
			`{"reasoning":"r","opportunity":"bogus",` + axes + `}`,
		)}, "defects.adjustment_off_list: 1"},
		"an adjustment field left out": {&fakeLLM{reply: adjustment(
			`{"reasoning":"r","opportunity":"keep","confidentiality":"affected","integrity":"affected"}`,
		)}, "defects.adjustment_off_list: 1"},
		"an adjustment without reasoning": {&fakeLLM{reply: adjustment(`{"opportunity":"keep",` + axes + `}`)},
			"defects.adjustment_without_reasoning: 1"},
		"an adjustment reasoning that is a list": {&fakeLLM{reply: adjustment(
			`{"reasoning":["r"],"opportunity":"keep",` + axes + `}`,
		)}, "defects.adjustment_without_reasoning: 1"},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, []string{tc.want}, acceptanceFailures(t, tc.m))
		})
	}
}

// acceptanceVulns are two CVEs: one plain, one both flags send to the
// adjustment.
func acceptanceVulns() []Vulnerability {
	return []Vulnerability{
		{
			VulnID: "CVE-2024-24790", PkgName: "stdlib", InstalledVersion: "1.21.0", FixedVersion: "1.21.11", BOMRef: "a",
			Title:       "net/netip: Unexpected behavior from Is methods for IPv4-mapped IPv6 addresses",
			Description: "The various Is methods (IsPrivate, IsLoopback, etc) did not work as expected for IPv4-mapped IPv6 addresses, returning false for addresses which would return true in their traditional IPv4 forms.",
			Severity:    "CRITICAL",
			CVSS:        []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")},
		},
		{
			VulnID: "CVE-2019-1010022", PkgName: "libc6", InstalledVersion: "2.36-9", BOMRef: "b",
			Title:       "glibc: stack guard protection bypass",
			Description: "GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass stack guard protection. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.\"",
			Severity:    "LOW", SeveritySource: "debian",
			VendorSeverities: []VendorSeverity{{Source: "debian", Severity: "LOW"}, {Source: "nvd", Severity: "CRITICAL"}},
			CVSS:             []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")},
			Flags:            Flags{MaintainerDisputed: true, SeverityContested: true},
		},
	}
}

// acceptanceFailures rates acceptanceVulns with client and lists what fails
// the gate, from the run's summary: a question not asked in exactly one
// call, every CVE answered at once; an adjustment not made in exactly one;
// and each defect Go found reading the replies, by kind, which covers an
// answer off its list, a key written twice, a reasoning that is no
// non-empty string and an adjustment Go cannot read.
func acceptanceFailures(t *testing.T, client llm.Client) []string {
	t.Helper()
	logs := withCapturedLogs(t)
	g := newGen(t, Opts{LLM: client, Config: fullConfig()})
	require.NoError(t, g.GenerateRiskScore(context.Background(), acceptanceVulns(), nil))
	summary := runSummary(t, logs)
	var failures []string
	for _, q := range append(contract.Order(), adjustmentCall) {
		if n := summary.attrs["calls."+string(q)]; n != int64(1) {
			failures = append(failures, fmt.Sprintf("calls.%s: %v, want 1", q, n))
		}
	}
	for key, n := range summary.attrs {
		if strings.HasPrefix(key, "defects.") {
			failures = append(failures, fmt.Sprintf("%s: %v", key, n))
		}
	}
	slices.Sort(failures)
	return failures
}
