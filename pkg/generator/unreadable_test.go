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
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/outputhandler"
)

const (
	unreadableWarning = "Unreadable reply; the vulnerabilities it leaves without an answer count as left out"
	askAgainWarning   = "No readable answer for vulnerabilities; asking again for those alone"
	// highReward answers Motive for CVE-2024-0000 with a level the fake's
	// default answer, low_or_no_reward, does not give: an M of 9 says which
	// reply answered.
	highReward = `{"vulnId":"CVE-2024-0000","answer":"high_reward","reasoning":"r"}`
)

// replyOnce replaces the reply to the run's first Motive call, its second
// call after reachability's, with raw.
func replyOnce(raw string) func(fakeCall) (string, bool) {
	return func(c fakeCall) (string, bool) { return raw, c.factor == contract.M && c.n == 1 }
}

// An ordinary reply Go cannot read, whole or one answer, is no answer for the
// CVEs it should have carried. A reply that is no JSON object, cut short
// included, or whose answers are no array answers none of them; an answer
// that is no JSON object is skipped and the others kept. The CVEs left
// without an answer take the one ask-again CVEs left out take; a reply cut
// short that the provider did not flag as truncated is not split. The reply
// counts one reply_unreadable defect and is logged at WARN, quoted.
func TestGenerator_UnreadableReplyIsAskedAgain(t *testing.T) {
	both := []string{"CVE-2024-0000", "CVE-2024-0001"}
	for name, tc := range map[string]struct {
		reply string
		again []string
		why   string
	}{
		"not JSON": {`Here are the answers: high_reward for both.`, both,
			"the reply is not JSON: invalid character 'H' looking for beginning of value"},
		"cut short": {`{"answers":[` + highReward + `,{"vulnId":"CVE-2024-0001","ans`, both,
			"the reply is not JSON: unexpected end of JSON input"},
		"a top-level array": {`[` + highReward + `]`, both, "the reply is an array, not a JSON object"},
		"null":              {`null`, both, "the reply is null, not a JSON object"},
		"answers an object": {`{"answers":` + highReward + `}`, both, "the answers are an object, not an array"},
		"answers null":      {`{"answers":null}`, both, "the answers are null, not an array"},
		"an answer no object": {`{"answers":[` + highReward + `,"CVE-2024-0001: high_reward"]}`, []string{"CVE-2024-0001"},
			"answer 2 of 2 is a string, not an object"},
	} {
		t.Run(name, func(t *testing.T) {
			logs := withCapturedLogs(t)
			m := &fakeLLM{reply: replyOnce(tc.reply)}
			g := newGen(t, Opts{LLM: m})
			var emitted []outputhandler.VulnRating
			require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), collect(&emitted)))

			motive := m.of(contract.M)
			require.Len(t, motive, 2, "the call, then its one ask-again")
			assert.Equal(t, tc.again, motive[1].ids)
			got := byID(emitted)
			kept := len(tc.again) == 1
			assert.Equal(t, map[bool]int{true: 9, false: 1}[kept], vectorLevel(t, got["CVE-2024-0000"].Rating.Vector, "M"),
				"an object answer of a reply skipping another is kept")
			assert.Equal(t, 1, vectorLevel(t, got["CVE-2024-0001"].Rating.Vector, "M"), "answered when asked again")

			summary := runSummary(t, logs)
			assert.Equal(t, int64(1), summary.attrs["defects.reply_unreadable"])
			assert.Equal(t, int64(1), summary.attrs["asked_again"])
			assert.Equal(t, int64(0), summary.attrs["splits"], "a cut the provider did not flag is not split")
			warned := logs.find(slog.LevelWarn, unreadableWarning)
			require.Len(t, warned, 1)
			assert.Equal(t, map[string]any{"question": "M", "error": tc.why, "reply": tc.reply}, warned[0].attrs)
		})
	}
}

// The attestation keeps an unreadable reply as its call's evidence, one entry
// per call that returned a reply, in call order. A claim cites the calls that
// answered for its CVE: the ask-again for a CVE the reply left without an
// answer, the reply itself for an answer Go read in it.
func TestGenerator_Attestor_UnreadableReplyAskedAgain(t *testing.T) {
	for name, tc := range map[string]struct {
		reply string
		// motive is the call each claim, in claim order, cites for Motive:
		// 1 the reply, 2 its ask-again.
		motive []int
	}{
		"whole reply unreadable": {`Here are the answers: high_reward for both.`, []int{2, 2}},
		"one answer unreadable":  {`{"answers":[` + highReward + `,"CVE-2024-0001: high_reward"]}`, []int{1, 2}},
	} {
		t.Run(name, func(t *testing.T) {
			at := attestation.NewBuilder(attestation.Opts{Provider: "mock", Model: "mock"})
			m := &fakeLLM{reply: replyOnce(tc.reply)}
			g := newGen(t, Opts{LLM: m})
			g.SetAttestor(at)
			require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), nil))
			require.Equal(t, append([]string{"M"}, questionsUndeclared...), m.log(), "Motive, its ask-again, then each other question")

			evidence := attestedCalls(t, at)
			require.Len(t, evidence, len(m.calls), "one per call that returned a reply, the unreadable one included")
			for i, c := range m.calls {
				sum := sha256.Sum256([]byte(c.req.System + "\n\n" + c.req.Human))
				assert.Equal(t, hex.EncodeToString(sum[:]), evidence[i].promptHash, "evidence-batch-%d is call %d", i+1, i+1)
			}
			assert.Equal(t, tc.reply, evidence[0].rawResponse, "the unreadable reply, as the model wrote it")

			cited := claims(t, at)
			require.Len(t, cited, len(tc.motive))
			for i, c := range cited {
				want := []string{fmt.Sprintf("evidence-batch-%d", tc.motive[i])}
				for n := 3; n <= len(m.calls); n++ {
					want = append(want, fmt.Sprintf("evidence-batch-%d", n))
				}
				assert.Equal(t, want, c.Evidence, "the claim on %s", c.Target)
			}
		})
	}
}

// A call the provider truncates is still split in half. A half whose reply is
// cut short with no flag from the provider is not split again: its CVEs are
// asked again once, together, and the other half's answers are kept. The
// halves answer high_reward, an M of 9, and the ask-again the fake's default,
// an M of 1.
func TestGenerator_TruncatedCallSplitsThenAsksAgainForAnUnreadableHalf(t *testing.T) {
	all := []string{"CVE-2024-0000", "CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}
	first, second := all[:2], all[2:]
	for name, tc := range map[string]struct {
		cut         int
		again, kept []string
	}{
		"first half unreadable":  {2, first, second},
		"second half unreadable": {3, second, first},
	} {
		t.Run(name, func(t *testing.T) {
			logs := withCapturedLogs(t)
			m := &fakeLLM{
				fail: func(c fakeCall) error {
					if c.n == 1 {
						return fmt.Errorf("mock truncated: %w", llm.ErrTruncated)
					}
					return nil
				},
				reply: func(c fakeCall) (string, bool) { return `{"answers":[{"vulnId":"CVE-2024-00`, c.n == tc.cut },
				answer: func(c fakeCall, _ string) any {
					if c.factor == contract.M && c.n <= 3 {
						return "high_reward"
					}
					return nil
				},
			}
			g := newGen(t, Opts{LLM: m})
			var emitted []outputhandler.VulnRating
			require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(4), collect(&emitted)))

			var asked [][]string
			for _, c := range m.of(contract.M) {
				asked = append(asked, c.ids)
			}
			assert.Equal(t, [][]string{all, first, second, tc.again}, asked, "the call, its halves, then one ask-again")
			got := byID(emitted)
			for _, id := range tc.kept {
				assert.Equal(t, 9, vectorLevel(t, got[id].Rating.Vector, "M"), "%s keeps its half's answer", id)
			}
			for _, id := range tc.again {
				assert.Equal(t, 1, vectorLevel(t, got[id].Rating.Vector, "M"), "%s answered when asked again", id)
			}

			summary := runSummary(t, logs)
			assert.Equal(t, int64(1), summary.attrs["splits"])
			assert.Equal(t, int64(1), summary.attrs["asked_again"])
			assert.Equal(t, int64(1), summary.attrs["defects.reply_unreadable"])
			warned := logs.find(slog.LevelWarn, askAgainWarning)
			require.Len(t, warned, 1)
			assert.Equal(t, map[string]any{"question": "M", "unanswered": int64(2), "of": int64(4), "vulns": strings.Join(tc.again, ",")},
				warned[0].attrs)
		})
	}
}

// An object without answers is a reply that answers nothing: its CVEs are
// left out, asked again, and no defect is counted.
func TestGenerator_ReplyWithoutAnswersIsNoDefect(t *testing.T) {
	logs := withCapturedLogs(t)
	m := &fakeLLM{reply: replyOnce(`{}`)}
	g := newGen(t, Opts{LLM: m})
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), nil))
	assert.Equal(t, []int{2, 2}, sizes(m.of(contract.M)))
	assert.Empty(t, logs.find(slog.LevelWarn, unreadableWarning))
	assert.NotContains(t, runSummary(t, logs).attrs, "defects.reply_unreadable")
}

// A reply still unreadable when asked again stops the run, as a CVE still
// left out does, and the error says what Go could not read, the reply
// quoted: "no answer" alone would hide why. Each unreadable reply counts
// once.
func TestGenerator_UnreadableTwiceStopsTheRun(t *testing.T) {
	logs := withCapturedLogs(t)
	m := &fakeLLM{reply: func(c fakeCall) (string, bool) { return "not json", c.factor == contract.O }}
	g := newGen(t, Opts{LLM: m})
	var emitted []outputhandler.VulnRating
	err := g.GenerateRiskScore(context.Background(), testVulns(2), collect(&emitted))
	require.EqualError(t, err, "model returned no answer to Opportunity (O) for CVE-2024-0000, CVE-2024-0001 after asking again; "+
		`stopping the run: unable to parse LLM output: the reply is not JSON: invalid character 'o' in literal null (expecting 'u'): "not json"`)
	assert.Empty(t, emitted)
	assert.Equal(t, []string{"M", "O", "O"}, m.log())
	summary := runSummary(t, logs)
	assert.Equal(t, int64(2), summary.attrs["defects.reply_unreadable"])
	assert.Equal(t, true, summary.attrs["failed"])
}

// Omissions and unreadable answers share the one ask-again. A CVE a reply
// leaves out and one it leaves with an answer Go cannot read are asked again
// together. When the run stops, its error keeps what Go could not read of a
// reply that left a CVE without an answer, the first's when the ask-again
// only leaves it out, the ask-again's when that one cannot be read.
func TestGenerator_OmissionAndUnreadableReplyMixed(t *testing.T) {
	const (
		notJSON   = `unable to parse LLM output: the reply is not JSON: invalid character 'o' in literal null (expecting 'u'): "not json"`
		answered2 = `{"vulnId":"CVE-2024-0002","answer":"low_or_no_reward","reasoning":"r"}`
	)
	for name, tc := range map[string]struct {
		reply func(fakeCall) (string, bool)
		skip  func(fakeCall, string) bool
		sizes []int
		err   string
	}{
		"left out and unreadable, then answered": {
			reply: replyOnce(`{"answers":[` + highReward + `,7]}`),
			sizes: []int{3, 2},
		},
		"unreadable, then left out": {
			reply: replyOnce("not json"),
			skip:  func(c fakeCall, id string) bool { return c.n == 2 && id == "CVE-2024-0001" },
			sizes: []int{3, 3},
			err:   "model returned no answer to Motive (M) for CVE-2024-0001 after asking again; stopping the run: " + notJSON,
		},
		"left out, then unreadable": {
			reply: func(c fakeCall) (string, bool) { return `[]`, c.n == 2 },
			skip:  func(c fakeCall, id string) bool { return c.n == 1 && id != "CVE-2024-0000" },
			sizes: []int{3, 2},
			err: "model returned no answer to Motive (M) for CVE-2024-0001, CVE-2024-0002 after asking again; stopping the run: " +
				`unable to parse LLM output: the reply is an array, not a JSON object: "[]"`,
		},
		"left out, then an answer unreadable": {
			reply: func(c fakeCall) (string, bool) { return `{"answers":[` + answered2 + `,1]}`, c.n == 2 },
			skip:  func(c fakeCall, id string) bool { return c.n == 1 && id != "CVE-2024-0000" },
			sizes: []int{3, 2},
			err: "model returned no answer to Motive (M) for CVE-2024-0001 after asking again; stopping the run: " +
				`unable to parse LLM output: answer 2 of 2 is a number, not an object: "{\"answers\":[` +
				strings.ReplaceAll(answered2, `"`, `\"`) + `,1]}"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := &fakeLLM{reply: tc.reply, skip: tc.skip}
			g := newGen(t, Opts{LLM: m})
			err := g.GenerateRiskScore(context.Background(), testVulns(3), nil)
			assert.Equal(t, tc.sizes, sizes(m.of(contract.M)))
			if tc.err == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.err)
		})
	}
}

// One reply_unreadable per reply, however many of its answers Go skips: the
// WARN names each.
func TestGenerator_UnreadableAnswersCountOncePerReply(t *testing.T) {
	logs := withCapturedLogs(t)
	m := &fakeLLM{reply: func(c fakeCall) (string, bool) {
		return `{"answers":[1,null,` + highReward + `,{"vulnId":"CVE-2024-0001","answer":"high_reward","reasoning":"r"}]}`, c.factor == contract.M
	}}
	g := newGen(t, Opts{LLM: m})
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(2), nil))
	assert.Len(t, m.of(contract.M), 1, "every CVE answered: no ask-again")
	assert.Equal(t, int64(1), runSummary(t, logs).attrs["defects.reply_unreadable"])
	warned := logs.find(slog.LevelWarn, unreadableWarning)
	require.Len(t, warned, 1)
	assert.Equal(t, "answer 1 of 4 is a number, not an object; answer 2 of 4 is null, not an object", warned[0].attrs["error"])
}

// The WARN and the stop's error quote at most loggedLimit characters of an
// unreadable reply; the debug record keeps it whole.
func TestGenerator_UnreadableReplyQuotedCapped(t *testing.T) {
	long := strings.Repeat("é", 3*loggedLimit)
	logs := withCapturedLogs(t)
	parent := t.TempDir()
	m := &fakeLLM{reply: func(fakeCall) (string, bool) { return long, true }}
	g := newGen(t, Opts{LLM: m, DebugDir: parent})
	err := g.GenerateRiskScore(context.Background(), testVulns(1), nil)
	capped := strings.Repeat("é", loggedLimit) + "…"
	require.ErrorContains(t, err, `: "`+capped+`"`)
	assert.NotContains(t, err.Error(), strings.Repeat("é", loggedLimit+1))
	warned := logs.find(slog.LevelWarn, unreadableWarning)
	require.Len(t, warned, 2, "the call and its ask-again")
	for _, r := range warned {
		assert.Equal(t, capped, r.attrs["reply"])
	}
	dirs := runDirs(t, parent)
	require.Len(t, dirs, 1)
	for call := 1; call <= 2; call++ {
		assert.Equal(t, long, debugFile(t, dirs[0], call, "response"))
	}
}

// A strict run takes the ask-again for an unreadable reply too: Go read no
// answer there, so nothing reads as cannot_tell.
func TestGenerator_StrictAsksAgainAfterAnUnreadableReply(t *testing.T) {
	m := &fakeLLM{reply: replyOnce("not json")}
	g := newGen(t, Opts{LLM: m, Config: strictConfig(), Strict: true})
	require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{complete(testVulns(1)[0])}, nil))
	assert.Equal(t, []int{1, 1}, sizes(m.of(contract.M)))
}
