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
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// schemaNode is the part of a JSON Schema the fake reads, as the mock does.
type schemaNode struct {
	Type       string                 `json:"type"`
	Properties map[string]*schemaNode `json:"properties"`
	Items      *schemaNode            `json:"items"`
	Enum       []string               `json:"enum"`
}

// fakeCall is a call as the fake model reads it from its schema: the
// question, the CVEs asked and the closed answers; or, for an adjustment, an
// empty factor and each field's answers.
type fakeCall struct {
	n       int
	factor  contract.Factor
	ids     []string
	choices []string
	fields  map[string][]string
	req     llm.Request
}

func (c fakeCall) adjustment() bool { return c.factor == "" }

// factorByAnswers names each question by its answer list, as the schemas
// contract writes give them.
var factorByAnswers = func() map[string]contract.Factor {
	m := map[string]contract.Factor{}
	for _, f := range contract.Order() {
		schema, err := contract.Schema(f, []string{"CVE-X"})
		if err != nil {
			panic(err)
		}
		m[strings.Join(readSchema(schema).choices, ",")] = f
	}
	return m
}()

func parseCall(req llm.Request) fakeCall {
	c := readSchema(req.Schema)
	c.req = req
	if c.fields == nil {
		c.factor = factorByAnswers[strings.Join(c.choices, ",")]
	}
	return c
}

// readSchema reads a question's CVEs and answers, or an adjustment's fields.
func readSchema(schema []byte) fakeCall {
	var s schemaNode
	if err := json.Unmarshal(schema, &s); err != nil {
		panic(err)
	}
	var c fakeCall
	if answers := s.Properties["answers"]; answers != nil {
		item := answers.Items
		c.ids = item.Properties["vulnId"].Enum
		a := item.Properties["answer"]
		c.choices = a.Enum
		if a.Type == "array" {
			c.choices = a.Items.Enum
		}
		return c
	}
	c.fields = map[string][]string{}
	for name, p := range s.Properties {
		if len(p.Enum) > 0 {
			c.fields[name] = p.Enum
		}
	}
	return c
}

// fakeLLM records every call and answers through its functions. By default
// each CVE gets the question's first answer and the adjustment keeps every
// baseline. answer overrides a CVE's answer when it returns non-nil; edit
// changes a CVE's entry before it is written; skip leaves a CVE out; extra
// appends entries to a reply; adjust replaces the adjustment's reply; reply
// replaces a call's raw reply; fail fails a call.
type fakeLLM struct {
	mu     sync.Mutex
	calls  []fakeCall
	answer func(c fakeCall, id string) any
	edit   func(c fakeCall, entry map[string]any)
	skip   func(c fakeCall, id string) bool
	extra  func(c fakeCall) []map[string]any
	adjust func(c fakeCall) map[string]any
	reply  func(c fakeCall) (string, bool)
	fail   func(c fakeCall) error
}

func (m *fakeLLM) Generate(_ context.Context, req llm.Request) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := parseCall(req)
	c.n = len(m.calls) + 1
	m.calls = append(m.calls, c)
	if m.fail != nil {
		if err := m.fail(c); err != nil {
			return "", err
		}
	}
	if m.reply != nil {
		if raw, ok := m.reply(c); ok {
			return raw, nil
		}
	}
	if c.adjustment() {
		return marshal(m.adjustmentReply(c))
	}
	answers := []map[string]any{}
	for _, id := range c.ids {
		if m.skip != nil && m.skip(c, id) {
			continue
		}
		entry := map[string]any{"vulnId": id, "reasoning": "because of " + id, "answer": m.answerFor(c, id)}
		if m.edit != nil {
			m.edit(c, entry)
		}
		answers = append(answers, entry)
	}
	if m.extra != nil {
		answers = append(answers, m.extra(c)...)
	}
	return marshal(map[string]any{"answers": answers})
}

func (m *fakeLLM) answerFor(c fakeCall, id string) any {
	if m.answer != nil {
		if a := m.answer(c, id); a != nil {
			return a
		}
	}
	if c.factor == contract.ID {
		return []string{c.choices[0]}
	}
	return c.choices[0]
}

func (m *fakeLLM) adjustmentReply(c fakeCall) map[string]any {
	if m.adjust != nil {
		return m.adjust(c)
	}
	out := map[string]any{"reasoning": "the evidence"}
	for name := range c.fields {
		out[name] = "affected"
	}
	out["opportunity"] = "keep"
	return out
}

func marshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// log lists the calls by question, "adjustment" for an adjustment.
func (m *fakeLLM) log() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.calls))
	for i, c := range m.calls {
		out[i] = string(c.factor)
		if c.adjustment() {
			out[i] = adjustmentCall
		}
	}
	return out
}

// of returns the calls of question f, in order.
func (m *fakeLLM) of(f contract.Factor) []fakeCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []fakeCall
	for _, c := range m.calls {
		if c.factor == f {
			out = append(out, c)
		}
	}
	return out
}

func sizes(calls []fakeCall) []int {
	out := make([]int, len(calls))
	for i, c := range calls {
		out[i] = len(c.ids)
	}
	return out
}

// truncateAbove makes a question's call fail as truncated when it asks about
// more than n CVEs.
func truncateAbove(n int) func(fakeCall) error {
	return func(c fakeCall) error {
		if !c.adjustment() && len(c.ids) > n {
			return fmt.Errorf("mock truncated: %w", llm.ErrTruncated)
		}
		return nil
	}
}

// testConfig is a valid config declaring nothing optional: a CVE gets
// Motive to Privacy violation, but Intrusion detection and Non-compliance.
func testConfig() *riskconfig.Config {
	return &riskconfig.Config{
		Project: riskconfig.ProjectConfig{Name: "test-project"},
		Context: riskconfig.ContextHints{Exposure: "internet", DataSensitivity: "high", BusinessCriticality: "critical"},
	}
}

// questionsUndeclared are the questions testConfig asks a CVE a row
// describes, in the declared order.
var questionsUndeclared = []string{"M", "O", "EE", "LAC", "FD", "RD", "PV"}

func newGen(t *testing.T, o Opts) *Generator {
	t.Helper()
	if o.Config == nil {
		o.Config = testConfig()
	}
	g, err := New(o)
	require.NoError(t, err)
	return g
}

func testVulns(n int) []Vulnerability {
	v := make([]Vulnerability, n)
	for i := range v {
		v[i] = Vulnerability{
			VulnID: fmt.Sprintf("CVE-2024-%04d", i), PkgName: "pkg", Title: "t",
			Description: "A described vulnerability.", BOMRef: fmt.Sprintf("ref-%d", i),
		}
	}
	return v
}

// v31 is a CVSS 3.1 vector from a source.
func v31(source, metrics string) cvss.Vector {
	return cvss.Vector{Source: source, Version: "3.1", Vector: "CVSS:3.1/" + metrics}
}

// noImpact is a vector that floors every axis.
const noImpact = "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

func collect(into *[]outputhandler.VulnRating) func([]outputhandler.VulnRating) error {
	return func(group []outputhandler.VulnRating) error {
		*into = append(*into, group...)
		return nil
	}
}

// byID indexes ratings by CVE, the last row's.
func byID(ratings []outputhandler.VulnRating) map[string]outputhandler.VulnRating {
	out := map[string]outputhandler.VulnRating{}
	for _, r := range ratings {
		out[r.VulnID] = r
	}
	return out
}

// vectorLevel reads one factor's level from a written vector.
func vectorLevel(t *testing.T, vector, factor string) int {
	t.Helper()
	for part := range strings.SplitSeq(vector, "/") {
		name, digit, _ := strings.Cut(part, ":")
		if name == factor {
			var level int
			_, err := fmt.Sscan(digit, &level)
			require.NoError(t, err)
			return level
		}
	}
	t.Fatalf("%s has no %s", vector, factor)
	return 0
}

// captureHandler records slog records so tests can assert on levels and
// attrs, a group's attrs under "group.key".
type captureHandler struct {
	mu      sync.Mutex
	records []capturedRecord
}

type capturedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	rec := capturedRecord{level: r.Level, msg: r.Message, attrs: map[string]any{}}
	r.Attrs(func(a slog.Attr) bool {
		if a.Value.Kind() == slog.KindGroup {
			for _, sub := range a.Value.Group() {
				rec.attrs[a.Key+"."+sub.Key] = sub.Value.Any()
			}
			return true
		}
		rec.attrs[a.Key] = a.Value.Any()
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, rec)
	h.mu.Unlock()
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) find(level slog.Level, msg string) []capturedRecord {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []capturedRecord
	for _, r := range h.records {
		if r.level == level && r.msg == msg {
			out = append(out, r)
		}
	}
	return out
}

// withCapturedLogs swaps in a capturing slog handler for the test.
func withCapturedLogs(t *testing.T) *captureHandler {
	t.Helper()
	h := &captureHandler{}
	old := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(old) })
	return h
}

type attestedClaim struct {
	Target    string   `json:"target"`
	Predicate string   `json:"predicate"`
	Reasoning string   `json:"reasoning"`
	Evidence  []string `json:"evidence"`
}

// claims reads the attestation's claims, in order.
func claims(t *testing.T, at *attestation.Builder) []attestedClaim {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, at.Write(&buf))
	var doc struct {
		Declarations struct {
			Claims []attestedClaim `json:"claims"`
		} `json:"declarations"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &doc), "output:\n%s", buf.String())
	return doc.Declarations.Claims
}

// requestEntries reads the CVE entries a question's request lists.
func requestEntries(t *testing.T, request string) []map[string]any {
	t.Helper()
	lines := strings.Split(request, "\n")
	require.Equal(t, "VULNERABILITIES", lines[0])
	var entries []map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &entries))
	return entries
}
