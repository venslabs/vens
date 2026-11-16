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
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// sent runs a flagged CVE and a plain one under cfg and returns the calls
// the model received.
func sent(t *testing.T, cfg *riskconfig.Config) []fakeCall {
	t.Helper()
	m := &fakeLLM{}
	g := newGen(t, Opts{LLM: m, Config: cfg})
	vulns := testVulns(2)
	vulns[0] = disputedRow(vulns[0])
	require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))
	return m.calls
}

// facts returns the FOR THIS QUESTION block of a question's request, "" when
// it has none.
func facts(request string) string {
	_, after, ok := strings.Cut(request, "\nFOR THIS QUESTION\n")
	if !ok {
		return ""
	}
	block, _, _ := strings.Cut(after, "\n\nANSWERS\n")
	return block
}

func richConfig() *riskconfig.Config {
	cfg := testConfig()
	cfg.Project.Description = "Checkout API"
	cfg.Context.Listener = "present"
	cfg.Context.Notes = "Parses attacker-controlled JSON."
	cfg.Context.AvailabilityRequirement = ptr("high")
	cfg.Context.ComplianceRequirements = []string{"PCI-DSS", "GDPR"}
	cfg.Context.AuditRequirement = ptr("high")
	cfg.Context.Traceability = ptr("per_individual")
	cfg.Context.DataSubjects = ptr("thousands")
	cfg.Context.Detection = &riskconfig.DetectionCoverage{Network: "logged_and_reviewed", Host: "logged", Application: "not_logged"}
	cfg.Context.Controls = riskconfig.SecurityControls{WAF: true, IDS: true, SIEM: true, EDR: true, Segmentation: true, Antivirus: true}
	return cfg
}

// The config reaches the questions as the config documents it: each value
// with its meaning, the five controls Ease of exploit shows that are set to
// true with their scope in the reference's order, and the fields Go reads
// alone as they are.
func TestDeploymentOf(t *testing.T) {
	d := deploymentOf(richConfig())
	assert.Equal(t, contract.Setting{Value: "internet", Meaning: "Publicly accessible"}, d.Exposure)
	assert.Equal(t, contract.Setting{Value: "high", Meaning: "PII, financial data, customer info"}, d.DataSensitivity)
	assert.Equal(t, contract.Setting{Value: "critical", Meaning: "Revenue-critical, compliance-required"}, d.BusinessCriticality)
	assert.Equal(t, &contract.Setting{Value: "high", Meaning: "24/7 required"}, d.AvailabilityRequirement)
	assert.Equal(t, riskconfig.Listener.Meaning("present"), d.Listener.Meaning)
	assert.Equal(t, []contract.Control{
		{Key: "waf", Description: "Web Application Firewall", Scope: "SQL injection, XSS, path traversal"},
		{Key: "segmentation", Description: "Network micro-segmentation", Scope: "Lateral movement"},
		{Key: "antivirus", Description: "Traditional AV / anti-malware", Scope: "Known malware signatures"},
	}, d.Controls)
	assert.Equal(t, &contract.Detection{Network: "logged_and_reviewed", Host: "logged", Application: "not_logged"}, d.Detection)
	assert.Equal(t, "per_individual", *d.Traceability)
	assert.Equal(t, "thousands", *d.DataSubjects)
	assert.Equal(t, []string{"PCI-DSS", "GDPR"}, d.Frameworks)
	assert.NoError(t, d.Check())
}

func TestPromptRoleDefinition(t *testing.T) {
	for _, c := range sent(t, testConfig()) {
		require.True(t, strings.HasPrefix(c.req.System, "You are a security expert. You answer questions of the OWASP Risk Rating Methodology"))
	}
}

// The deployment block carries the project, the exposure with its meaning
// and the attacker group, the listener when declared, and the notes; the
// system prompt is the same for every call of the run.
func TestPromptContextInjection(t *testing.T) {
	calls := sent(t, richConfig())
	system := calls[0].req.System
	for _, line := range []string{
		"Project: test-project",
		"Description: Checkout API",
		"Exposure: internet (Publicly accessible). The attacker group to consider is anonymous Internet users.",
		"Listener: present (" + riskconfig.Listener.Meaning("present") + ").",
		"Notes: Parses attacker-controlled JSON.",
	} {
		assert.Contains(t, system, "\n"+line+"\n")
	}
	for _, c := range calls {
		assert.Equal(t, system, c.req.System)
	}
	cfg := richConfig()
	cfg.Context.Listener = "unknown"
	assert.NotContains(t, sent(t, cfg)[0].req.System, "Listener:")
}

// The controls set to true that Ease of exploit shows reach its facts alone,
// with their scope; ids, siem and edr reach no request.
func TestPromptSecurityControlsConditional(t *testing.T) {
	const line = "Controls in front of this deployment: waf (Web Application Firewall; scope: SQL injection, XSS, path traversal); " +
		"segmentation (Network micro-segmentation; scope: Lateral movement); antivirus (Traditional AV / anti-malware; scope: Known malware signatures)"
	for _, c := range sent(t, richConfig()) {
		if c.factor == contract.EE {
			assert.Contains(t, facts(c.req.Human), line)
		} else {
			assert.NotContains(t, c.req.Human, "Controls in front")
		}
		text := c.req.System + c.req.Human
		for _, hidden := range []string{"ids (", "siem (", "edr (", "IDS", "SIEM", "EDR", "Intrusion Detection System", "Endpoint Detection"} {
			assert.NotContains(t, text, hidden)
		}
	}
	for _, c := range sent(t, testConfig()) {
		assert.NotContains(t, c.req.Human, "Controls in front", "no control set to true, no line")
	}
}

// Loss of availability's background is the availability requirement when
// declared, the business criticality otherwise.
func TestPromptAvailabilityRequirementConditional(t *testing.T) {
	lav := func(cfg *riskconfig.Config) string {
		for _, c := range sent(t, cfg) {
			if c.factor == contract.LAV {
				return facts(c.req.Human)
			}
		}
		t.Fatal("no Loss of availability call")
		return ""
	}
	assert.Equal(t, "Availability requirement: high (24/7 required)", lav(richConfig()))
	assert.Equal(t, "Business criticality: critical (Revenue-critical, compliance-required)", lav(testConfig()))
}

// Non-compliance is asked only when a framework is declared, and its
// question names the frameworks.
func TestPromptComplianceConditional(t *testing.T) {
	for _, c := range sent(t, testConfig()) {
		assert.NotEqual(t, contract.NC, c.factor)
	}
	var nc []fakeCall
	for _, c := range sent(t, richConfig()) {
		if c.factor == contract.NC {
			nc = append(nc, c)
		}
	}
	require.Len(t, nc, 1)
	assert.Contains(t, nc[0].req.Human, "QUESTION\nThis service must comply with PCI-DSS, GDPR.")
}

// audit_requirement moves nothing and reaches no request, nor do the fields
// Go reads alone.
func TestPromptAuditRequirementConditional(t *testing.T) {
	for _, c := range sent(t, richConfig()) {
		for _, hidden := range []string{"audit", "traceability", "per_individual", "data_subjects", "detection", "logged_and_reviewed", "not_logged"} {
			assert.NotContains(t, c.req.System, hidden)
			assert.NotContains(t, c.req.Human, hidden)
		}
	}
}

// Every schema sent closes every object and requires each of its
// properties, as OpenAI's strict mode needs.
func TestOutputSchemaRequired(t *testing.T) {
	var check func(t *testing.T, node map[string]any)
	check = func(t *testing.T, node map[string]any) {
		if props, ok := node["properties"].(map[string]any); ok {
			assert.Equal(t, false, node["additionalProperties"])
			var names, required []string
			for name, p := range props {
				names = append(names, name)
				check(t, p.(map[string]any))
			}
			for _, r := range node["required"].([]any) {
				required = append(required, r.(string))
			}
			slices.Sort(names)
			slices.Sort(required)
			assert.Equal(t, names, required)
		}
		if items, ok := node["items"].(map[string]any); ok {
			check(t, items)
		}
	}
	calls := sent(t, richConfig())
	require.True(t, slices.ContainsFunc(calls, fakeCall.adjustment))
	for _, c := range calls {
		var schema map[string]any
		require.NoError(t, json.Unmarshal(c.req.Schema, &schema))
		check(t, schema)
	}
}

func TestPromptNoInstructionLeakage(t *testing.T) {
	for _, c := range sent(t, richConfig()) {
		for _, pattern := range []string{"ignore previous", "disregard above", "forget everything", "new instructions"} {
			assert.NotContains(t, strings.ToLower(c.req.System+c.req.Human), pattern)
		}
	}
}

// A missing or empty config fails New with an error, never a panic.
func TestPromptNoNilPanic(t *testing.T) {
	_, err := New(Opts{LLM: &fakeLLM{}})
	require.EqualError(t, err, "config not initialized; load config.yaml first")
	_, err = New(Opts{LLM: &fakeLLM{}, Config: &riskconfig.Config{}})
	require.ErrorContains(t, err, "config: the project has no name")
	_, err = New(Opts{Config: testConfig()})
	require.EqualError(t, err, "no model")
}

// The system prompt asks for one sentence of reasoning before each answer,
// and each request's reply line writes the reasoning before the answer.
func TestPromptReasoningGuidance(t *testing.T) {
	for _, c := range sent(t, testConfig()) {
		assert.Contains(t, c.req.System, "In reasoning, state in one sentence the fact that decides the answer, before giving it.")
		if !c.adjustment() {
			assert.Contains(t, c.req.Human, `Reply with {"answers": [{"vulnId": "...", "reasoning": "...", "answer": `)
		}
	}
}
