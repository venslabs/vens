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
	"encoding/json"
	"strings"
	"testing"

	"github.com/venslabs/vens/internal/testutil"
	"github.com/venslabs/vens/pkg/riskconfig"
)

func TestPromptRoleDefinition(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	prompt := g.buildSystemPrompt()

	if !strings.HasPrefix(prompt, "You are") {
		t.Error("Prompt should start with role definition 'You are...'")
	}

	roleElements := []string{
		"security expert",
		"OWASP Risk Rating Methodology",
	}

	for _, element := range roleElements {
		if !strings.Contains(prompt, element) {
			t.Errorf("Role definition missing: %q", element)
		}
	}
}

func TestPromptStructureOrder(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	prompt := g.buildSystemPrompt()

	rolePos := strings.Index(prompt, "You are")
	contextPos := strings.Index(prompt, "SYSTEM CONTEXT:")
	taskPos := strings.Index(prompt, "TASK:")
	outputPos := strings.Index(prompt, "OUTPUT:")

	if rolePos == -1 || contextPos == -1 || taskPos == -1 || outputPos == -1 {
		t.Fatal("Missing required prompt sections")
	}

	if rolePos >= contextPos || contextPos >= taskPos || taskPos >= outputPos {
		t.Errorf("Prompt structure order incorrect. Expected: Role(%d) < Context(%d) < Task(%d) < Output(%d)",
			rolePos, contextPos, taskPos, outputPos)
	}
}

func TestPromptCoreStructure(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	prompt := g.buildSystemPrompt()

	requiredElements := []struct {
		name    string
		content string
	}{
		{"OWASP methodology reference", "OWASP Risk Rating Methodology"},
		{"Factor 1: Threat Agent", "THREAT_AGENT"},
		{"Factor 2: Vulnerability", "VULNERABILITY"},
		{"Factor 3: Technical Impact", "TECHNICAL_IMPACT"},
		{"Factor 4: Business Impact", "BUSINESS_IMPACT"},
		{"Scoring scale", "SCORING SCALE"},
		{"Score range 0-9", "0-9"},
		{"Low range", "low:1-3"},
		{"Medium range", "medium:4-6"},
		{"High range", "high:7-8"},
		{"Critical value", "critical:9"},
	}

	for _, tc := range requiredElements {
		if !strings.Contains(prompt, tc.content) {
			t.Errorf("Prompt missing %s: expected to contain %q", tc.name, tc.content)
		}
	}
}

func TestPromptCIATriad(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	prompt := g.buildSystemPrompt()

	ciaElements := []string{
		"confidentiality",
		"integrity",
		"availability",
		"accountability",
	}

	for _, element := range ciaElements {
		if !strings.Contains(strings.ToLower(prompt), element) {
			t.Errorf("Prompt missing CIA element: %q", element)
		}
	}
}

func TestPromptOutputInstructions(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	prompt := g.buildSystemPrompt()

	outputRequirements := []string{
		"OUTPUT:",
		"4 scores",
		"reasoning",
	}

	for _, req := range outputRequirements {
		if !strings.Contains(prompt, req) {
			t.Errorf("Prompt missing output instruction: %q", req)
		}
	}
}

func TestPromptScoreNormalization(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	prompt := g.buildSystemPrompt()

	if !strings.Contains(prompt, "Cap at 9") {
		t.Error("Prompt missing 'Cap at 9' score normalization instruction")
	}

	if !strings.Contains(prompt, "Return highest applicable score") {
		t.Error("Prompt missing 'Return highest applicable score' instruction")
	}
}

func TestPromptDataSensitivityMapping(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	prompt := g.buildSystemPrompt()

	if !strings.Contains(prompt, "C/I breach: score = data_sensitivity") {
		t.Error("Prompt missing data_sensitivity mapping for C/I breach")
	}
}

func TestPromptTaskClarity(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	prompt := g.buildSystemPrompt()

	taskClarityElements := []string{
		"For EACH vulnerability",
		"THIS vuln",
		"THIS system",
		"THIS specific vulnerability",
	}

	foundCount := 0
	for _, element := range taskClarityElements {
		if strings.Contains(prompt, element) {
			foundCount++
		}
	}

	if foundCount < 2 {
		t.Error("Prompt lacks clarity about processing each vulnerability individually")
	}
}

func TestPromptThreatAgentGuidelines(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	prompt := g.buildSystemPrompt()

	guidelines := []string{
		"Internet-exposed remote vuln: 7-9",
		"Private network local vuln: 3-5",
		"attack vector",
	}

	for _, guideline := range guidelines {
		if !strings.Contains(prompt, guideline) {
			t.Errorf("Prompt missing threat agent guideline: %q", guideline)
		}
	}
}

func TestPromptVulnerabilityGuidelines(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	prompt := g.buildSystemPrompt()

	guidelines := []string{
		"Easy discovery + exploit available: 7-9",
		"Requires expertise: 4-6",
		"Theoretical/complex: 1-3",
		"CRITICAL: Score the ACTUAL vulnerability",
	}

	for _, guideline := range guidelines {
		if !strings.Contains(prompt, guideline) {
			t.Errorf("Prompt missing vulnerability guideline: %q", guideline)
		}
	}
}

func TestPromptContextInjection(t *testing.T) {
	cfg := &riskconfig.Config{
		Project: riskconfig.ProjectConfig{
			Name:        "test-project",
			Description: "Test project description",
		},
		Context: riskconfig.ContextHints{
			Exposure:            "internet",
			DataSensitivity:     "critical",
			BusinessCriticality: "high",
		},
	}

	g := newTestGenerator(t, cfg)
	prompt := g.buildSystemPrompt()

	expectedContext := []string{
		"SYSTEM CONTEXT:",
		"test-project",
		"internet",
		"critical",
	}

	for _, expected := range expectedContext {
		if !strings.Contains(prompt, expected) {
			t.Errorf("Prompt missing context element: %q", expected)
		}
	}
}

func TestPromptSecurityControlsConditional(t *testing.T) {
	controlsMessage := "Reduce if controls block this vuln type"

	t.Run("without controls", func(t *testing.T) {
		g := newTestGenerator(t, minimalConfig())
		prompt := g.buildSystemPrompt()

		if strings.Contains(prompt, controlsMessage) {
			t.Error("Prompt should NOT contain controls message when no controls configured")
		}
	})

	t.Run("with WAF control", func(t *testing.T) {
		cfg := minimalConfig()
		cfg.Context.Controls.WAF = true

		g := newTestGenerator(t, cfg)
		prompt := g.buildSystemPrompt()

		if !strings.Contains(prompt, controlsMessage) {
			t.Error("Prompt should contain controls message when WAF is enabled")
		}
	})

	t.Run("with IDS control", func(t *testing.T) {
		cfg := minimalConfig()
		cfg.Context.Controls.IDS = true

		g := newTestGenerator(t, cfg)
		prompt := g.buildSystemPrompt()

		if !strings.Contains(prompt, controlsMessage) {
			t.Error("Prompt should contain controls message when IDS is enabled")
		}
	})

	t.Run("with multiple controls", func(t *testing.T) {
		cfg := minimalConfig()
		cfg.Context.Controls.WAF = true
		cfg.Context.Controls.EDR = true
		cfg.Context.Controls.Segmentation = true

		g := newTestGenerator(t, cfg)
		prompt := g.buildSystemPrompt()

		if !strings.Contains(prompt, controlsMessage) {
			t.Error("Prompt should contain controls message when multiple controls enabled")
		}
	})
}

func TestPromptAvailabilityRequirementConditional(t *testing.T) {
	t.Run("without availability requirement", func(t *testing.T) {
		g := newTestGenerator(t, minimalConfig())
		prompt := g.buildSystemPrompt()

		if !strings.Contains(prompt, "Availability loss: score = business_criticality") {
			t.Error("Without availability_requirement, should reference business_criticality")
		}
	})

	t.Run("with availability requirement", func(t *testing.T) {
		cfg := minimalConfig()
		avail := "critical"
		cfg.Context.AvailabilityRequirement = &avail

		g := newTestGenerator(t, cfg)
		prompt := g.buildSystemPrompt()

		if !strings.Contains(prompt, "Availability loss: score = availability_requirement") {
			t.Error("With availability_requirement, should reference availability_requirement")
		}
	})
}

func TestPromptComplianceConditional(t *testing.T) {
	complianceMessage := "+2 if vuln triggers compliance violation"

	t.Run("without compliance requirements", func(t *testing.T) {
		g := newTestGenerator(t, minimalConfig())
		prompt := g.buildSystemPrompt()

		if strings.Contains(prompt, complianceMessage) {
			t.Error("Prompt should NOT contain compliance message when no requirements")
		}
	})

	t.Run("with compliance requirements", func(t *testing.T) {
		cfg := minimalConfig()
		cfg.Context.ComplianceRequirements = []string{"PCI-DSS", "GDPR"}

		g := newTestGenerator(t, cfg)
		prompt := g.buildSystemPrompt()

		if !strings.Contains(prompt, complianceMessage) {
			t.Error("Prompt should contain compliance message when requirements exist")
		}
	})
}

func TestPromptAuditRequirementConditional(t *testing.T) {
	auditMessage := "Accountability loss: score = audit_requirement"

	t.Run("without audit requirement", func(t *testing.T) {
		g := newTestGenerator(t, minimalConfig())
		prompt := g.buildSystemPrompt()

		if strings.Contains(prompt, auditMessage) {
			t.Error("Prompt should NOT contain audit message when no requirement")
		}
	})

	t.Run("with audit requirement", func(t *testing.T) {
		cfg := minimalConfig()
		audit := "high"
		cfg.Context.AuditRequirement = &audit

		g := newTestGenerator(t, cfg)
		prompt := g.buildSystemPrompt()

		if !strings.Contains(prompt, auditMessage) {
			t.Error("Prompt should contain audit message when requirement exists")
		}
	})
}

func TestOutputSchemaRequired(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	schema := g.buildOutputSchema()

	if schema.Type != "object" {
		t.Errorf("Schema type should be 'object', got %q", schema.Type)
	}

	results, ok := schema.Properties["results"]
	if !ok {
		t.Fatal("Schema missing 'results' property")
	}

	if results.Type != "array" {
		t.Errorf("Results type should be 'array', got %q", results.Type)
	}

	if results.Items == nil {
		t.Fatal("Results.Items should not be nil")
	}

	requiredFields := []string{
		"vulnId",
		"threat_agent_score",
		"vulnerability_score",
		"technical_impact",
		"business_impact",
		"reasoning",
	}

	for _, field := range requiredFields {
		if _, ok := results.Items.Properties[field]; !ok {
			t.Errorf("Schema missing required field: %s", field)
		}
	}

	for _, field := range requiredFields {
		found := false
		for _, req := range results.Items.Required {
			if req == field {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Field %q not in Required array", field)
		}
	}
}

func TestOutputSchemaScoreDescriptions(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	schema := g.buildOutputSchema()

	results := schema.Properties["results"]
	props := results.Items.Properties

	scoreFields := map[string]string{
		"threat_agent_score":  "0-9",
		"vulnerability_score": "0-9",
		"technical_impact":    "0-9",
		"business_impact":     "0-9",
	}

	for field, expectedRange := range scoreFields {
		prop, ok := props[field]
		if !ok {
			t.Errorf("Missing field: %s", field)
			continue
		}

		if prop.Type != "number" {
			t.Errorf("Field %s should be 'number', got %q", field, prop.Type)
		}

		if !strings.Contains(prop.Description, expectedRange) {
			t.Errorf("Field %s description should contain %q, got %q", field, expectedRange, prop.Description)
		}
	}
}

func TestOutputExample(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	example := g.buildOutputExample()

	if !strings.HasPrefix(strings.TrimSpace(example), "{") {
		t.Error("Example should start with '{'")
	}

	if !strings.Contains(example, `"results"`) {
		t.Error("Example missing 'results' field")
	}

	if !strings.Contains(example, "CVE-") {
		t.Error("Example should contain CVE IDs")
	}

	scoreFields := []string{
		"threat_agent_score",
		"vulnerability_score",
		"technical_impact",
		"business_impact",
	}

	for _, field := range scoreFields {
		if !strings.Contains(example, field) {
			t.Errorf("Example missing field: %s", field)
		}
	}

	if !strings.Contains(example, "reasoning") {
		t.Error("Example missing 'reasoning' field")
	}
}

func TestExampleSchemaConsistency(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	schema := g.buildOutputSchema()
	example := g.buildOutputExample()

	results := schema.Properties["results"]
	schemaFields := make([]string, 0)
	for field := range results.Items.Properties {
		schemaFields = append(schemaFields, field)
	}

	for _, field := range schemaFields {
		if !strings.Contains(example, field) {
			t.Errorf("Schema field %q not found in example - this can cause LLM confusion", field)
		}
	}

	scorePatterns := []string{
		`"threat_agent_score": 8`,
		`"vulnerability_score": 7`,
		`"technical_impact": 8`,
		`"business_impact": 9`,
	}

	foundNumericScore := false
	for _, pattern := range scorePatterns {
		if strings.Contains(example, pattern) {
			foundNumericScore = true
			break
		}
	}

	if !foundNumericScore {
		t.Error("Example should contain numeric scores (not quoted strings)")
	}
}

func TestPromptNoInstructionLeakage(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	prompt := g.buildSystemPrompt()

	dangerousPatterns := []string{
		"ignore previous",
		"disregard above",
		"forget everything",
		"new instructions",
	}

	promptLower := strings.ToLower(prompt)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(promptLower, pattern) {
			t.Errorf("Prompt contains potentially dangerous pattern: %q", pattern)
		}
	}
}

func TestPromptNoNilPanic(t *testing.T) {
	g := &Generator{
		o: Opts{
			LLM:       testutil.NewMockLLM(),
			BatchSize: 10,
			Config:    nil, // nil config
		},
	}

	prompt := g.buildSystemPrompt()

	if !strings.Contains(prompt, "OWASP Risk Rating Methodology") {
		t.Error("Prompt should contain OWASP reference even with nil config")
	}
}

func TestPromptNegativeInstructions(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	prompt := g.buildSystemPrompt()

	if !strings.Contains(prompt, "not the system") {
		t.Error("Prompt missing negative instruction 'not the system'")
	}

	if !strings.Contains(prompt, "ACTUAL vulnerability") {
		t.Error("Prompt missing emphasis on 'ACTUAL vulnerability'")
	}
}

func TestPromptAnchoringValues(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	prompt := g.buildSystemPrompt()

	anchorRanges := []string{
		"7-9", // High severity anchor
		"4-6", // Medium severity anchor
		"3-5", // Low-medium anchor
		"1-3", // Low severity anchor
	}

	for _, anchor := range anchorRanges {
		if !strings.Contains(prompt, anchor) {
			t.Errorf("Prompt missing anchoring range: %q", anchor)
		}
	}
}

func TestOutputExampleValidJSON(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	example := g.buildOutputExample()

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(example), &parsed); err != nil {
		t.Errorf("Example is not valid JSON: %v", err)
	}

	results, ok := parsed["results"].([]interface{})
	if !ok {
		t.Fatal("Parsed example missing 'results' array")
	}

	if len(results) == 0 {
		t.Error("Example should contain at least one result")
	}
}

func TestOutputExampleFewShotDiversity(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	example := g.buildOutputExample()

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(example), &parsed); err != nil {
		t.Fatalf("Example is not valid JSON: %v", err)
	}

	results, ok := parsed["results"].([]interface{})
	if !ok {
		t.Fatal("Parsed example missing 'results' array")
	}

	if len(results) < 2 {
		t.Error("Example should contain at least 2 results for few-shot diversity")
	}

	var hasHighScore, hasLowScore bool
	for _, r := range results {
		result, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		if score, ok := result["threat_agent_score"].(float64); ok {
			if score >= 7 {
				hasHighScore = true
			}
			if score <= 4 {
				hasLowScore = true
			}
		}
	}

	if !hasHighScore || !hasLowScore {
		t.Error("Example should show both high-score and low-score cases for calibration")
	}
}

func TestOutputExampleReasoningQuality(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	example := g.buildOutputExample()

	reasoningIndicators := []string{
		"ThreatAgent",
		"Vulnerability",
		"TechImpact",
		"BusinessImpact",
	}

	foundCount := 0
	for _, indicator := range reasoningIndicators {
		if strings.Contains(example, indicator) {
			foundCount++
		}
	}

	if foundCount < 3 {
		t.Errorf("Example reasoning should reference OWASP factors, found %d/4", foundCount)
	}
}

func TestPromptReasoningGuidance(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	prompt := g.buildSystemPrompt()

	if !strings.Contains(prompt, "brief") && !strings.Contains(prompt, "reasoning") {
		t.Error("Prompt should guide reasoning format")
	}
}

func TestPromptLength(t *testing.T) {
	cfg := &riskconfig.Config{
		Project: riskconfig.ProjectConfig{
			Name:        "test-project",
			Description: "A detailed project description for testing",
		},
		Context: riskconfig.ContextHints{
			Exposure:               "internet",
			DataSensitivity:        "critical",
			BusinessCriticality:    "critical",
			ComplianceRequirements: []string{"PCI-DSS", "GDPR", "HIPAA"},
			Controls: riskconfig.SecurityControls{
				WAF:          true,
				IDS:          true,
				EDR:          true,
				Segmentation: true,
			},
			Notes: "Additional context notes for testing prompt length",
		},
	}
	avail := "critical"
	cfg.Context.AvailabilityRequirement = &avail
	audit := "high"
	cfg.Context.AuditRequirement = &audit

	g := newTestGenerator(t, cfg)
	prompt := g.buildSystemPrompt()

	maxLength := 4000
	if len(prompt) > maxLength {
		t.Errorf("Prompt too long: %d chars (max %d). Risk of truncation.", len(prompt), maxLength)
	}

	minLength := 500
	if len(prompt) < minLength {
		t.Errorf("Prompt suspiciously short: %d chars (min %d)", len(prompt), minLength)
	}
}

func newTestGenerator(t *testing.T, cfg *riskconfig.Config) *Generator {
	t.Helper()
	g, err := New(Opts{
		LLM:       testutil.NewMockLLM(),
		BatchSize: 10,
		Config:    cfg,
	})
	if err != nil {
		t.Fatalf("Failed to create generator: %v", err)
	}
	return g
}

func minimalConfig() *riskconfig.Config {
	return &riskconfig.Config{
		Project: riskconfig.ProjectConfig{
			Name: "test-project",
		},
		Context: riskconfig.ContextHints{
			Exposure:            "internet",
			DataSensitivity:     "high",
			BusinessCriticality: "critical",
		},
	}
}
