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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/internal/testutil"
	"github.com/venslabs/vens/pkg/llm"
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
		{"The 16 factors", "rate the 16 OWASP factors below, each separately, on that factor's own levels:"},
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
		"the 16 factor levels",
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

	// It asked for one technical-impact value; each factor is now rated apart.
	if strings.Contains(prompt, "Return highest applicable score") {
		t.Error("Prompt still asks to 'Return highest applicable score'")
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

// schemaDoc mirrors the JSON Schema produced by buildOutputSchema, enough to
// assert on its shape in tests.
type schemaDoc struct {
	Type                 string `json:"type"`
	AdditionalProperties *bool  `json:"additionalProperties"`
	Properties           struct {
		Results struct {
			Type  string `json:"type"`
			Items struct {
				Type                 string `json:"type"`
				AdditionalProperties *bool  `json:"additionalProperties"`
				Properties           map[string]struct {
					Type        string `json:"type"`
					Enum        []int  `json:"enum"`
					Description string `json:"description"`
				} `json:"properties"`
				Required []string `json:"required"`
			} `json:"items"`
		} `json:"results"`
	} `json:"properties"`
	Required []string `json:"required"`
}

func parseOutputSchema(t *testing.T, raw json.RawMessage) schemaDoc {
	t.Helper()
	var doc schemaDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("buildOutputSchema returned invalid JSON: %v", err)
	}
	return doc
}

func TestOutputSchemaRequired(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	doc := parseOutputSchema(t, g.buildOutputSchema())

	if doc.Type != "object" {
		t.Errorf("Schema type should be 'object', got %q", doc.Type)
	}

	results := doc.Properties.Results
	if results.Type != "array" {
		t.Errorf("Results type should be 'array', got %q", results.Type)
	}

	requiredFields := []string{"vulnId"}
	for _, f := range factors {
		requiredFields = append(requiredFields, f.key)
	}
	requiredFields = append(requiredFields, "reasoning")

	if len(results.Items.Properties) != len(requiredFields) {
		t.Errorf("Schema has %d properties, want %d", len(results.Items.Properties), len(requiredFields))
	}
	if strings.Join(results.Items.Required, ",") != strings.Join(requiredFields, ",") {
		t.Errorf("Required is %v, want %v", results.Items.Required, requiredFields)
	}
	for _, ap := range []*bool{doc.AdditionalProperties, results.Items.AdditionalProperties} {
		if ap == nil || *ap {
			t.Error("additionalProperties must be false in both object schemas")
		}
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

func TestOutputSchemaFactors(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	doc := parseOutputSchema(t, g.buildOutputSchema())

	props := doc.Properties.Results.Items.Properties
	for _, f := range factors {
		prop, ok := props[f.key]
		if !ok {
			t.Errorf("Missing field: %s", f.key)
			continue
		}
		if prop.Type != "integer" {
			t.Errorf("Field %s should be 'integer', got %q", f.key, prop.Type)
		}
		if fmt.Sprint(prop.Enum) != fmt.Sprint(f.levels) {
			t.Errorf("Field %s enum %v, want %v", f.key, prop.Enum, f.levels)
		}
		if prop.Description != f.question {
			t.Errorf("Field %s description %q, want OWASP's question %q", f.key, prop.Description, f.question)
		}
	}
	if props["reasoning"].Description != "Brief explanation of each score (2-3 sentences)" {
		t.Errorf("reasoning keeps main's description, got %q", props["reasoning"].Description)
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

	// main's 4000-character cap cannot hold the 16 OWASP factor lines; the
	// exact prompt is pinned by the golden files instead.
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

var update = flag.Bool("update", false, "rewrite the comparator's golden prompts and schema under testdata")

// systemCapture records the system prompt of the last call.
type systemCapture struct{ system string }

func (c *systemCapture) Generate(ctx context.Context, req llm.Request) (string, error) {
	c.system = req.System
	return testutil.NewMockLLM().Generate(ctx, req)
}

// sentSystemPrompt is the system prompt one call sends in a context, schema
// included, as the provider receives it.
func sentSystemPrompt(t *testing.T, name string) string {
	t.Helper()
	yaml, ok := demoContexts[name]
	require.True(t, ok, name)
	cfg, err := riskconfig.Parse([]byte(yaml))
	require.NoError(t, err)
	c := &systemCapture{}
	g, err := New(Opts{LLM: c, Config: cfg, BatchSize: 1})
	require.NoError(t, err)
	require.NoError(t, g.GenerateRiskScore(context.Background(), testVulns(1), nil))
	return c.system
}

func readGolden(t *testing.T, path ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, path...)...))
	require.NoError(t, err)
	return string(b)
}

func writeGolden(t *testing.T, content string, path ...string) {
	t.Helper()
	p := filepath.Join(append([]string{"testdata"}, path...)...)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

// The system prompt sent in each context is its golden file, byte for byte.
func TestSystemPromptGolden(t *testing.T) {
	for _, c := range demoContextNames {
		t.Run(c, func(t *testing.T) {
			got := sentSystemPrompt(t, c)
			if *update {
				writeGolden(t, got, "prompts", "comparator", c+".system.prompt")
			}
			require.Equal(t, readGolden(t, "prompts", "comparator", c+".system.prompt"), got)
		})
	}
}

// The schema is its golden file, byte for byte.
func TestOutputSchemaGolden(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	got := string(g.buildOutputSchema())
	if *update {
		writeGolden(t, got, "schema.json")
	}
	require.Equal(t, readGolden(t, "schema.json"), got)
	require.True(t, json.Valid([]byte(got)))
}

// owaspLines reads testdata/owasp-factors.txt: each factor's line in OWASP's
// Risk Rating Methodology, from its name to its last level, bold marks removed.
func owaspLines(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(readGolden(t, "owasp-factors.txt"), "\n"), "\n") {
		key, text, ok := strings.Cut(line, ": ")
		require.True(t, ok, line)
		out[key] = text
	}
	require.Len(t, out, 16)
	return out
}

func replaceOnce(t *testing.T, s, old, new string) string {
	t.Helper()
	require.Equal(t, 1, strings.Count(s, old), "%q must occur once", old)
	return strings.Replace(s, old, new, 1)
}

// The prompt main 43ab10b sends in each context (testdata/prompts/main-43ab10b,
// equal to every system prompt step 5's main control sent) becomes this
// branch's by the spec's five edits and the schema alone.
func TestSystemPromptIsMainsWithTheFiveEdits(t *testing.T) {
	lines := owaspLines(t)
	block := func(keys ...string) string {
		s := "\n   Factors, each rated separately:"
		for _, k := range keys {
			s += "\n   - " + k + ": " + lines[k]
		}
		return s
	}
	schema := readGolden(t, "schema.json")
	for _, c := range demoContextNames {
		t.Run(c, func(t *testing.T) {
			s := readGolden(t, "prompts", "main-43ab10b", c+".system.prompt")

			// 5: the output example block, which ends main's prompt, is removed.
			i := strings.Index(s, "#### Output Example\n")
			require.Positive(t, i)
			require.True(t, strings.HasSuffix(s, "\n```\n"))
			s = s[:i]
			// The schema: main's four scores give way to the 16 factors.
			head := "#### Output format: JSON Schema\n"
			j := strings.Index(s, head)
			require.Positive(t, j)
			s = s[:j+len(head)] + schema + "\n"
			// 1.
			s = replaceOnce(t, s, "score 4 factors (0-9):",
				"rate the 16 OWASP factors below, each separately, on that factor's own levels:")
			// 3.
			s = replaceOnce(t, s, "\n   - Return highest applicable score", "")
			// 4.
			s = replaceOnce(t, s, "OUTPUT: 4 scores (0-9) + brief reasoning", "OUTPUT: the 16 factor levels + brief reasoning")
			// 2: each group's four factors after its last guidance line.
			s = replaceOnce(t, s, "\n\n2. VULNERABILITY", block("SL", "M", "O", "S")+"\n\n2. VULNERABILITY")
			s = replaceOnce(t, s, "\n\n3. TECHNICAL_IMPACT", block("ED", "EE", "A", "ID")+"\n\n3. TECHNICAL_IMPACT")
			s = replaceOnce(t, s, "\n\n4. BUSINESS_IMPACT", block("LC", "LI", "LAV", "LAC")+"\n\n4. BUSINESS_IMPACT")
			s = replaceOnce(t, s, "\n\nSCORING SCALE", block("FD", "RD", "NC", "PV")+"\n\nSCORING SCALE")

			require.Equal(t, s, readGolden(t, "prompts", "comparator", c+".system.prompt"))
			require.Equal(t, s, sentSystemPrompt(t, c))
		})
	}
}

// Each factor's line and question in the code are OWASP's, and its levels
// are the distinct numbers its options carry.
func TestFactorsAreOWASPs(t *testing.T) {
	lines := owaspLines(t)
	number := regexp.MustCompile(`\((\d)\)`)
	for _, f := range factors {
		require.Equal(t, lines[f.key], f.name+" - "+f.question+" "+f.options, f.key)
		var distinct []int
		for _, m := range number.FindAllStringSubmatch(f.options, -1) {
			n := int(m[1][0] - '0')
			if !slices.Contains(distinct, n) {
				distinct = append(distinct, n)
			}
		}
		slices.Sort(distinct)
		require.Equal(t, distinct, f.levels, f.key)
	}
}

// Each schema enum is levels.go's set of distinct levels for its factor:
// owasp.Vector.Check accepts a level, all others valid, exactly when the
// enum holds it.
func TestSchemaEnumsAreLevelsGos(t *testing.T) {
	g := newTestGenerator(t, minimalConfig())
	props := parseOutputSchema(t, g.buildOutputSchema()).Properties.Results.Items.Properties
	base := make([]int, len(factors))
	for i, f := range factors {
		base[i] = f.levels[0]
	}
	require.NoError(t, vectorOf(base).Check())
	for i, f := range factors {
		enum := props[f.key].Enum
		require.NotEmpty(t, enum, f.key)
		for level := -100; level <= 100; level++ {
			l := slices.Clone(base)
			l[i] = level
			err := vectorOf(l).Check()
			require.Equal(t, slices.Contains(enum, level), err == nil, "%s:%d", f.key, level)
		}
	}
}

// The request carries no example levels: any would be free parameters.
func TestRequestHasNoOutputExample(t *testing.T) {
	for _, c := range demoContextNames {
		s := sentSystemPrompt(t, c)
		require.NotContains(t, s, "Output Example", c)
		require.True(t, strings.HasSuffix(s, "#### Output format: JSON Schema\n"+string(json.RawMessage(outputSchema))+"\n"), c)
	}
}
