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

// Package generator provides LLM-based OWASP risk scoring for vulnerabilities.
// The approach is inspired by github.com/AkihiroSuda/vexllm for LLM prompt structure.
package generator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/tmc/langchaingo/jsonschema"
	"github.com/tmc/langchaingo/llms"
	"github.com/venslabs/vens/pkg/llm"
	outputhandler "github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/riskconfig"
)

const (
	DefaultBatchSize        = 10
	DefaultSleepOnRateLimit = 10 * time.Second
	DefaultRetryOnRateLimit = 10
)

// Vulnerability represents a single vulnerability from a scanner report.
type Vulnerability struct {
	VulnID      string `json:"vulnId"`
	PkgID       string `json:"pkgId"`
	PkgName     string `json:"pkgName"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

// llmOutputEntry represents the LLM response for a single vulnerability.
// Inspired by vexllm's llmOutputEntry structure (github.com/AkihiroSuda/vexllm).
type llmOutputEntry struct {
	VulnID                      string  `json:"vulnId"`
	ThreatAgentContribution     float64 `json:"threat_agent_contribution"`
	VulnerabilityContribution   float64 `json:"vulnerability_contribution"`
	TechnicalImpactContribution float64 `json:"technical_impact_contribution"`
	BusinessImpactContribution  float64 `json:"business_impact_contribution"`
	Reasoning                   string  `json:"reasoning"`
}

// llmOutput wraps the array of results from LLM.
// Structure inspired by vexllm (github.com/AkihiroSuda/vexllm).
type llmOutput struct {
	Results []llmOutputEntry `json:"results"`
}

// Opts configures the Generator.
type Opts struct {
	LLM         llms.Model
	Temperature float64
	BatchSize   int // Avoid high values to avoid rate limit
	Seed        int

	SleepOnRateLimit time.Duration
	RetryOnRateLimit int
	DebugDir         string

	// Config carries user-provided OWASP base factors loaded from config.yaml.
	Config *riskconfig.Config
}

// Generator produces OWASP risk scores using LLM analysis.
type Generator struct {
	o Opts
}

// New creates a new Generator with the given options.
func New(o Opts) (*Generator, error) {
	g := &Generator{
		o: o,
	}

	if g.o.LLM == nil {
		return nil, errors.New("no model")
	}
	if g.o.BatchSize == 0 {
		g.o.BatchSize = DefaultBatchSize
	}
	if g.o.SleepOnRateLimit == 0 {
		g.o.SleepOnRateLimit = DefaultSleepOnRateLimit
	}
	if g.o.RetryOnRateLimit == 0 {
		g.o.RetryOnRateLimit = DefaultRetryOnRateLimit
	}
	if g.o.DebugDir != "" {
		if err := os.MkdirAll(g.o.DebugDir, 0755); err != nil {
			slog.Error("failed to create the debug dir", "error", err)
			g.o.DebugDir = ""
		}
	}
	return g, nil
}

// GenerateRiskScore generates contextual OWASP risk scores for the given vulnerabilities.
// It uses the LLM to evaluate each vulnerability's contribution to the 4 OWASP factors,
// then computes the final weighted risk score.
func (g *Generator) GenerateRiskScore(ctx context.Context, vulns []Vulnerability, h func([]outputhandler.VulnRating) error) error {
	batchSize := g.o.BatchSize
	for i := 0; i < len(vulns); i += batchSize {
		batch := vulns[i:min(i+batchSize, len(vulns))]
		if err := g.generateRiskScore(ctx, batch, h); err != nil {
			return err
		}
	}
	return nil
}

func (g *Generator) generateRiskScore(ctx context.Context, vulnBatch []Vulnerability, h func([]outputhandler.VulnRating) error) error {
	if g.o.Config == nil {
		return errors.New("config not initialized; load config.yaml first")
	}

	// Call LLM to evaluate OWASP contributions for each vulnerability
	contributions, err := g.evaluateOWASPContributions(ctx, vulnBatch)
	if err != nil {
		return fmt.Errorf("LLM evaluation failed: %w", err)
	}

	// Build VulnRating group using computed weighted scores
	group := make([]outputhandler.VulnRating, 0, len(vulnBatch))
	for vulnID, contrib := range contributions {
		score := g.o.Config.ComputeWeightedRisk(contrib)
		severity := riskconfig.RiskSeverity(score)

		slog.InfoContext(ctx, "vuln_risk_score",
			"vuln", vulnID,
			"score", fmt.Sprintf("%.2f", score),
			"severity", severity,
			"threat_agent_contrib", fmt.Sprintf("%.0f%%", contrib.ThreatAgent*100),
			"vulnerability_contrib", fmt.Sprintf("%.0f%%", contrib.Vulnerability*100),
			"technical_impact_contrib", fmt.Sprintf("%.0f%%", contrib.TechnicalImpact*100),
			"business_impact_contrib", fmt.Sprintf("%.0f%%", contrib.BusinessImpact*100),
		)

		group = append(group, outputhandler.VulnRating{
			VulnID: vulnID,
			Rating: cyclonedx.VulnerabilityRating{
				Method:   cyclonedx.ScoringMethodOWASP,
				Score:    &score,
				Severity: cyclonedx.Severity(severity),
			},
		})
	}

	if len(group) == 0 {
		return nil
	}
	if h != nil {
		return h(group)
	}
	return nil
}

// evaluateOWASPContributions calls the LLM to evaluate how each vulnerability
// contributes to the 4 OWASP factors. Returns a map from VulnID to contributions.
// The prompt structure is inspired by vexllm (github.com/AkihiroSuda/vexllm).
func (g *Generator) evaluateOWASPContributions(ctx context.Context, vulns []Vulnerability) (map[string]riskconfig.OWASPContributions, error) {
	if g.o.LLM == nil {
		return nil, errors.New("no LLM configured")
	}

	var buf bytes.Buffer
	callOpts := []llms.CallOption{
		llms.WithJSONMode(),
		llms.WithStreamingFunc(func(ctx context.Context, chunk []byte) error {
			buf.Write(chunk)
			return nil
		}),
	}

	if g.o.Temperature > 0.0 {
		slog.Debug("Using temperature", "temperature", g.o.Temperature)
		callOpts = append(callOpts, llms.WithTemperature(g.o.Temperature))
	}
	if g.o.Seed != 0 {
		slog.Debug("Using seed", "seed", g.o.Seed)
		callOpts = append(callOpts, llms.WithSeed(g.o.Seed))
	}

	// Build system prompt with OWASP context
	// Inspired by vexllm's system prompt structure (github.com/AkihiroSuda/vexllm)
	systemPrompt := g.buildSystemPrompt()

	// Build JSON schema for structured output
	schema := g.buildOutputSchema()
	schemaJ, err := schema.MarshalJSON()
	if err != nil {
		return nil, err
	}

	systemPrompt += "#### Output format: JSON Schema\n"
	systemPrompt += string(schemaJ) + "\n"
	systemPrompt += "#### Output Example\n"
	systemPrompt += "```json\n" + g.buildOutputExample() + "\n```\n"

	// Only ollama and openai supports WithJSONSchema
	// Reference: https://github.com/tmc/langchaingo/pull/1302
	callOpts = append(callOpts, llms.WithJSONSchema(schema))

	// Build human prompt with vulnerabilities
	// Inspired by vexllm's human prompt structure (github.com/AkihiroSuda/vexllm)
	vulnsJSON, err := json.Marshal(vulns)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vulnerabilities: %w", err)
	}
	humanPrompt := string(vulnsJSON)

	msgs := []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeSystem, systemPrompt),
		llms.TextParts(llms.ChatMessageTypeHuman, humanPrompt),
	}

	// Debug: save prompts if debug directory is configured
	if g.o.DebugDir != "" {
		if err := os.WriteFile(filepath.Join(g.o.DebugDir, "system.prompt"), []byte(systemPrompt), 0644); err != nil {
			slog.ErrorContext(ctx, "failed to write system.prompt", "error", err)
		}
		if err := os.WriteFile(filepath.Join(g.o.DebugDir, "human.prompt"), []byte(humanPrompt), 0644); err != nil {
			slog.ErrorContext(ctx, "failed to write human.prompt", "error", err)
		}
	}

	// Call LLM with retry on rate limit
	if err := llm.RetryOnRateLimit(ctx, g.o.SleepOnRateLimit, g.o.RetryOnRateLimit, func(c context.Context) error {
		buf.Reset()
		_, err := g.o.LLM.GenerateContent(c, msgs, callOpts...)
		return err
	}); err != nil {
		return nil, err
	}

	// Parse LLM response
	var resp llmOutput
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("unable to parse LLM output: %w: %q", err, buf.String())
	}

	// Convert to map
	result := make(map[string]riskconfig.OWASPContributions)
	for _, r := range resp.Results {
		if r.VulnID == "" {
			continue
		}
		result[r.VulnID] = riskconfig.OWASPContributions{
			ThreatAgent:     clampContribution(r.ThreatAgentContribution),
			Vulnerability:   clampContribution(r.VulnerabilityContribution),
			TechnicalImpact: clampContribution(r.TechnicalImpactContribution),
			BusinessImpact:  clampContribution(r.BusinessImpactContribution),
		}
		slog.DebugContext(ctx, "llm_reasoning",
			"vuln", r.VulnID,
			"reasoning", r.Reasoning,
		)
	}

	return result, nil
}

// buildSystemPrompt creates the system prompt for OWASP contribution evaluation.
// The structure is inspired by vexllm (github.com/AkihiroSuda/vexllm).
func (g *Generator) buildSystemPrompt() string {
	prompt := `You are a cybersecurity expert specialized in OWASP Risk Rating Methodology.
Your mission is to evaluate how much each vulnerability contributes to the 4 OWASP risk factors.

### Project Context
`
	if g.o.Config != nil {
		prompt += fmt.Sprintf("- Project Name: %s\n", g.o.Config.Project.Name)
		if g.o.Config.Project.Description != "" {
			prompt += fmt.Sprintf("- Project Description: %s\n", g.o.Config.Project.Description)
		}
		prompt += fmt.Sprintf(`
### Base OWASP Factors (defined by the project owner)
- Threat Agent: %.1f/9 (Who might attack?)
- Vulnerability: %.1f/9 (How easy to exploit?)
- Technical Impact: %.1f/9 (Damage to systems?)
- Business Impact: %.1f/9 (Business consequences?)
`,
			g.o.Config.OWASP.ThreatAgent,
			g.o.Config.OWASP.Vulnerability,
			g.o.Config.OWASP.TechnicalImpact,
			g.o.Config.OWASP.BusinessImpact,
		)
	}

	prompt += `
### Your Task
For each vulnerability in the input, evaluate how much it contributes to each OWASP factor as a percentage (0.0 to 1.0).

**Contribution Guidelines:**

1. **Threat Agent Contribution** (0.0-1.0):
   - 0.9-1.0: Widely known vulnerability, public exploits available, actively targeted by APT groups
   - 0.6-0.8: Known CVE, some exploit tools available, moderate attacker interest
   - 0.3-0.5: Less known, requires specific knowledge to exploit
   - 0.0-0.2: Obscure, rarely targeted

2. **Vulnerability Contribution** (0.0-1.0):
   - 0.9-1.0: Trivial to exploit, automated scanners detect it, POC exploits public
   - 0.6-0.8: Moderate difficulty, requires some setup
   - 0.3-0.5: Requires specific conditions or configuration
   - 0.0-0.2: Very difficult, theoretical only

3. **Technical Impact Contribution** (0.0-1.0):
   - 0.9-1.0: RCE, complete system compromise, data destruction
   - 0.6-0.8: Significant data access, privilege escalation
   - 0.3-0.5: Limited data exposure, DoS
   - 0.0-0.2: Minimal technical impact, information disclosure only

4. **Business Impact Contribution** (0.0-1.0):
   - 0.9-1.0: Critical business system, customer-facing, regulatory implications
   - 0.6-0.8: Important internal system, moderate business disruption
   - 0.3-0.5: Non-critical system, limited business impact
   - 0.0-0.2: Test/dev system, negligible business impact

### Important Rules
- Always provide a brief reasoning explaining your evaluation.
- Consider the vulnerability type (RCE, DoS, XSS, SQLi, etc.) when evaluating.
- Consider the affected library and its role in the project.
- Be conservative: if unsure, lean towards higher contribution values.

### Input Format
The input is a JSON array of vulnerabilities with vulnId, pkgId, pkgName, title, description, and severity.

### Output Format
Return a JSON object with a "results" array containing one entry per vulnerability.
`
	return prompt
}

// buildOutputSchema creates the JSON schema for the LLM output.
func (g *Generator) buildOutputSchema() *jsonschema.Definition {
	return &jsonschema.Definition{
		Type: jsonschema.Object,
		Properties: map[string]jsonschema.Definition{
			"results": {
				Type: jsonschema.Array,
				Items: &jsonschema.Definition{
					Type: jsonschema.Object,
					Properties: map[string]jsonschema.Definition{
						"vulnId": {
							Type:        jsonschema.String,
							Description: "The vulnerability ID from the input (e.g., CVE-2024-1234)",
						},
						"threat_agent_contribution": {
							Type:        jsonschema.Number,
							Description: "Contribution to Threat Agent factor (0.0-1.0)",
						},
						"vulnerability_contribution": {
							Type:        jsonschema.Number,
							Description: "Contribution to Vulnerability factor (0.0-1.0)",
						},
						"technical_impact_contribution": {
							Type:        jsonschema.Number,
							Description: "Contribution to Technical Impact factor (0.0-1.0)",
						},
						"business_impact_contribution": {
							Type:        jsonschema.Number,
							Description: "Contribution to Business Impact factor (0.0-1.0)",
						},
						"reasoning": {
							Type:        jsonschema.String,
							Description: "Brief explanation of the evaluation (2-3 sentences)",
						},
					},
					Required: []string{
						"vulnId",
						"threat_agent_contribution",
						"vulnerability_contribution",
						"technical_impact_contribution",
						"business_impact_contribution",
						"reasoning",
					},
				},
			},
		},
		Required: []string{"results"},
	}
}

// buildOutputExample returns an example output for the LLM.
func (g *Generator) buildOutputExample() string {
	return `{
  "results": [
    {
      "vulnId": "CVE-2024-1234",
      "threat_agent_contribution": 0.90,
      "vulnerability_contribution": 0.85,
      "technical_impact_contribution": 0.95,
      "business_impact_contribution": 1.00,
      "reasoning": "This is an RCE vulnerability in OpenSSL, widely known with public exploits. The affected library is a direct dependency of the web server exposed to the internet, making it critical for business operations."
    },
    {
      "vulnId": "CVE-2024-5678",
      "threat_agent_contribution": 0.40,
      "vulnerability_contribution": 0.50,
      "technical_impact_contribution": 0.30,
      "business_impact_contribution": 0.20,
      "reasoning": "This is a DoS vulnerability in an internal logging library. It requires specific network conditions and only affects availability, not confidentiality or integrity."
    }
  ]
}`
}

// clampContribution ensures the contribution value is within [0.0, 1.0].
func clampContribution(v float64) float64 {
	if v < 0.0 {
		return 0.0
	}
	if v > 1.0 {
		return 1.0
	}
	return v
}
