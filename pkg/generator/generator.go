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
// The LLM calculates the OWASP risk score directly based on context hints.
type llmOutputEntry struct {
	VulnID    string  `json:"vulnId"`
	Score     float64 `json:"owasp_score"`
	Severity  string  `json:"severity"`
	Reasoning string  `json:"reasoning"`
}

// llmOutput wraps the array of results from LLM.
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

	// Config carries user-provided context hints loaded from config.yaml.
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
// It uses the LLM to calculate the OWASP risk score for each vulnerability based on
// the project context hints provided in config.yaml.
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

	// Call LLM to calculate OWASP scores for each vulnerability
	scores, err := g.evaluateOWASPScores(ctx, vulnBatch)
	if err != nil {
		return fmt.Errorf("LLM evaluation failed: %w", err)
	}

	// Build VulnRating group using LLM-computed scores
	group := make([]outputhandler.VulnRating, 0, len(vulnBatch))
	for _, entry := range scores {
		if entry.VulnID == "" {
			continue
		}

		score := clampScore(entry.Score)
		severity := riskconfig.RiskSeverity(score)

		slog.InfoContext(ctx, "vuln_risk_score",
			"vuln", entry.VulnID,
			"score", fmt.Sprintf("%.2f", score),
			"severity", severity,
		)

		group = append(group, outputhandler.VulnRating{
			VulnID: entry.VulnID,
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

// evaluateOWASPScores calls the LLM to calculate the OWASP risk score for each vulnerability.
// The LLM uses the project context hints to determine the appropriate score.
func (g *Generator) evaluateOWASPScores(ctx context.Context, vulns []Vulnerability) ([]llmOutputEntry, error) {
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

	// Build system prompt with context hints
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

	// Log reasoning for debugging
	for _, r := range resp.Results {
		slog.DebugContext(ctx, "llm_reasoning",
			"vuln", r.VulnID,
			"score", r.Score,
			"reasoning", r.Reasoning,
		)
	}

	return resp.Results, nil
}

// buildSystemPrompt creates the system prompt for OWASP score calculation.
// Inspired by github.com/AkihiroSuda/vexllm prompt structure.
func (g *Generator) buildSystemPrompt() string {
	prompt := `You are a cybersecurity expert specialized in OWASP Risk Rating Methodology.
Your mission is to calculate the OWASP risk score for each vulnerability based on the project context.

Reference: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

### OWASP Risk Rating Formula
Risk = Likelihood × Impact

Where:
- Likelihood = (Threat Agent Factor + Vulnerability Factor) / 2
- Impact = (Technical Impact + Business Impact) / 2

Each factor is scored 0-9, so:
- Likelihood range: 0-9
- Impact range: 0-9
- Final Risk Score range: 0-81

### Severity Levels
- CRITICAL: score >= 60
- HIGH: score >= 40
- MEDIUM: score >= 20
- LOW: score >= 5
- NOTE: score < 5

### Project Context
`
	if g.o.Config != nil {
		prompt += g.o.Config.FormatForLLM()
	}

	prompt += `
### Context Interpretation Guide

**Exposure:**
- "internal": Low threat agent (2-3), attackers need internal access
- "private": Medium threat agent (4-5), requires VPN/authentication
- "internet": High threat agent (7-9), publicly accessible, APT targets

**Data Sensitivity:**
- "low": Low technical impact (1-3), public data only
- "medium": Medium technical impact (4-5), internal data
- "high": High technical impact (6-7), PII, financial data
- "critical": Maximum technical impact (8-9), secrets, credentials, PHI

**Business Criticality:**
- "low": Low business impact (1-3), dev/test environments
- "medium": Medium business impact (4-5), internal tools
- "high": High business impact (6-7), customer-facing services
- "critical": Maximum business impact (8-9), revenue-critical, compliance

### Your Task
For each vulnerability in the input:
1. Analyze the CVE, severity, and affected package
2. Consider the project context (exposure, data sensitivity, business criticality)
3. Calculate the 4 OWASP factors (0-9 each):
   - Threat Agent Factor: Based on exposure and vulnerability attractiveness
   - Vulnerability Factor: Based on ease of discovery and exploitation
   - Technical Impact: Based on data sensitivity and potential damage
   - Business Impact: Based on business criticality and consequences
4. Compute the final OWASP risk score (0-81)
5. Determine the severity level

### Important Rules
- Always provide a brief reasoning explaining your evaluation
- Consider the vulnerability type (RCE, DoS, XSS, SQLi, etc.)
- Consider the affected library and its role in the project
- Be conservative: when in doubt, lean towards higher scores for internet-exposed systems

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
						"owasp_score": {
							Type:        jsonschema.Number,
							Description: "The calculated OWASP risk score (0-81)",
						},
						"severity": {
							Type:        jsonschema.String,
							Description: "The severity level (CRITICAL, HIGH, MEDIUM, LOW, NOTE)",
						},
						"reasoning": {
							Type:        jsonschema.String,
							Description: "Brief explanation of the score calculation (2-3 sentences)",
						},
					},
					Required: []string{
						"vulnId",
						"owasp_score",
						"severity",
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
      "owasp_score": 56.25,
      "severity": "HIGH",
      "reasoning": "RCE vulnerability in OpenSSL on internet-exposed server (threat_agent=8, vuln=7). Handles high-sensitivity data (tech_impact=7) and is business-critical (biz_impact=8). Score: ((8+7)/2) × ((7+8)/2) = 7.5 × 7.5 = 56.25"
    },
    {
      "vulnId": "CVE-2024-5678",
      "owasp_score": 12.0,
      "severity": "LOW",
      "reasoning": "DoS vulnerability in logging library. Internal exposure reduces threat (threat_agent=3, vuln=4). Low data sensitivity (tech_impact=3) and medium business impact (biz_impact=4). Score: ((3+4)/2) × ((3+4)/2) = 3.5 × 3.5 = 12.25"
    }
  ]
}`
}

// clampScore ensures the score is within [0, 81].
func clampScore(v float64) float64 {
	if v < 0.0 {
		return 0.0
	}
	if v > 81.0 {
		return 81.0
	}
	return v
}
