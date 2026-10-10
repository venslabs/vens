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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/owasp"
	"github.com/venslabs/vens/pkg/riskconfig"
	"github.com/venslabs/vens/pkg/vuln"
)

const (
	DefaultBatchSize        = 10
	DefaultSleepOnRateLimit = 10 * time.Second
	DefaultRetryOnRateLimit = 10
)

// Vulnerability represents a single vulnerability from a scanner report.
// Contains all fields needed for VEX generation.
type Vulnerability struct {
	VulnID           string
	PkgID            string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	BOMRef           string // CycloneDX BOM-Ref (calculated using Trivy's logic)
	Title            string
	Description      string
	Severity         string // NVD/vendor severity
	SourceName       string
	SourceURL        string
}

// LLMVulnerability contains only the fields needed for LLM analysis.
// This is sent to the LLM to minimize token usage.
type LLMVulnerability struct {
	VulnID           string `json:"vulnId"`
	PkgID            string `json:"pkgId"`
	PkgName          string `json:"pkgName"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	FixedVersion     string `json:"fixedVersion,omitempty"`
	Title            string `json:"title"`
	Description      string `json:"description,omitempty"`
	Severity         string `json:"severity,omitempty"` // NVD/vendor severity as context
}

// llmOutputEntry represents the LLM response for a single vulnerability.
// The LLM rates each of the 4 OWASP factors (0-9 scale), and the final score
// is calculated in Go code for mathematical accuracy.
type llmOutputEntry struct {
	VulnID             string  `json:"vulnId"`
	ThreatAgentScore   float64 `json:"threat_agent_score"`  // 0-9: Threat actor factors (skill, motive, opportunity, size)
	VulnerabilityScore float64 `json:"vulnerability_score"` // 0-9: Vulnerability factors (ease of discovery, ease of exploit)
	TechnicalImpact    float64 `json:"technical_impact"`    // 0-9: Technical impact (loss of CIA)
	BusinessImpact     float64 `json:"business_impact"`     // 0-9: Business impact (financial, reputation, compliance)
	Reasoning          string  `json:"reasoning"`           // Brief explanation of the scoring
}

// llmOutput wraps the array of results from LLM.
type llmOutput struct {
	Results []llmOutputEntry `json:"results"`
}

// Opts configures the Generator.
type Opts struct {
	LLM         llm.Client
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
	o        Opts
	attestor *attestation.Builder
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

// SetAttestor attaches an attestation Builder after construction. Pass nil to disable.
func (g *Generator) SetAttestor(b *attestation.Builder) { g.attestor = b }

// scoringRun carries state shared across the batches of one GenerateRiskScore
// call: the VulnIDs an earlier batch already scored (so one batch's declined answer
// never kills a run another batch already scored), the first answer per CVE
// (so a later batch reuses it instead of dropping the CVE's rows from the
// VEX), and the CVEs declined or left unanswered after asking again (checked
// once, at the end of the run, so batch order never decides the outcome).
type scoringRun struct {
	scored   map[string]bool
	scores   map[string]answer
	declined map[string]bool
	missing  map[string]bool
}

// GenerateRiskScore generates contextual OWASP risk scores for the given vulnerabilities.
// It uses the LLM to calculate the OWASP risk score for each vulnerability based on
// the project context hints provided in config.yaml.
func (g *Generator) GenerateRiskScore(ctx context.Context, vulns []Vulnerability, h func([]outputhandler.VulnRating) error) error {
	run := &scoringRun{
		scored:   make(map[string]bool),
		scores:   make(map[string]answer),
		declined: make(map[string]bool),
		missing:  make(map[string]bool),
	}
	if err := g.scoreInBatches(ctx, vulns, g.o.BatchSize, run, h); err != nil {
		return err
	}
	return run.checkUnassessed()
}

// checkUnassessed fails the run once, at the end, when the model declined to
// assess CVEs or left them unanswered after asking again. Both categories are
// listed, and both sides of the count are distinct CVEs — never package rows.
func (run *scoringRun) checkUnassessed() error {
	if len(run.declined) == 0 && len(run.missing) == 0 {
		return nil
	}
	total := len(run.scored) + len(run.declined) + len(run.missing)
	failed := len(run.declined) + len(run.missing)
	var parts []string
	if len(run.declined) > 0 {
		parts = append(parts, fmt.Sprintf("declined to assess %d: %s (see https://github.com/venslabs/vens/issues/337)",
			len(run.declined), strings.Join(sortedKeys(run.declined), ", ")))
	}
	if len(run.missing) > 0 {
		parts = append(parts, fmt.Sprintf("returned no score for %d: %s",
			len(run.missing), strings.Join(sortedKeys(run.missing), ", ")))
	}
	return fmt.Errorf("model failed to assess %d of %d vulnerabilities, after asking again: %s",
		failed, total, strings.Join(parts, "; "))
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// scoreInBatches scores vulns batchSize at a time. If a provider truncates a
// batch at its output-token limit (llm.ErrTruncated), that batch is split in
// half and retried; the split repeats on each further truncation, down to a
// single CVE. Only a lone CVE that still truncates fails the run.
func (g *Generator) scoreInBatches(ctx context.Context, vulns []Vulnerability, batchSize int, run *scoringRun, h func([]outputhandler.VulnRating) error) error {
	if batchSize < 1 {
		batchSize = 1
	}
	for i := 0; i < len(vulns); i += batchSize {
		batch := vulns[i:min(i+batchSize, len(vulns))]
		err := g.generateRiskScore(ctx, batch, run, h)
		if err == nil {
			continue
		}
		if errors.Is(err, llm.ErrTruncated) && len(batch) > 1 {
			half := (len(batch) + 1) / 2
			slog.WarnContext(ctx, "LLM truncated the batch; retrying with smaller batches",
				"from", len(batch), "to", half)
			if err := g.scoreInBatches(ctx, batch, half, run, h); err != nil {
				return err
			}
			continue
		}
		return err
	}
	return nil
}

func (g *Generator) generateRiskScore(ctx context.Context, vulnBatch []Vulnerability, run *scoringRun, h func([]outputhandler.VulnRating) error) error {
	if g.o.Config == nil {
		return errors.New("config not initialized; load config.yaml first")
	}

	// A CVE can affect several components in one batch, so group every component
	// under its VulnID. Keying by VulnID alone would keep only the last one.
	vulnsByID := make(map[string][]Vulnerability, len(vulnBatch))
	llmBatch := make([]LLMVulnerability, len(vulnBatch))
	for i, v := range vulnBatch {
		vulnsByID[v.VulnID] = append(vulnsByID[v.VulnID], v)
		llmBatch[i] = LLMVulnerability{
			VulnID:           v.VulnID,
			PkgID:            v.PkgID,
			PkgName:          v.PkgName,
			InstalledVersion: v.InstalledVersion,
			FixedVersion:     v.FixedVersion,
			Title:            v.Title,
			Description:      v.Description,
			Severity:         v.Severity,
		}
	}

	answers, err := g.scoreAll(ctx, llmBatch, run)
	if err != nil {
		return err
	}
	for _, a := range answers {
		run.scored[a.entry.VulnID] = true
	}

	group := make([]outputhandler.VulnRating, 0, len(vulnBatch))
	for _, answer := range answers {
		entry, evidenceRef := answer.entry, answer.evidenceRef

		// Calculate final OWASP score using the formula:
		// Risk = Likelihood × Impact = ((ThreatAgent + Vulnerability)/2) × ((TechImpact + BusinessImpact)/2)
		likelihoodScore := (entry.ThreatAgentScore + entry.VulnerabilityScore) / 2.0
		impactScore := (entry.TechnicalImpact + entry.BusinessImpact) / 2.0
		owaspScore := likelihoodScore * impactScore // Range: 0-81

		score := clampScore(owaspScore)
		severity := riskconfig.RiskSeverity(score)

		// Generate OWASP RR vector in standard format
		vector := owasp.FromAggregatedScores(
			entry.ThreatAgentScore,
			entry.VulnerabilityScore,
			entry.TechnicalImpact,
			entry.BusinessImpact,
		)
		vectorString := vector.String()

		comps := vulnsByID[entry.VulnID]
		if len(comps) == 0 {
			// Keep one rating even when the CVE isn't in the batch map (unchanged).
			comps = []Vulnerability{{VulnID: entry.VulnID}}
		}
		for _, v := range comps {
			slog.InfoContext(ctx, "Scored vulnerability",
				"vuln", entry.VulnID,
				"pkg", v.BOMRef,
				"score", fmt.Sprintf("%.1f", score),
				"severity", severity,
				"vector", vectorString,
			)

			var source *cyclonedx.Source
			if v.SourceName != "" {
				source = &cyclonedx.Source{
					Name: v.SourceName,
					URL:  v.SourceURL,
				}
			} else {
				source = vuln.Source(entry.VulnID)
			}

			s := score
			group = append(group, outputhandler.VulnRating{
				VulnID: entry.VulnID,
				BOMRef: v.BOMRef,
				Rating: cyclonedx.VulnerabilityRating{
					Method:   cyclonedx.ScoringMethodOWASP,
					Score:    &s,
					Severity: cyclonedx.Severity(severity),
					Vector:   vectorString,
				},
				Source: source,
			})

			if g.attestor != nil {
				g.attestor.AddClaim(evidenceRef, attestation.ClaimInput{
					VulnID:      entry.VulnID,
					CompRef:     v.BOMRef,
					CompName:    v.PkgName,
					CompVersion: v.InstalledVersion,
					PURL:        v.BOMRef,
					Score:       score,
					Severity:    severity,
					Reasoning:   entry.Reasoning,
				})
			}
		}
	}

	if len(group) == 0 {
		return nil
	}
	if h != nil {
		return h(group)
	}
	return nil
}

// answer pairs a model entry with the evidence bundle it came from. One bundle
// per LLM call, so every entry from the same call shares it.
type answer struct {
	entry       llmOutputEntry
	evidenceRef string
}

// tokenScore is the largest value the model writes on an impact axis as a
// placeholder when it declines an assessment instead of scoring it: [0 0 1 1]
// with "not reachable here" means the same as [0 0 0 1].
const tokenScore = 1

// declinedAssessment reports whether the model's answer is a declined
// assessment rather than a genuine low score: both likelihood factors are
// zero and the impact axes carry at most token values, so the OWASP score
// computes to ~0 while carrying no signal. A zero reached through a non-zero
// likelihood axis — e.g. CVE-2019-9192's [0 1 0 0] — is a genuine low score,
// not a declined one.
func declinedAssessment(e llmOutputEntry) bool {
	return e.ThreatAgentScore == 0 && e.VulnerabilityScore == 0 &&
		e.TechnicalImpact <= tokenScore && e.BusinessImpact <= tokenScore
}

// scoreAll scores every vulnerability in the batch. A model can leave some out of
// its answer without saying so, or answer with a declined assessment (zeros);
// those are asked for again on their own. Declined or still-unanswered CVEs after
// the retry don't fail the batch: they're recorded on the run and checked once,
// at the end of the run, so batch order never decides the outcome. CVEs an
// earlier batch already scored are never re-asked; their first score is reused
// so every component keeps its rows in the VEX.
func (g *Generator) scoreAll(ctx context.Context, batch []LLMVulnerability, run *scoringRun) ([]answer, error) {
	answers := make([]answer, 0, len(batch))
	scored := make(map[string]bool, len(batch))
	for id := range run.scored {
		scored[id] = true
	}
	declined := make(map[string]bool)

	collect := func(entries []llmOutputEntry, evidenceRef string) {
		for _, e := range entries {
			if e.VulnID == "" || scored[e.VulnID] {
				continue
			}
			if declinedAssessment(e) {
				// A declined assessment is the same as no answer: leave the
				// CVE unscored so it is asked for again below.
				declined[e.VulnID] = true
				run.declined[e.VulnID] = true
				delete(run.missing, e.VulnID)
				continue
			}
			delete(declined, e.VulnID)
			delete(run.declined, e.VulnID)
			delete(run.missing, e.VulnID)
			scored[e.VulnID] = true
			a := answer{entry: e, evidenceRef: evidenceRef}
			if _, ok := run.scores[e.VulnID]; !ok {
				run.scores[e.VulnID] = a
			}
			answers = append(answers, a)
		}
	}

	// reuseFirstScores appends the first score of every batch CVE an earlier
	// batch already scored, so this batch's components keep their rows in the
	// VEX even when the model doesn't answer the CVE again.
	reuseFirstScores := func() {
		seen := make(map[string]bool, len(answers))
		for _, a := range answers {
			seen[a.entry.VulnID] = true
		}
		for _, v := range batch {
			if v.VulnID == "" || seen[v.VulnID] {
				continue
			}
			if first, ok := run.scores[v.VulnID]; ok {
				answers = append(answers, first)
				seen[v.VulnID] = true
			}
		}
	}

	entries, evidenceRef, err := g.evaluateOWASPScores(ctx, batch)
	if err != nil {
		return nil, fmt.Errorf("LLM evaluation failed: %w", err)
	}
	collect(entries, evidenceRef)

	skipped := unscored(batch, scored)
	if len(skipped) == 0 {
		reuseFirstScores()
		return answers, nil
	}

	// Counts go by distinct CVE: one hitting several components is several rows.
	asked := len(unscored(batch, nil))

	slog.WarnContext(ctx, "Model skipped vulnerabilities; asking again for those alone",
		"skipped", len(skipped), "of", asked, "vulns", strings.Join(vulnIDs(skipped), ","))

	entries, evidenceRef, err = g.evaluateOWASPScores(ctx, skipped)
	if err != nil {
		return nil, fmt.Errorf("LLM evaluation failed while asking again for %d vulnerabilities: %w", len(skipped), err)
	}
	collect(entries, evidenceRef)

	// Declined or still-unanswered CVEs don't fail the batch: record them on
	// the run; GenerateRiskScore checks once, at the end of the run.
	for _, v := range unscored(batch, scored) {
		if declined[v.VulnID] || run.declined[v.VulnID] {
			run.declined[v.VulnID] = true
		} else {
			run.missing[v.VulnID] = true
		}
	}
	reuseFirstScores()
	return answers, nil
}

func vulnIDs(vs []LLMVulnerability) []string {
	ids := make([]string, len(vs))
	for i, v := range vs {
		ids[i] = v.VulnID
	}
	return ids
}

// unscored lists the vulnerabilities the model has not answered for, once each.
// A nil scored map lists them all.
func unscored(batch []LLMVulnerability, scored map[string]bool) []LLMVulnerability {
	var out []LLMVulnerability
	seen := make(map[string]bool, len(batch))
	for _, v := range batch {
		if v.VulnID == "" || scored[v.VulnID] || seen[v.VulnID] {
			continue
		}
		seen[v.VulnID] = true
		out = append(out, v)
	}
	return out
}

// evaluateOWASPScores calls the LLM to calculate the OWASP risk score for each vulnerability.
// The LLM uses the project context hints to determine the appropriate score.
func (g *Generator) evaluateOWASPScores(ctx context.Context, vulns []LLMVulnerability) ([]llmOutputEntry, string, error) {
	if g.o.LLM == nil {
		return nil, "", errors.New("no LLM configured")
	}

	systemPrompt := g.buildSystemPrompt()

	// Build the JSON schema for structured output and embed it in the prompt so
	// the contract is self-documented even for weaker models.
	schema := g.buildOutputSchema()
	systemPrompt += "#### Output format: JSON Schema\n"
	systemPrompt += string(schema) + "\n"
	systemPrompt += "#### Output Example\n"
	systemPrompt += "```json\n" + g.buildOutputExample() + "\n```\n"

	vulnsJSON, err := json.Marshal(vulns)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal vulnerabilities: %w", err)
	}
	humanPrompt := string(vulnsJSON)

	if g.o.DebugDir != "" {
		if err := os.WriteFile(filepath.Join(g.o.DebugDir, "system.prompt"), []byte(systemPrompt), 0644); err != nil {
			slog.ErrorContext(ctx, "failed to write system.prompt", "error", err)
		}
		if err := os.WriteFile(filepath.Join(g.o.DebugDir, "human.prompt"), []byte(humanPrompt), 0644); err != nil {
			slog.ErrorContext(ctx, "failed to write human.prompt", "error", err)
		}
	}

	req := llm.Request{
		System:      systemPrompt,
		Human:       humanPrompt,
		Schema:      schema,
		Temperature: g.o.Temperature,
		Seed:        g.o.Seed,
	}

	var raw string
	if err := llm.RetryOnRateLimit(ctx, g.o.SleepOnRateLimit, g.o.RetryOnRateLimit, func(c context.Context) error {
		var e error
		raw, e = g.o.LLM.Generate(c, req)
		return e
	}); err != nil {
		return nil, "", err
	}

	var evidenceRef string
	if g.attestor != nil {
		evidenceRef = g.attestor.AddBatch(systemPrompt, humanPrompt, []byte(raw))
	}

	var resp llmOutput
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return nil, "", fmt.Errorf("unable to parse LLM output: %w: %q", err, raw)
	}

	for i := range resp.Results {
		entry := &resp.Results[i]

		entry.ThreatAgentScore = clampScore09(entry.ThreatAgentScore)
		entry.VulnerabilityScore = clampScore09(entry.VulnerabilityScore)
		entry.TechnicalImpact = clampScore09(entry.TechnicalImpact)
		entry.BusinessImpact = clampScore09(entry.BusinessImpact)

		slog.DebugContext(ctx, "owasp_components",
			"vuln", entry.VulnID,
			"threat_agent", entry.ThreatAgentScore,
			"vulnerability", entry.VulnerabilityScore,
			"technical_impact", entry.TechnicalImpact,
			"business_impact", entry.BusinessImpact,
			"reasoning", entry.Reasoning,
		)
	}

	return resp.Results, evidenceRef, nil
}

// buildSystemPrompt creates the system prompt for OWASP score calculation.
// Inspired by github.com/AkihiroSuda/vexllm prompt structure.
func (g *Generator) buildSystemPrompt() string {
	prompt := `You are a talented security expert scoring vulnerabilities using OWASP Risk Rating Methodology.

SYSTEM CONTEXT:
`
	if g.o.Config != nil {
		prompt += g.o.Config.FormatForLLM()
	}

	prompt += `
TASK: For EACH vulnerability, analyze its specific characteristics and score 4 factors (0-9):

1. THREAT_AGENT (Who can exploit THIS vuln in THIS system?)
   - Consider: Does system exposure match vuln attack vector?
   - Internet-exposed remote vuln: 7-9 | Private network local vuln: 3-5 | Mismatch: lower
   - Adjust for attacker motivation based on business value

2. VULNERABILITY (How exploitable is THIS specific vuln?)
   CRITICAL: Score the ACTUAL vulnerability, not the system
   - Analyze: CVE/description reveals public exploits? Known PoC? Automated scanners detect it?
   - Easy discovery + exploit available: 7-9 | Requires expertise: 4-6 | Theoretical/complex: 1-3`

	if g.o.Config != nil {
		controls := g.o.Config.Context.Controls
		hasControls := controls.WAF || controls.IDS || controls.EDR || controls.Segmentation || controls.ZeroTrust
		if hasControls {
			prompt += `
   - Reduce if controls block this vuln type (WAF blocks web exploits, IDS detects network attacks)`
		}
	}

	prompt += `

3. TECHNICAL_IMPACT (What does THIS vuln compromise?)
   - Identify what the vulnerability exposes (confidentiality/integrity/availability/accountability)
   - Map impact to system sensitivity:`

	prompt += `
     * C/I breach: score = data_sensitivity`
	if g.o.Config != nil && g.o.Config.Context.AvailabilityRequirement != nil {
		prompt += `
     * Availability loss: score = availability_requirement`
	} else {
		prompt += `
     * Availability loss: score = business_criticality`
	}
	if g.o.Config != nil && g.o.Config.Context.AuditRequirement != nil {
		prompt += `
     * Accountability loss: score = audit_requirement`
	}

	prompt += `
   - Return highest applicable score

4. BUSINESS_IMPACT (Business damage if THIS vuln exploited?)
   - Base: business_criticality`

	if g.o.Config != nil && len(g.o.Config.Context.ComplianceRequirements) > 0 {
		prompt += `
   - +2 if vuln triggers compliance violation (data breach/audit failure)`
	}
	prompt += `
   - Cap at 9

SCORING SCALE: low:1-3, medium:4-6, high:7-8, critical:9
OUTPUT: 4 scores (0-9) + brief reasoning for THIS specific vulnerability in THIS context.
`
	return prompt
}

// buildOutputSchema returns the JSON Schema the LLM output must satisfy.
// Every property is required and additionalProperties is false so the schema is
// valid for OpenAI strict mode; the same document is then enforced natively by
// each provider.
func (g *Generator) buildOutputSchema() json.RawMessage {
	return json.RawMessage(outputSchema)
}

const outputSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "results": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "vulnId": {"type": "string", "description": "The vulnerability ID from the input (e.g., CVE-2024-1234)"},
          "threat_agent_score": {"type": "number", "description": "Threat Agent score (0-9): skill level, motive, opportunity, size"},
          "vulnerability_score": {"type": "number", "description": "Vulnerability score (0-9): ease of discovery, ease of exploit"},
          "technical_impact": {"type": "number", "description": "Technical Impact score (0-9): loss of confidentiality, integrity, availability, accountability"},
          "business_impact": {"type": "number", "description": "Business Impact score (0-9): financial damage, reputation damage, non-compliance, privacy violation"},
          "reasoning": {"type": "string", "description": "Brief explanation of each score (2-3 sentences)"}
        },
        "required": ["vulnId", "threat_agent_score", "vulnerability_score", "technical_impact", "business_impact", "reasoning"]
      }
    }
  },
  "required": ["results"]
}`

// buildOutputExample returns an example output for the LLM.
func (g *Generator) buildOutputExample() string {
	return `{
  "results": [
    {
      "vulnId": "CVE-2024-1234",
      "threat_agent_score": 8,
      "vulnerability_score": 7,
      "technical_impact": 8,
      "business_impact": 9,
      "reasoning": "RCE in OpenSSL: ThreatAgent=8 (internet-exposed, attracts skilled attackers), Vulnerability=7 (known exploit exists), TechImpact=8 (full system compromise), BusinessImpact=9 (critical system + compliance risk)"
    },
    {
      "vulnId": "CVE-2024-5678",
      "threat_agent_score": 3,
      "vulnerability_score": 4,
      "technical_impact": 4,
      "business_impact": 5,
      "reasoning": "DoS in logging lib: ThreatAgent=3 (internal only), Vulnerability=4 (requires config), TechImpact=4 (availability impact medium), BusinessImpact=5 (medium criticality system)"
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

// clampScore09 ensures a component score is within [0, 9].
func clampScore09(v float64) float64 {
	if v < 0.0 {
		return 0.0
	}
	if v > 9.0 {
		return 9.0
	}
	return v
}
