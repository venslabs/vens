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

package riskconfig

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

// Config represents the structure of config.yaml provided by users.
// The schema follows OWASP Risk Rating Methodology with 4 base factors.
//
// Example YAML:
//
//	project:
//	  name: "nginx-production"
//	  description: "Production NGINX web server"
//
//	owasp:
//	  threat_agent: 7      # 0-9: Who might attack?
//	  vulnerability: 6     # 0-9: How easy to exploit?
//	  technical_impact: 7  # 0-9: Damage to systems?
//	  business_impact: 8   # 0-9: Business consequences?
//
// The LLM will evaluate how much each vulnerability contributes to these
// base factors (as percentages), then compute the final weighted risk score.
type Config struct {
	Project ProjectConfig `yaml:"project"`
	OWASP   OWASPFactors  `yaml:"owasp"`
}

// ProjectConfig holds project metadata for context in LLM analysis.
type ProjectConfig struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
}

// OWASPFactors holds the 4 base OWASP risk factors (0-9 scale each).
// Reference: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
//
// Likelihood factors:
//   - ThreatAgent: Skill, motivation, and opportunity of potential attackers
//   - Vulnerability: Ease of discovery and exploitation
//
// Impact factors:
//   - TechnicalImpact: Damage to systems, data, and infrastructure
//   - BusinessImpact: Financial, reputation, and compliance consequences
type OWASPFactors struct {
	// === LIKELIHOOD FACTORS ===

	// ThreatAgent represents who might attack (0-9)
	// 0-3: Script kiddies, opportunistic attacks
	// 4-6: Skilled attackers, moderate resources
	// 7-9: Organized crime, nation-states, APT groups
	ThreatAgent float64 `yaml:"threat_agent"`

	// Vulnerability represents how easy it is to find and exploit (0-9)
	// 0-3: Very difficult, requires insider knowledge
	// 4-6: Public CVEs, some tools available
	// 7-9: Trivial, automated scanners, known exploits
	Vulnerability float64 `yaml:"vulnerability"`

	// === IMPACT FACTORS ===

	// TechnicalImpact represents damage to systems (0-9)
	// 0-3: Minor data disclosure, limited access
	// 4-6: Significant data loss, service disruption
	// 7-9: Complete system compromise, data destruction
	TechnicalImpact float64 `yaml:"technical_impact"`

	// BusinessImpact represents consequences for the business (0-9)
	// 0-3: Minimal financial/reputation loss
	// 4-6: Moderate losses, customer complaints
	// 7-9: Bankruptcy risk, regulatory fines, brand destruction
	BusinessImpact float64 `yaml:"business_impact"`
}

// Load parses a config.yaml file from the given path and validates entries.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}

	// Validate OWASP factors are in valid range [0, 9]
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validate checks that all OWASP factors are within the valid range [0, 9].
func (c *Config) validate() error {
	factors := map[string]float64{
		"threat_agent":     c.OWASP.ThreatAgent,
		"vulnerability":    c.OWASP.Vulnerability,
		"technical_impact": c.OWASP.TechnicalImpact,
		"business_impact":  c.OWASP.BusinessImpact,
	}

	for name, value := range factors {
		if !inRange09(value) {
			return fmt.Errorf("OWASP factor %q must be between 0 and 9, got %.2f", name, value)
		}
	}
	return nil
}

// ComputeBaseRisk calculates the base OWASP risk score without LLM adjustments.
// Formula: Risk = Likelihood × Impact
// Where: Likelihood = (ThreatAgent + Vulnerability) / 2
//
//	Impact = (TechnicalImpact + BusinessImpact) / 2
//
// Result is in range [0, 81] (9 × 9 max).
func (c *Config) ComputeBaseRisk() float64 {
	likelihood := (c.OWASP.ThreatAgent + c.OWASP.Vulnerability) / 2.0
	impact := (c.OWASP.TechnicalImpact + c.OWASP.BusinessImpact) / 2.0
	return likelihood * impact
}

// ComputeWeightedRisk calculates the risk score adjusted by LLM contribution percentages.
// Each contribution is a percentage (0.0 to 1.0) representing how much the specific
// vulnerability contributes to each OWASP factor.
//
// Formula:
//
//	Likelihood = (ThreatAgent × threatAgentContrib + Vulnerability × vulnContrib) / 2
//	Impact = (TechnicalImpact × techContrib + BusinessImpact × bizContrib) / 2
//	Risk = Likelihood × Impact
func (c *Config) ComputeWeightedRisk(contributions OWASPContributions) float64 {
	weightedThreatAgent := c.OWASP.ThreatAgent * contributions.ThreatAgent
	weightedVulnerability := c.OWASP.Vulnerability * contributions.Vulnerability
	weightedTechnicalImpact := c.OWASP.TechnicalImpact * contributions.TechnicalImpact
	weightedBusinessImpact := c.OWASP.BusinessImpact * contributions.BusinessImpact

	likelihood := (weightedThreatAgent + weightedVulnerability) / 2.0
	impact := (weightedTechnicalImpact + weightedBusinessImpact) / 2.0
	return likelihood * impact
}

// OWASPContributions holds the LLM-evaluated contribution percentages for each factor.
// Each value is a percentage between 0.0 (0%) and 1.0 (100%).
type OWASPContributions struct {
	ThreatAgent     float64 `json:"threat_agent_contribution"`
	Vulnerability   float64 `json:"vulnerability_contribution"`
	TechnicalImpact float64 `json:"technical_impact_contribution"`
	BusinessImpact  float64 `json:"business_impact_contribution"`
}

// RiskSeverity returns a human-readable severity level based on the risk score.
// Based on OWASP Risk Rating: score range is [0, 81].
func RiskSeverity(score float64) string {
	switch {
	case score >= 60:
		return "CRITICAL"
	case score >= 40:
		return "HIGH"
	case score >= 20:
		return "MEDIUM"
	case score >= 5:
		return "LOW"
	default:
		return "NOTE"
	}
}

func inRange09(v float64) bool { return v >= 0 && v <= 9 }
