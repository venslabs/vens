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
	"strings"

	"go.yaml.in/yaml/v3"
)

// Config represents the structure of config.yaml provided by users.
// The schema uses textual context hints that help the LLM calculate
// accurate OWASP risk scores for each vulnerability.
//
// Example YAML:
//
//	project:
//	  name: "nginx-production"
//	  description: "Production NGINX web server"
//
//	context:
//	  exposure: "internet"           # internal | private | internet
//	  data_sensitivity: "high"       # low | medium | high | critical
//	  business_criticality: "critical" # low | medium | high | critical
//	  notes: "Handles customer PII, PCI-DSS compliance required"
//
// The LLM uses these context hints to evaluate the OWASP risk score
// for each vulnerability according to the OWASP Risk Rating Methodology.
type Config struct {
	Project ProjectConfig `yaml:"project"`
	Context ContextHints  `yaml:"context"`
}

// ProjectConfig holds project metadata for context in LLM analysis.
type ProjectConfig struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
}

// ContextHints holds textual hints that describe the project's risk context.
// These hints help the LLM calculate accurate OWASP risk scores.
// Reference: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
type ContextHints struct {
	// Exposure describes how the system is exposed to potential attackers.
	// Values: "internal" (corporate network only), "private" (VPN/authenticated),
	//         "internet" (publicly accessible)
	Exposure string `yaml:"exposure"`

	// DataSensitivity describes the sensitivity of data handled by the system.
	// Values: "low" (public data), "medium" (internal data),
	//         "high" (PII, financial), "critical" (secrets, credentials, PHI)
	DataSensitivity string `yaml:"data_sensitivity"`

	// BusinessCriticality describes how critical the system is for business operations.
	// Values: "low" (dev/test), "medium" (internal tools),
	//         "high" (customer-facing), "critical" (revenue-critical, compliance)
	BusinessCriticality string `yaml:"business_criticality"`

	// Notes provides additional context in free-form text (optional).
	// Examples: "PCI-DSS compliance required", "Handles authentication tokens",
	//           "Connected to production database"
	Notes string `yaml:"notes,omitempty"`
}

// Valid values for context hints
var (
	validExposure            = []string{"internal", "private", "internet"}
	validDataSensitivity     = []string{"low", "medium", "high", "critical"}
	validBusinessCriticality = []string{"low", "medium", "high", "critical"}
)

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

	// Validate context hints
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validate checks that all context hints have valid values.
func (c *Config) validate() error {
	if c.Project.Name == "" {
		return fmt.Errorf("project.name is required")
	}

	// Normalize values to lowercase
	c.Context.Exposure = strings.ToLower(strings.TrimSpace(c.Context.Exposure))
	c.Context.DataSensitivity = strings.ToLower(strings.TrimSpace(c.Context.DataSensitivity))
	c.Context.BusinessCriticality = strings.ToLower(strings.TrimSpace(c.Context.BusinessCriticality))

	if c.Context.Exposure == "" {
		return fmt.Errorf("context.exposure is required (valid values: %v)", validExposure)
	}
	if !contains(validExposure, c.Context.Exposure) {
		return fmt.Errorf("context.exposure must be one of %v, got %q", validExposure, c.Context.Exposure)
	}

	if c.Context.DataSensitivity == "" {
		return fmt.Errorf("context.data_sensitivity is required (valid values: %v)", validDataSensitivity)
	}
	if !contains(validDataSensitivity, c.Context.DataSensitivity) {
		return fmt.Errorf("context.data_sensitivity must be one of %v, got %q", validDataSensitivity, c.Context.DataSensitivity)
	}

	if c.Context.BusinessCriticality == "" {
		return fmt.Errorf("context.business_criticality is required (valid values: %v)", validBusinessCriticality)
	}
	if !contains(validBusinessCriticality, c.Context.BusinessCriticality) {
		return fmt.Errorf("context.business_criticality must be one of %v, got %q", validBusinessCriticality, c.Context.BusinessCriticality)
	}

	return nil
}

// FormatForLLM returns a formatted string representation of the context
// suitable for inclusion in LLM prompts.
func (c *Config) FormatForLLM() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Project: %s\n", c.Project.Name))
	if c.Project.Description != "" {
		sb.WriteString(fmt.Sprintf("Description: %s\n", c.Project.Description))
	}
	sb.WriteString(fmt.Sprintf("Exposure: %s\n", c.Context.Exposure))
	sb.WriteString(fmt.Sprintf("Data Sensitivity: %s\n", c.Context.DataSensitivity))
	sb.WriteString(fmt.Sprintf("Business Criticality: %s\n", c.Context.BusinessCriticality))
	if c.Context.Notes != "" {
		sb.WriteString(fmt.Sprintf("Additional Notes: %s\n", c.Context.Notes))
	}
	return sb.String()
}

// RiskSeverity returns a human-readable severity level based on the OWASP risk score.
// Based on OWASP Risk Rating: score range is [0, 81].
// Returns lowercase severity strings compatible with CycloneDX specification.
// Reference: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
func RiskSeverity(score float64) string {
	switch {
	case score >= 60:
		return "critical"
	case score >= 40:
		return "high"
	case score >= 20:
		return "medium"
	case score >= 5:
		return "low"
	default:
		return "info"
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
