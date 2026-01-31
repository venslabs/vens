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
	// Maps to: OWASP Threat Agent Factors (Opportunity, Size)
	Exposure string `yaml:"exposure"`

	// DataSensitivity describes the sensitivity of data handled by the system.
	// Values: "low" (public data), "medium" (internal data),
	//         "high" (PII, financial), "critical" (secrets, credentials, PHI)
	// Maps to: OWASP Technical Impact (Loss of Confidentiality, Loss of Integrity)
	DataSensitivity string `yaml:"data_sensitivity"`

	// BusinessCriticality describes how critical the system is for business operations.
	// Values: "low" (dev/test), "medium" (internal tools),
	//         "high" (customer-facing), "critical" (revenue-critical, compliance)
	// Maps to: OWASP Business Impact (Financial Damage, Reputation Damage)
	BusinessCriticality string `yaml:"business_criticality"`

	// AvailabilityRequirement describes how critical system availability is.
	// Values: "low" (best-effort), "medium" (business hours SLA),
	//         "high" (24/7 required), "critical" (zero downtime, lives at risk)
	// Maps to: OWASP Technical Impact (Loss of Availability)
	// Default: nil (inherits from business_criticality if not specified)
	// Optional: Only needed if availability criticality differs from business criticality
	AvailabilityRequirement *string `yaml:"availability_requirement,omitempty"`

	// ComplianceRequirements lists regulatory/compliance frameworks that apply.
	// Values: "PCI-DSS", "HIPAA", "GDPR", "SOX", "ISO27001", "FedRAMP", etc.
	// Maps to: OWASP Business Impact (Non-Compliance)
	// Default: nil (no compliance requirements)
	// Optional: Specify if system must comply with regulations
	ComplianceRequirements []string `yaml:"compliance_requirements,omitempty"`

	// AuditRequirement describes the importance of audit logging and traceability.
	// Values: "low" (basic logging), "medium" (audit trail required),
	//         "high" (forensic-grade logging, immutable audit)
	// Maps to: OWASP Technical Impact (Loss of Accountability)
	// Default: nil (no special audit requirements)
	// Optional: Only needed for systems with strong audit requirements
	AuditRequirement *string `yaml:"audit_requirement,omitempty"`

	// Controls describes the security controls in place to defend the system.
	// These controls affect the Vulnerability Factor score (ease of exploit).
	// All controls are optional and default to false (no control in place).
	Controls SecurityControls `yaml:"controls,omitempty"`

	// Notes provides additional context in free-form text (optional).
	// Examples: "Handles authentication tokens", "Connected to production database"
	Notes string `yaml:"notes,omitempty"`
}

// SecurityControls describes the security defenses in place.
// These controls affect the OWASP Vulnerability Factor score by making
// vulnerabilities harder to discover and exploit.
type SecurityControls struct {
	// Perimeter controls
	WAF            bool `yaml:"waf,omitempty"`             // Web Application Firewall
	DDoSProtection bool `yaml:"ddos_protection,omitempty"` // DDoS mitigation service

	// Detection controls
	IDS  bool `yaml:"ids,omitempty"`  // Intrusion Detection System
	SIEM bool `yaml:"siem,omitempty"` // Security Information & Event Management

	// Endpoint controls
	EDR       bool `yaml:"edr,omitempty"`       // Endpoint Detection & Response
	Antivirus bool `yaml:"antivirus,omitempty"` // Antivirus/Anti-malware

	// Network controls
	Segmentation bool `yaml:"segmentation,omitempty"` // Network micro-segmentation
	ZeroTrust    bool `yaml:"zero_trust,omitempty"`   // Zero-trust architecture
}

// Valid values for context hints
var (
	validExposure                = []string{"internal", "private", "internet"}
	validDataSensitivity         = []string{"low", "medium", "high", "critical"}
	validBusinessCriticality     = []string{"low", "medium", "high", "critical"}
	validAvailabilityRequirement = []string{"low", "medium", "high", "critical"}
	validAuditRequirement        = []string{"low", "medium", "high"}
	validComplianceFrameworks    = []string{
		"PCI-DSS", "HIPAA", "GDPR", "SOX", "ISO27001", "FedRAMP",
		"NIST", "CCPA", "SOC2", "FISMA", "ITAR", "CMMC",
	}
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

// validate checks that all context hints have valid values and applies defaults.
func (c *Config) validate() error {
	if c.Project.Name == "" {
		return fmt.Errorf("project.name is required")
	}

	// Validate required fields
	if c.Context.Exposure == "" {
		return fmt.Errorf("context.exposure is required (valid values: %v)", validExposure)
	}
	if c.Context.DataSensitivity == "" {
		return fmt.Errorf("context.data_sensitivity is required (valid values: %v)", validDataSensitivity)
	}
	if c.Context.BusinessCriticality == "" {
		return fmt.Errorf("context.business_criticality is required (valid values: %v)", validBusinessCriticality)
	}

	// Normalize required values to lowercase
	c.Context.Exposure = strings.ToLower(strings.TrimSpace(c.Context.Exposure))
	c.Context.DataSensitivity = strings.ToLower(strings.TrimSpace(c.Context.DataSensitivity))
	c.Context.BusinessCriticality = strings.ToLower(strings.TrimSpace(c.Context.BusinessCriticality))

	// Normalize optional pointer values
	if c.Context.AvailabilityRequirement != nil {
		normalized := strings.ToLower(strings.TrimSpace(*c.Context.AvailabilityRequirement))
		c.Context.AvailabilityRequirement = &normalized
	}
	if c.Context.AuditRequirement != nil {
		normalized := strings.ToLower(strings.TrimSpace(*c.Context.AuditRequirement))
		c.Context.AuditRequirement = &normalized
	}

	// Validate normalized values against valid options
	if !contains(validExposure, c.Context.Exposure) {
		return fmt.Errorf("context.exposure must be one of %v, got %q", validExposure, c.Context.Exposure)
	}
	if !contains(validDataSensitivity, c.Context.DataSensitivity) {
		return fmt.Errorf("context.data_sensitivity must be one of %v, got %q", validDataSensitivity, c.Context.DataSensitivity)
	}
	if !contains(validBusinessCriticality, c.Context.BusinessCriticality) {
		return fmt.Errorf("context.business_criticality must be one of %v, got %q", validBusinessCriticality, c.Context.BusinessCriticality)
	}

	// Validate optional fields if provided (no defaults applied)
	if c.Context.AvailabilityRequirement != nil {
		if !contains(validAvailabilityRequirement, *c.Context.AvailabilityRequirement) {
			return fmt.Errorf("context.availability_requirement must be one of %v, got %q", validAvailabilityRequirement, *c.Context.AvailabilityRequirement)
		}
	}

	if c.Context.AuditRequirement != nil {
		if !contains(validAuditRequirement, *c.Context.AuditRequirement) {
			return fmt.Errorf("context.audit_requirement must be one of %v, got %q", validAuditRequirement, *c.Context.AuditRequirement)
		}
	}

	// Validate compliance requirements
	for _, framework := range c.Context.ComplianceRequirements {
		if !containsCaseInsensitive(validComplianceFrameworks, framework) {
			return fmt.Errorf("context.compliance_requirements contains unknown framework %q (valid: %v)", framework, validComplianceFrameworks)
		}
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

	// Required fields
	sb.WriteString(fmt.Sprintf("Exposure: %s\n", c.Context.Exposure))
	sb.WriteString(fmt.Sprintf("Data Sensitivity: %s\n", c.Context.DataSensitivity))
	sb.WriteString(fmt.Sprintf("Business Criticality: %s\n", c.Context.BusinessCriticality))

	// Optional fields - only show if explicitly provided
	if c.Context.AvailabilityRequirement != nil {
		sb.WriteString(fmt.Sprintf("Availability Requirement: %s\n", *c.Context.AvailabilityRequirement))
	}

	if len(c.Context.ComplianceRequirements) > 0 {
		sb.WriteString(fmt.Sprintf("Compliance Requirements: %s\n", strings.Join(c.Context.ComplianceRequirements, ", ")))
	}

	if c.Context.AuditRequirement != nil {
		sb.WriteString(fmt.Sprintf("Audit Requirement: %s\n", *c.Context.AuditRequirement))
	}

	// Format security controls if any are enabled
	controls := c.Context.Controls
	var activeControls []string
	if controls.WAF {
		activeControls = append(activeControls, "WAF")
	}
	if controls.DDoSProtection {
		activeControls = append(activeControls, "DDoS Protection")
	}
	if controls.IDS {
		activeControls = append(activeControls, "IDS")
	}
	if controls.SIEM {
		activeControls = append(activeControls, "SIEM")
	}
	if controls.EDR {
		activeControls = append(activeControls, "EDR")
	}
	if controls.Antivirus {
		activeControls = append(activeControls, "Antivirus")
	}
	if controls.Segmentation {
		activeControls = append(activeControls, "Network Segmentation")
	}
	if controls.ZeroTrust {
		activeControls = append(activeControls, "Zero Trust")
	}

	if len(activeControls) > 0 {
		sb.WriteString(fmt.Sprintf("Security Controls: %s\n", strings.Join(activeControls, ", ")))
	}

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

func containsCaseInsensitive(slice []string, item string) bool {
	itemLower := strings.ToLower(item)
	for _, s := range slice {
		if strings.ToLower(s) == itemLower {
			return true
		}
	}
	return false
}
