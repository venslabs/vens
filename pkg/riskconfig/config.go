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
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// SchemaVersion is the version of the config.yaml format this vens reads.
const SchemaVersion = 2

// Config is config.yaml: the deployment every finding is scored in. Go reads
// some fields itself to set an OWASP factor's level and never sends them;
// others are shown to the model with their documented meaning; a few move no
// score and are kept as information.
//
// Example YAML:
//
//	schema_version: 2
//	project:
//	  name: "nginx-production"
//	  description: "Production NGINX web server"
//	context:
//	  exposure: "internet"
//	  data_sensitivity: "high"
//	  business_criticality: "critical"
//	  notes: "Handles customer PII, PCI-DSS compliance required"
type Config struct {
	// SchemaVersion must be 2. A file without it was written for vens v0.6
	// or earlier, schema 1, and is refused.
	SchemaVersion int           `yaml:"schema_version"`
	Project       ProjectConfig `yaml:"project"`
	Context       ContextHints  `yaml:"context"`
}

// ProjectConfig names the deployment in every question's deployment block.
type ProjectConfig struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
}

// ContextHints describes the deployment. Each field says which OWASP factor
// reads it and how.
type ContextHints struct {
	// Exposure is internal, private or internet: Size's level in Go and the
	// attacker group every likelihood question names, shown in the
	// deployment block with its meaning.
	Exposure string `yaml:"exposure"`

	// DataSensitivity is low, medium, high or critical: Loss of
	// confidentiality's column in Go (low and medium non-sensitive, high and
	// critical critical), hidden from that question; background to Motive,
	// Loss of integrity and Privacy violation.
	DataSensitivity string `yaml:"data_sensitivity"`

	// BusinessCriticality is low, medium, high or critical: background to
	// Motive, Financial damage and Reputation damage, and to Loss of
	// availability when AvailabilityRequirement is unset.
	BusinessCriticality string `yaml:"business_criticality"`

	// AvailabilityRequirement is low, medium, high or critical: background
	// to Loss of availability. nil: BusinessCriticality stands in.
	AvailabilityRequirement *string `yaml:"availability_requirement,omitempty"`

	// ComplianceRequirements are the frameworks Non-compliance asks about.
	// Empty: Non-compliance is 2 and not asked.
	ComplianceRequirements []string `yaml:"compliance_requirements,omitempty"`

	// AuditRequirement is low, medium or high. It states a requirement, not
	// what is recorded, so it moves no score and is sent nowhere; kept as
	// information. Traceability states what is recorded.
	AuditRequirement *string `yaml:"audit_requirement,omitempty"`

	// Listener is present, absent or unknown: whether the deployment accepts
	// connections others open. Shown in the deployment block when present or
	// absent. Omitted, it reads unknown.
	Listener string `yaml:"listener,omitempty"`

	// DataSubjects is the band of people whose personal data the service can
	// read: Privacy violation's cap, in Go, never sent. nil: no cap.
	DataSubjects *string `yaml:"data_subjects,omitempty"`

	// Detection is what records an attempt on each channel: Intrusion
	// detection, in Go, never sent. nil: every channel not logged, 9.
	Detection *DetectionCoverage `yaml:"detection,omitempty"`

	// Traceability is none, per_request or per_individual: Loss of
	// accountability's column, in Go, never sent. nil: the none column.
	Traceability *string `yaml:"traceability,omitempty"`

	// Controls are the security controls in operation.
	Controls SecurityControls `yaml:"controls,omitempty"`

	// Notes is free text shown in every question's deployment block.
	Notes string `yaml:"notes,omitempty"`
}

// DetectionCoverage declares, per channel, what records an attempt across
// the whole service. Once detection is written, all three are required.
type DetectionCoverage struct {
	Network     string `yaml:"network"`
	Host        string `yaml:"host"`
	Application string `yaml:"application"`
}

// SecurityControls are booleans, default false. WAF, DDoSProtection,
// Segmentation, ZeroTrust and Antivirus are shown, when true and with their
// documented scope, to the Ease of exploit question only. IDS, SIEM and EDR
// say a tool exists, not that this service's attempts are recorded: they
// move no score and are sent nowhere. Detection states coverage.
type SecurityControls struct {
	WAF            bool `yaml:"waf,omitempty"`
	DDoSProtection bool `yaml:"ddos_protection,omitempty"`
	IDS            bool `yaml:"ids,omitempty"`
	SIEM           bool `yaml:"siem,omitempty"`
	EDR            bool `yaml:"edr,omitempty"`
	Antivirus      bool `yaml:"antivirus,omitempty"`
	Segmentation   bool `yaml:"segmentation,omitempty"`
	ZeroTrust      bool `yaml:"zero_trust,omitempty"`
}

// byKey maps each control's YAML key to its field in s.
func (s *SecurityControls) byKey() map[string]*bool {
	return map[string]*bool{
		"waf": &s.WAF, "ddos_protection": &s.DDoSProtection, "ids": &s.IDS, "siem": &s.SIEM,
		"edr": &s.EDR, "antivirus": &s.Antivirus, "segmentation": &s.Segmentation, "zero_trust": &s.ZeroTrust,
	}
}

// Enable returns s with the control named by its YAML key set to true, and
// false when no control has that key.
func (s SecurityControls) Enable(key string) (SecurityControls, bool) {
	on := s.byKey()[key]
	if on == nil {
		return s, false
	}
	*on = true
	return s, true
}

// Enabled reports whether the control named by its YAML key is set to true,
// false for a key no control has.
func (s SecurityControls) Enabled(key string) bool {
	on := s.byKey()[key]
	return on != nil && *on
}

// Parse loads config.yaml from its bytes. It reads the YAML tree first, so
// that the marker, the shape of the schema-2 keys and unknown keys fail with
// errors naming the YAML path, then decodes strictly and validates.
func Parse(b []byte) (*Config, error) {
	root, err := rootMapping(b)
	if err != nil {
		return nil, err
	}
	if err := checkSchemaVersion(root, b); err != nil {
		return nil, err
	}
	if err := checkSchema2Keys(root); err != nil {
		return nil, err
	}
	if err := checkKnownKeys(root, reflect.TypeFor[Config](), ""); err != nil {
		return nil, err
	}
	var decoded Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}
	cfg, err := decoded.validated()
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

// validated returns c with its values normalized, or the first value that
// keeps it from loading. An empty listener reads unknown: Parse has already
// refused one written empty, so only an omitted key or a struct literal
// reaches here with it.
func (c Config) validated() (Config, error) {
	if c.Project.Name == "" {
		return Config{}, fmt.Errorf("project.name is required")
	}
	for _, f := range []struct {
		field Field
		value string
	}{
		{Exposure, c.Context.Exposure},
		{DataSensitivity, c.Context.DataSensitivity},
		{BusinessCriticality, c.Context.BusinessCriticality},
	} {
		if f.value == "" {
			return Config{}, fmt.Errorf("%s is required (valid values: %v)", f.field.Path(), f.field.Values())
		}
	}
	n := c
	n.Context = c.Context.normalized()
	if err := n.Context.checkSchema1Values(); err != nil {
		return Config{}, err
	}
	if err := n.Context.checkSchema2Values(); err != nil {
		return Config{}, err
	}
	return n, nil
}

func (h ContextHints) normalized() ContextHints {
	n := h
	n.Exposure = normalize(h.Exposure)
	n.DataSensitivity = normalize(h.DataSensitivity)
	n.BusinessCriticality = normalize(h.BusinessCriticality)
	n.AvailabilityRequirement = normalizePtr(h.AvailabilityRequirement)
	n.AuditRequirement = normalizePtr(h.AuditRequirement)
	n.Listener = normalize(h.Listener)
	if n.Listener == "" {
		n.Listener = listenerUnknown
	}
	n.DataSubjects = normalizePtr(h.DataSubjects)
	n.Traceability = normalizePtr(h.Traceability)
	if h.Detection != nil {
		n.Detection = &DetectionCoverage{
			Network:     normalize(h.Detection.Network),
			Host:        normalize(h.Detection.Host),
			Application: normalize(h.Detection.Application),
		}
	}
	return n
}

func (h ContextHints) checkSchema1Values() error {
	for _, f := range []struct {
		field Field
		value *string
	}{
		{Exposure, &h.Exposure},
		{DataSensitivity, &h.DataSensitivity},
		{BusinessCriticality, &h.BusinessCriticality},
		{AvailabilityRequirement, h.AvailabilityRequirement},
		{AuditRequirement, h.AuditRequirement},
	} {
		if f.value != nil && !f.field.accepts(*f.value) {
			return fmt.Errorf("%s must be one of %v, got %q", f.field.Path(), f.field.Values(), *f.value)
		}
	}
	for _, framework := range h.ComplianceRequirements {
		// Lowercased equality, as schema 1 matched: EqualFold would also take
		// Unicode case folds such as ſOX for SOX.
		lower := strings.ToLower(framework)
		if !slices.ContainsFunc(complianceFrameworks, func(v string) bool { return strings.ToLower(v) == lower }) {
			return fmt.Errorf("context.compliance_requirements contains unknown framework %q (valid: %v)", framework, complianceFrameworks)
		}
	}
	return nil
}

func (h ContextHints) checkSchema2Values() error {
	for _, f := range []struct {
		field Field
		value *string
	}{
		{Listener, &h.Listener},
		{DataSubjects, h.DataSubjects},
		{Traceability, h.Traceability},
	} {
		if f.value != nil && !f.field.accepts(*f.value) {
			return &loadError{4, fmt.Sprintf("%s must be one of %v, got %q", f.field.Path(), f.field.Values(), *f.value)}
		}
	}
	if h.Detection != nil {
		return h.Detection.check()
	}
	return nil
}

// check applies the rule that once detection is written, it declares all
// three channels, and that active_in_application is the application's alone.
func (d DetectionCoverage) check() error {
	channels := []struct {
		field Field
		value string
	}{
		{DetectionNetwork, d.Network},
		{DetectionHost, d.Host},
		{DetectionApplication, d.Application},
	}
	var missing []string
	for _, c := range channels {
		if c.value == "" {
			missing = append(missing, fmt.Sprintf("%s is required once context.detection is present (values: %v)", c.field.Path(), c.field.Values()))
		}
	}
	if len(missing) > 0 {
		return &loadError{5, strings.Join(missing, "; ")}
	}
	for _, c := range channels {
		switch {
		case c.value == activeInApplication && c.field != DetectionApplication:
			return &loadError{5, fmt.Sprintf("%s: active_in_application applies to application only", c.field.Path())}
		case !c.field.accepts(c.value):
			return &loadError{5, fmt.Sprintf("%s must be one of %v, got %q", c.field.Path(), c.field.Values(), c.value)}
		}
	}
	return nil
}

func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func normalizePtr(s *string) *string {
	if s == nil {
		return nil
	}
	n := normalize(*s)
	return &n
}
