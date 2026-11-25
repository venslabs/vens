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

const (
	warnAuditNoTraceability = "context.audit_requirement no longer moves any score, and context.traceability is not declared: " +
		"Loss of accountability uses its `none` column, 7 when the attacker must authenticate and cannot act as someone else " +
		"or tamper with the records, 9 otherwise."
	warnControlsNoDetection = "controls ids/siem/edr give no detection credit, and context.detection is not declared: " +
		"every channel counts as not logged, so Intrusion detection is 9 on every finding."
	warnNoTraceability = "context.traceability is not declared: Loss of accountability uses its `none` column, 7 or 9 on every finding."
	warnNoDetection    = "context.detection is not declared: every channel counts as not logged, so Intrusion detection is 9 on every finding."
	warnNoDataSubjects = "context.data_subjects is not declared: Privacy violation has no cap, so the model's band stands " +
		"wherever Privacy violation is asked, and every finding is rated on its technical impact. Declared, it is taken as " +
		"the business information OWASP's rule asks for, and every finding is rated on its business impact instead, " + basisShift
)

// Undeclared returns the YAML paths of data_subjects, detection and
// traceability, in that order, when the config leaves them out: each then
// takes its worst case, which a run counts and a strict run refuses.
func (c *Config) Undeclared() []string {
	var paths []string
	if c.Context.DataSubjects == nil {
		paths = append(paths, DataSubjects.Path())
	}
	if c.Context.Detection == nil {
		paths = append(paths, Detection.Path())
	}
	if c.Context.Traceability == nil {
		paths = append(paths, Traceability.Path())
	}
	return paths
}

// Warnings returns one warning per field Undeclared returns, saying what its
// worst case does, and naming audit_requirement or the ids, siem and edr
// controls when they are set, since neither stands in for the field. They
// come at load, before a run spends anything.
func (c *Config) Warnings() []string {
	traced := c.Context.Traceability != nil
	audited := c.Context.AuditRequirement != nil
	detected := c.Context.Detection != nil
	detectionTools := c.Context.Controls.IDS || c.Context.Controls.SIEM || c.Context.Controls.EDR

	var warnings []string
	if !traced && audited {
		warnings = append(warnings, warnAuditNoTraceability)
	}
	if !detected && detectionTools {
		warnings = append(warnings, warnControlsNoDetection)
	}
	if !traced && !audited {
		warnings = append(warnings, warnNoTraceability)
	}
	if !detected && !detectionTools {
		warnings = append(warnings, warnNoDetection)
	}
	if c.Context.DataSubjects == nil {
		warnings = append(warnings, warnNoDataSubjects)
	}
	return warnings
}
