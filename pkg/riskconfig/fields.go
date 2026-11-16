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
	"slices"

	"github.com/venslabs/vens/pkg/owasp"
)

// Field is a context field whose value is one of a documented list. The
// texts below are the one wording the reference (docs/reference/config-schema.md),
// the questions and vens init share; the docs tests hold the reference to them.
type Field string

// The enumerated context fields. Each detection channel is a field of its
// own; Detection carries what the three share, the coverage rule and the
// levels.
const (
	Exposure                Field = "exposure"
	DataSensitivity         Field = "data_sensitivity"
	BusinessCriticality     Field = "business_criticality"
	AvailabilityRequirement Field = "availability_requirement"
	AuditRequirement        Field = "audit_requirement"
	Listener                Field = "listener"
	DataSubjects            Field = "data_subjects"
	Detection               Field = "detection"
	DetectionNetwork        Field = "detection.network"
	DetectionHost           Field = "detection.host"
	DetectionApplication    Field = "detection.application"
	Traceability            Field = "traceability"
)

// Choice is a value a field accepts and its documented meaning.
type Choice struct {
	Value   string
	Meaning string
}

// Band is one of Privacy violation's population bands: the value
// data_subjects declares and the model's answer names, the people it covers,
// and its level, which is also the cap a declared band sets.
type Band struct {
	Name   string
	People string
	Level  owasp.PrivacyViolation
}

// Control is a control a question shows when it is set to true, with its
// documented description and scope.
type Control struct {
	Key         string
	Description string
	Scope       string
}

const (
	listenerUnknown     = "unknown"
	activeInApplication = "active_in_application"
)

// bands are exhaustive and disjoint over whole numbers of people. OWASP names
// no band for 2 to 99 people; those counts belong to hundreds, the
// conservative side.
var bands = []Band{
	{"none", "0", owasp.PrivacyViolationOneIndividual},
	{"one_individual", "1", owasp.PrivacyViolationOneIndividual},
	{"hundreds", "2 to 999", owasp.PrivacyViolationHundredsOfPeople},
	{"thousands", "1,000 to 999,999", owasp.PrivacyViolationThousandsOfPeople},
	{"millions", "1,000,000 or more", owasp.PrivacyViolationMillionsOfPeople},
}

// detectionLevels run from the worst detection to the best;
// active_in_application, last, applies to the application channel only.
var detectionLevels = []Choice{
	{"not_logged", "nothing is recorded"},
	{"logged", "recorded, and nobody reviews it"},
	{"logged_and_reviewed", "recorded and reviewed, by people or by alerts that people act on"},
	{activeInApplication, "the service itself detects attacks and acts on them"},
}

var complianceFrameworks = []string{
	"PCI-DSS", "HIPAA", "GDPR", "SOX", "ISO27001", "FedRAMP",
	"NIST", "CCPA", "SOC2", "FISMA", "ITAR", "CMMC",
}

// controlScopes are listed in the order the Ease of exploit question shows
// them. ids, siem and edr move no score and are not among them.
var controlScopes = []Control{
	{"waf", "Web Application Firewall", "SQL injection, XSS, path traversal"},
	{"ddos_protection", "DDoS mitigation (CloudFlare, AWS Shield…)", "Availability / DoS CVEs"},
	{"segmentation", "Network micro-segmentation", "Lateral movement"},
	{"zero_trust", "Zero-trust architecture", "Authentication bypass, lateral movement"},
	{"antivirus", "Traditional AV / anti-malware", "Known malware signatures"},
}

type fieldDoc struct {
	about   string
	choices []Choice
}

// fieldDocs lists each field's values in their documented order: from the
// smallest population to the largest for data_subjects, from nothing
// recorded to active detection for detection, from no record to records per
// individual for traceability.
var fieldDocs = map[Field]fieldDoc{
	Exposure: {choices: []Choice{
		{"internal", "Corporate network only, no external access"},
		{"private", "Requires VPN / authenticated tunnel"},
		{"internet", "Publicly accessible"},
	}},
	DataSensitivity: {choices: []Choice{
		{"low", "Public data"},
		{"medium", "Internal data, limited confidentiality"},
		{"high", "PII, financial data, customer info"},
		{"critical", "Secrets, PHI, payment card data"},
	}},
	BusinessCriticality: {choices: []Choice{
		{"low", "Dev / test / sandbox"},
		{"medium", "Internal tools"},
		{"high", "Customer-facing, important operations"},
		{"critical", "Revenue-critical, compliance-required"},
	}},
	AvailabilityRequirement: {choices: []Choice{
		{"low", "Best-effort uptime"},
		{"medium", "Business-hours SLA"},
		{"high", "24/7 required"},
		{"critical", "Zero downtime tolerance"},
	}},
	// No question shows audit_requirement, so its values carry no meaning here.
	AuditRequirement: {choices: []Choice{{Value: "low"}, {Value: "medium"}, {Value: "high"}}},
	Listener: {
		about: "Does this deployment accept connections others open?",
		choices: []Choice{
			{"present", "this deployment accepts connections that other parties open: it listens on a port or socket, as a server or as a peer others connect to"},
			{"absent", "it accepts none: no listening port or socket, such as a batch job, a command-line tool, or a client that only opens connections"},
			{listenerUnknown, "not stated"},
		},
	},
	DataSubjects: {
		about:   "How many distinct people's personal data this service can read: what it stores, what passes through it, and what it can fetch with its own access. A count belongs to the band whose interval holds it, and a count of 2 to 99 belongs to hundreds. Nothing is inferred from data_sensitivity.",
		choices: bandChoices(),
	},
	Detection: {
		about:   "Declaring a channel's level states it for every instance of this service. Where only part of the service is covered, the level declared is the one that holds for all of it.",
		choices: detectionLevels,
	},
	DetectionNetwork: {
		about:   "each attempt crossing the network to or from the service is recorded where it can be seen",
		choices: detectionLevels[:3],
	},
	DetectionHost: {
		about:   "process, file and privilege activity on the hosts that run the service is recorded",
		choices: detectionLevels[:3],
	},
	DetectionApplication: {
		about:   "the service's own logs record each request or action an attempt would make",
		choices: detectionLevels,
	},
	Traceability: {
		about: "What is in place, not what is required. Records kept in front of the service count when they cover every request to it (a gateway or proxy log). The value declared must hold across the whole service: where only part of it records this, declare the weaker value.",
		choices: []Choice{
			{"none", "nothing records the requests the service receives or who made them"},
			{"per_request", "each request is recorded with its time and origin (source address, client), not with the individual who made it"},
			{"per_individual", "as per_request, and each action of an authenticated user is recorded with that user's identity"},
		},
	},
}

func bandChoices() []Choice {
	choices := make([]Choice, len(bands))
	for i, b := range bands {
		choices[i] = Choice{b.Name, b.People}
	}
	return choices
}

// Path returns the field's YAML path.
func (f Field) Path() string {
	return "context." + string(f)
}

// Values returns the values the field accepts, in their documented order.
func (f Field) Values() []string {
	choices := fieldDocs[f].choices
	values := make([]string, len(choices))
	for i, c := range choices {
		values[i] = c.Value
	}
	return values
}

// Choices returns the field's values with their documented meanings.
func (f Field) Choices() []Choice {
	return slices.Clone(fieldDocs[f].choices)
}

// Meaning returns the documented meaning of one of the field's values, or ""
// when the field documents none for it.
func (f Field) Meaning(value string) string {
	for _, c := range fieldDocs[f].choices {
		if c.Value == value {
			return c.Meaning
		}
	}
	return ""
}

// About returns what the field states as a whole, or "" when its values say
// it all.
func (f Field) About() string {
	return fieldDocs[f].about
}

func (f Field) accepts(value string) bool {
	return slices.ContainsFunc(fieldDocs[f].choices, func(c Choice) bool { return c.Value == value })
}

// DataSubjectsBands returns Privacy violation's bands, the smallest
// population first.
func DataSubjectsBands() []Band {
	return slices.Clone(bands)
}

// ComplianceFrameworks returns the frameworks compliance_requirements accepts,
// matched without regard to case.
func ComplianceFrameworks() []string {
	return slices.Clone(complianceFrameworks)
}

// ControlScopes returns the controls the Ease of exploit question shows when
// they are set to true, in the order it shows them.
func ControlScopes() []Control {
	return slices.Clone(controlScopes)
}
