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

package contract

import (
	"errors"
	"fmt"
	"slices"

	"github.com/venslabs/vens/pkg/owasp"
)

// Deployment is the config as the contracts read it. A value the model is
// shown comes with its documented meaning, which the caller takes from the
// config's documentation: this package writes no config wording of its own.
// Traceability, DataSubjects, Detection and AvailabilityRequirement are read
// by Go alone and never shown.
type Deployment struct {
	Name        string
	Description string
	Notes       string
	// Exposure is internet, private or internal: Size's level, and the
	// attacker group every question names.
	Exposure Setting
	// Listener is shown when present or absent, and not when unknown or
	// empty.
	Listener            Setting
	BusinessCriticality Setting
	// DataSensitivity is low, medium, high or critical, which also picks
	// Loss of confidentiality's column.
	DataSensitivity Setting
	// Controls are the controls set to true among waf, ddos_protection,
	// segmentation, zero_trust and antivirus, which Ease of exploit shows in
	// that order.
	Controls []Control
	// Frameworks are the compliance frameworks declared, in their order.
	// Non-compliance is asked only when there is one.
	Frameworks []string

	// Traceability is none, per_request or per_individual; nil when
	// undeclared.
	Traceability *string
	// DataSubjects is one of Privacy violation's bands, none to millions;
	// nil when undeclared. Declared, it sets the impact basis to business.
	DataSubjects *string
	// Detection is each channel's declared level; nil when undeclared.
	Detection *Detection
	// AvailabilityRequirement is low, medium, high or critical, which picks
	// Loss of availability's column; nil when undeclared.
	AvailabilityRequirement *string
}

// ImpactBasis is the impact every finding is rated on. The config is taken as
// the deployment owner's truth: business_criticality is required and no
// compliance framework declared reads as none applying, so data_subjects is
// the one business input whose absence leaves the business unknown. Declared,
// the config holds the business information OWASP asks for and the basis is
// business; undeclared, technical (OWASP_Risk_Rating_Methodology.md:142-145,
// :305-307).
func (d Deployment) ImpactBasis() owasp.Basis {
	if d.DataSubjects != nil {
		return owasp.BasisBusiness
	}
	return owasp.BasisTechnical
}

// Setting is a config value the model is shown, with its documented meaning.
type Setting struct {
	Value   string
	Meaning string
}

// Control is a control set to true, with its documented description and the
// attacks it is documented to stop.
type Control struct {
	Key         string
	Description string
	Scope       string
}

// Detection is the level each channel is declared to log an attempt at:
// not_logged, logged or logged_and_reviewed, and for application also
// active_in_application.
type Detection struct {
	Network     string
	Host        string
	Application string
}

// levels returns each channel's level in channel order.
func (d Detection) levels() [3]owasp.IntrusionDetection {
	return [3]owasp.IntrusionDetection{
		channelNetwork:     detectionLevels[d.Network],
		channelHost:        detectionLevels[d.Host],
		channelApplication: detectionLevels[d.Application],
	}
}

const (
	listenerUnknown = "unknown"
	listenerPresent = "present"
	listenerAbsent  = "absent"
)

func listenerShown(value string) bool {
	return value == listenerPresent || value == listenerAbsent
}

// controlKeys are the controls Ease of exploit can show, in the order it
// shows them.
var controlKeys = [...]string{"waf", "ddos_protection", "segmentation", "zero_trust", "antivirus"}

// Check returns an error naming every value of d that the texts or the rules
// cannot read. Each function of this package that takes a Deployment checks
// it first.
func (d Deployment) Check() error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}
	if d.Name == "" {
		fail("the project has no name")
	}
	if _, ok := exposures[d.Exposure.Value]; !ok {
		fail("exposure %q is not internet, private or internal", d.Exposure.Value)
	}
	if _, ok := critical[d.DataSensitivity.Value]; !ok {
		fail("data_sensitivity %q is not low, medium, high or critical", d.DataSensitivity.Value)
	}
	if d.BusinessCriticality.Value == "" {
		fail("business_criticality has no value")
	}
	switch d.Listener.Value {
	case "", listenerUnknown, listenerPresent, listenerAbsent:
	default:
		fail("listener %q is not present, absent or unknown", d.Listener.Value)
	}
	for _, s := range d.shownSettings() {
		if s.setting.Meaning == "" {
			fail("%s %q has no meaning to show", s.key, s.setting.Value)
		}
	}
	errs = append(errs, checkControls(d.Controls)...)
	if slices.Contains(d.Frameworks, "") {
		fail("a compliance framework has no name")
	}
	if d.Traceability != nil && !slices.Contains(traceabilities[:], *d.Traceability) {
		fail("traceability %q is not none, per_request or per_individual", *d.Traceability)
	}
	if d.DataSubjects != nil && !isBand(*d.DataSubjects) {
		fail("data_subjects %q is not none, one_individual, hundreds, thousands or millions", *d.DataSubjects)
	}
	if r := d.AvailabilityRequirement; r != nil {
		if _, ok := primaryServices[*r]; !ok {
			fail("availability_requirement %q is not low, medium, high or critical", *r)
		}
	}
	if d.Detection != nil {
		errs = append(errs, d.Detection.check()...)
	}
	return errors.Join(errs...)
}

type keyedSetting struct {
	key     string
	setting Setting
}

// shownSettings returns the settings the texts show, by config key.
func (d Deployment) shownSettings() []keyedSetting {
	s := []keyedSetting{
		{"exposure", d.Exposure},
		{"business_criticality", d.BusinessCriticality},
		{"data_sensitivity", d.DataSensitivity},
	}
	if listenerShown(d.Listener.Value) {
		s = append(s, keyedSetting{"listener", d.Listener})
	}
	return s
}

func checkControls(controls []Control) []error {
	var errs []error
	seen := map[string]bool{}
	for _, c := range controls {
		switch {
		case !slices.Contains(controlKeys[:], c.Key):
			// ids, siem and edr move no level, so no question shows them.
			errs = append(errs, fmt.Errorf("control %q is not one Ease of exploit shows", c.Key))
		case seen[c.Key]:
			errs = append(errs, fmt.Errorf("control %q is given twice", c.Key))
		case c.Description == "" || c.Scope == "":
			errs = append(errs, fmt.Errorf("control %q has no description or scope to show", c.Key))
		}
		seen[c.Key] = true
	}
	return errs
}

func (d Detection) check() []error {
	var errs []error
	for _, c := range []struct{ name, level string }{
		{"network", d.Network}, {"host", d.Host}, {"application", d.Application},
	} {
		_, ok := detectionLevels[c.level]
		if !ok || (c.level == activeInApplication && c.name != "application") {
			errs = append(errs, fmt.Errorf("detection.%s %q is not a level that channel can be declared at", c.name, c.level))
		}
	}
	return errs
}
