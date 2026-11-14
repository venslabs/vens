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
	"strings"
	"testing"
)

func TestDeploymentCheckAcceptsWhatTheConfigAllows(t *testing.T) {
	for _, d := range []Deployment{base(), declared()} {
		if err := d.Check(); err != nil {
			t.Errorf("%+v: %v", d, err)
		}
	}
	d := declared()
	d.Listener = Setting{Value: "unknown"}
	d.Detection = &Detection{Network: "logged_and_reviewed", Host: "logged", Application: activeInApplication}
	d.Controls = []Control{{"zero_trust", "Zero-trust architecture", "Authentication bypass, lateral movement"}}
	if err := d.Check(); err != nil {
		t.Error(err)
	}
}

func TestDeploymentCheckNamesEachValueItCannotRead(t *testing.T) {
	for _, c := range []struct {
		change func(*Deployment)
		want   string
	}{
		{func(d *Deployment) { d.Name = "" }, "no name"},
		{func(d *Deployment) { d.Exposure.Value = "public" }, `exposure "public"`},
		{func(d *Deployment) { d.Exposure.Meaning = "" }, `exposure "internet" has no meaning`},
		{func(d *Deployment) { d.DataSensitivity.Value = "secret" }, `data_sensitivity "secret"`},
		{func(d *Deployment) { d.BusinessCriticality = Setting{} }, "business_criticality has no value"},
		{func(d *Deployment) { d.Listener = Setting{Value: "maybe", Meaning: "x"} }, `listener "maybe"`},
		{func(d *Deployment) { d.Listener = Setting{Value: "present"} }, `listener "present" has no meaning`},
		{func(d *Deployment) { d.AvailabilityRequirement = &Setting{Value: "high"} }, `availability_requirement "high" has no meaning`},
		{func(d *Deployment) { d.Controls = []Control{{"ids", "IDS", "Network-level exploits"}} }, `control "ids" is not one`},
		{func(d *Deployment) {
			d.Controls = []Control{{"waf", "WAF", "SQLi"}, {"waf", "WAF", "SQLi"}}
		}, `control "waf" is given twice`},
		{func(d *Deployment) { d.Controls = []Control{{Key: "waf", Description: "WAF"}} }, `control "waf" has no description or scope`},
		{func(d *Deployment) { d.Frameworks = []string{"GDPR", ""} }, "framework has no name"},
		{func(d *Deployment) { d.Traceability = ptr("full") }, `traceability "full"`},
		{func(d *Deployment) { d.DataSubjects = ptr("dozens") }, `data_subjects "dozens"`},
		{func(d *Deployment) { d.DataSubjects = ptr(cannotTell) }, `data_subjects "cannot_tell"`},
		{func(d *Deployment) {
			d.Detection = &Detection{Network: activeInApplication, Host: "logged", Application: "logged"}
		}, `detection.network "active_in_application"`},
		{func(d *Deployment) {
			d.Detection = &Detection{Network: "logged", Host: "audited", Application: "logged"}
		}, `detection.host "audited"`},
		{func(d *Deployment) { d.Detection = &Detection{} }, `detection.application ""`},
	} {
		d := declared()
		c.change(&d)
		err := d.Check()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Check() = %v, want an error naming %s", err, c.want)
		}
	}
	// Every value at fault is named at once.
	d := base()
	d.Exposure.Value, d.DataSensitivity.Value = "public", "secret"
	if err := d.Check(); err == nil || !strings.Contains(err.Error(), "exposure") || !strings.Contains(err.Error(), "data_sensitivity") {
		t.Errorf("Check() = %v, want both values named", err)
	}
}
