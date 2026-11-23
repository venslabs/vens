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

package generator

import (
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// deploymentOf reads the config as the questions do: each value the model is
// shown with the meaning the config documents for it, and of the controls
// only those Ease of exploit shows, set to true, with their scope. The
// fields Go reads alone pass through unshown.
func deploymentOf(cfg *riskconfig.Config) contract.Deployment {
	c := cfg.Context
	d := contract.Deployment{
		Name:                    cfg.Project.Name,
		Description:             cfg.Project.Description,
		Notes:                   c.Notes,
		Exposure:                setting(riskconfig.Exposure, c.Exposure),
		Listener:                setting(riskconfig.Listener, c.Listener),
		BusinessCriticality:     setting(riskconfig.BusinessCriticality, c.BusinessCriticality),
		DataSensitivity:         setting(riskconfig.DataSensitivity, c.DataSensitivity),
		Frameworks:              c.ComplianceRequirements,
		Traceability:            c.Traceability,
		DataSubjects:            c.DataSubjects,
		AvailabilityRequirement: c.AvailabilityRequirement,
	}
	for _, s := range riskconfig.ControlScopes() {
		if c.Controls.Enabled(s.Key) {
			d.Controls = append(d.Controls, contract.Control{Key: s.Key, Description: s.Description, Scope: s.Scope})
		}
	}
	if c.Detection != nil {
		d.Detection = &contract.Detection{Network: c.Detection.Network, Host: c.Detection.Host, Application: c.Detection.Application}
	}
	return d
}

func setting(f riskconfig.Field, value string) contract.Setting {
	return contract.Setting{Value: value, Meaning: f.Meaning(value)}
}
