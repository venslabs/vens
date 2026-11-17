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
	"fmt"
	"strings"

	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// CheckStrictConfig refuses a config a strict run cannot take: one leaving
// data_subjects, detection or traceability undeclared, each of which would
// fall back to its worst case. New runs it for a strict run; a command can
// run it as soon as the config loads, before setting up a provider.
func CheckStrictConfig(cfg *riskconfig.Config) error {
	if undeclared := cfg.Undeclared(); len(undeclared) > 0 {
		return fmt.Errorf("strict: %s not declared, so each would fall back to its worst case",
			strings.Join(undeclared, ", "))
	}
	return nil
}

// preflight is a strict run's check before any call. A CVE whose vectors
// leave an axis's Applicability unknown keeps that axis applicable, and a
// CVE no row describes is not asked Motive, Opportunity and Ease of exploit,
// each at its worst level: each falls back to a worst case known before
// anything is spent. One error names every such CVE with its causes.
func preflight(cves []*cve) error {
	var lines []string
	for _, c := range cves {
		var causes []string
		if missing := c.applicability.Missing; len(missing) > 0 {
			parts := make([]string, len(missing))
			for i, m := range missing {
				parts[i] = m.String()
			}
			causes = append(causes, "applicability_missing: "+strings.Join(parts, "; "))
		}
		if !c.in.Described() {
			causes = append(causes, "no description in the scanner's report, so Motive, Opportunity and Ease of exploit are not asked and take their worst case")
		}
		if len(causes) > 0 {
			lines = append(lines, c.id()+": "+strings.Join(causes, "; "))
		}
	}
	if len(lines) == 0 {
		return nil
	}
	noun := "vulnerabilities"
	if len(lines) == 1 {
		noun = "vulnerability"
	}
	return fmt.Errorf("strict: %d %s would fall back to a worst case, so no LLM call is made:\n  %s",
		len(lines), noun, strings.Join(lines, "\n  "))
}

// firstCannotTell is a strict run's stop after a call: the first answer of
// the call that Go reads as cannot_tell, an answer off the list included,
// would take the factor's worst case.
func firstCannotTell(f contract.Factor, cves []*cve, got map[string]reply) error {
	for _, c := range cves {
		r, ok := got[c.id()]
		if !ok {
			continue
		}
		if reading, _ := contract.ReadAnswer(f, r.answer...); reading == contract.CannotTell || reading == contract.Invalid {
			return fmt.Errorf("strict: the answer to %s (%s) for %s reads as cannot_tell, counted as %s; stopping the run",
				f.Name(), f, c.id(), f.Counter())
		}
	}
	return nil
}
