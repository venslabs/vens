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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// strictConfig declares every field Go reads, Privacy violation asked under a
// cap above 3.
func strictConfig() *riskconfig.Config {
	cfg := fullConfig()
	cfg.Context.Traceability, cfg.Context.DataSubjects = ptr("per_request"), ptr("millions")
	return cfg
}

// complete is a vulnerability a strict run accepts: described, every axis
// read on a vector.
func complete(v Vulnerability) Vulnerability {
	v.CVSS = []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N")}
	return v
}

// A strict run refuses a config that leaves data_subjects, detection or
// traceability undeclared before anything is read or asked, naming each.
func TestNew_StrictRefusesUndeclaredFields(t *testing.T) {
	_, err := New(Opts{LLM: &fakeLLM{}, Config: testConfig(), Strict: true})
	require.EqualError(t, err, "strict: context.data_subjects, context.detection, context.traceability not declared, so each would fall back to its worst case")

	cfg := strictConfig()
	cfg.Context.Detection = nil
	_, err = New(Opts{LLM: &fakeLLM{}, Config: cfg, Strict: true})
	require.EqualError(t, err, "strict: context.detection not declared, so each would fall back to its worst case")

	_, err = New(Opts{LLM: &fakeLLM{}, Config: strictConfig(), Strict: true})
	require.NoError(t, err)
	_, err = New(Opts{LLM: &fakeLLM{}, Config: testConfig()})
	require.NoError(t, err, "a run that is not strict takes the worst cases, counted")

	// The same check, for a command to run as soon as the config loads.
	require.EqualError(t, CheckStrictConfig(cfg), "strict: context.detection not declared, so each would fall back to its worst case")
	require.NoError(t, CheckStrictConfig(strictConfig()))
}

// Before any call, a strict run refuses every CVE with no usable CVSS v3
// vector, whatever the cause, and every CVE no row describes: one error names
// each with its causes, each v3 vector refused with why.
func TestGenerator_StrictPreflight(t *testing.T) {
	const (
		noV3    = "cvss_v3_missing: no CVSS v3 vector in the scanner's report, so Loss of confidentiality, integrity and availability take their worst level"
		refused = "cvss_v3_missing: no usable CVSS v3 vector, so Loss of confidentiality, integrity and availability take their worst level: "
	)
	cases := []struct {
		id    string
		cvss  []cvss.Vector
		bare  bool
		cause string
	}{
		{"CVE-2024-0001", nil, false, noV3},
		{"CVE-2024-0002", []cvss.Vector{v31("nvd", "AV:N/garbage")}, false,
			refused + `nvd CVSS 3.1 vector "CVSS:3.1/AV:N/garbage": "garbage" is not a metric:value pair`},
		{"CVE-2024-0003", []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N")}, false,
			refused + `nvd CVSS 3.1 vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N": A is absent or off H, L and N`},
		{"CVE-2024-0004", []cvss.Vector{v31("redhat", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:X/A:N"), v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/A:N")}, false,
			refused + `redhat CVSS 3.1 vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:X/A:N": I is absent or off H, L and N; ` +
				`nvd CVSS 3.1 vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/A:N": metric A given twice`},
		{"CVE-2024-0005", []cvss.Vector{{Source: "nvd", Version: "4.0", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"}}, false, noV3},
		{"CVE-2024-0006", []cvss.Vector{v31("nvd", noImpact)}, true,
			"no description in the scanner's report, so Motive, Opportunity and Ease of exploit are not asked and take their worst case"},
	}
	vulnOf := func(i int) Vulnerability {
		c := cases[i]
		v := Vulnerability{VulnID: c.id, PkgName: "pkg", Description: "d", BOMRef: c.id, CVSS: c.cvss}
		if c.bare {
			v.Description = ""
		}
		return v
	}
	for i, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			m := &fakeLLM{}
			g := newGen(t, Opts{LLM: m, Config: strictConfig(), Strict: true})
			err := g.GenerateRiskScore(context.Background(), []Vulnerability{complete(testVulns(1)[0]), vulnOf(i)}, nil)
			require.EqualError(t, err, "strict: 1 vulnerability would fall back to a worst case, so no LLM call is made:\n  "+c.id+": "+c.cause)
			require.Empty(t, m.calls)
		})
	}

	t.Run("every CVE in one error", func(t *testing.T) {
		vulns := []Vulnerability{complete(testVulns(1)[0])}
		want := "strict: 6 vulnerabilities would fall back to a worst case, so no LLM call is made:"
		for i, c := range cases {
			vulns = append(vulns, vulnOf(i))
			want += "\n  " + c.id + ": " + c.cause
		}
		m := &fakeLLM{}
		g := newGen(t, Opts{LLM: m, Config: strictConfig(), Strict: true})
		require.EqualError(t, g.GenerateRiskScore(context.Background(), vulns, nil), want)
		require.Empty(t, m.calls)
	})

	t.Run("a run that is not strict asks", func(t *testing.T) {
		vulns := make([]Vulnerability, len(cases))
		for i := range cases {
			vulns[i] = vulnOf(i)
		}
		m := &fakeLLM{}
		g := newGen(t, Opts{LLM: m, Config: strictConfig()})
		require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))
		require.NotEmpty(t, m.calls)
	})
}

// A strict run stops right after the call that gave the first answer Go
// reads as cannot_tell, an answer off the list included, naming the CVE, the
// question and its counter, even when it is the run's last call: the run
// fails, so nothing is written. The adjustment's cannot_tell, an abstention,
// does not stop it.
func TestGenerator_StrictStopsAfterTheFirstCannotTell(t *testing.T) {
	vulns := []Vulnerability{complete(testVulns(2)[0]), complete(testVulns(2)[1])}
	for name, answer := range map[string]string{"cannot_tell": cannotTell, "an answer off the list": "bogus"} {
		t.Run(name, func(t *testing.T) {
			m := &fakeLLM{answer: func(c fakeCall, id string) any {
				if c.factor == contract.PV && id == "CVE-2024-0001" {
					return answer
				}
				return nil
			}}
			parent := t.TempDir()
			logs := withCapturedLogs(t)
			g := newGen(t, Opts{LLM: m, Config: strictConfig(), Strict: true, BatchSize: 1, DebugDir: parent})
			var emitted []outputhandler.VulnRating
			err := g.GenerateRiskScore(context.Background(), vulns, collect(&emitted))
			require.EqualError(t, err, "strict: the answer to Privacy violation (PV) for CVE-2024-0001 reads as cannot_tell, counted as privacy_cannot_tell; stopping the run")
			last := m.calls[len(m.calls)-1]
			assert.Equal(t, contract.PV, last.factor, "the run's last call")
			assert.Equal(t, []string{"CVE-2024-0001"}, last.ids)
			assert.Len(t, emitted, 1, "the first batch was rated; the run fails all the same")

			// The answer that stopped the run is counted where the error says.
			assert.Equal(t, int64(1), runSummary(t, logs).attrs["counters.privacy_cannot_tell"])
			got, _ := readAnswers(t, parent)
			require.Len(t, got.Vulnerabilities, 2)
			stopped := got.Vulnerabilities[1]
			assert.True(t, stopped.Unrated)
			assert.Equal(t, []string{"privacy_cannot_tell"}, stopped.Counters)
			pv := stopped.Factors[len(stopped.Factors)-1]
			assert.Equal(t, []any{"PV", answer}, []any{pv.Factor, pv.Answer})
		})
	}

	t.Run("the same answers outside a strict run", func(t *testing.T) {
		m := &fakeLLM{answer: func(c fakeCall, _ string) any {
			if c.factor == contract.PV {
				return cannotTell
			}
			return nil
		}}
		g := newGen(t, Opts{LLM: m, Config: strictConfig(), BatchSize: 1})
		require.NoError(t, g.GenerateRiskScore(context.Background(), vulns, nil))
	})

	t.Run("the adjustment's cannot_tell", func(t *testing.T) {
		m := &fakeLLM{adjust: func(c fakeCall) map[string]any {
			out := map[string]any{"reasoning": "r"}
			for name := range c.fields {
				out[name] = cannotTell
			}
			return out
		}}
		g := newGen(t, Opts{LLM: m, Config: strictConfig(), Strict: true})
		require.NoError(t, g.GenerateRiskScore(context.Background(), []Vulnerability{complete(disputedRow(testVulns(1)[0]))}, nil))
		assert.Equal(t, adjustmentCall, m.log()[len(m.calls)-1])
	})
}
