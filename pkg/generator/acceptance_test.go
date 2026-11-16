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
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/llm/llmfactory"
)

// acceptanceEnv names the providers the acceptance test calls,
// comma-separated among openai, anthropic, googleai and ollama, each with
// its own key and model variables. Unset, the test is skipped: it calls real
// models and spends.
const acceptanceEnv = "VENS_PROVIDER_ACCEPTANCE"

// Each provider gets one call per question's schema and one adjustment call,
// and Go reads every reply: no answer missing, none off its list, the
// adjustment's fields each on theirs.
func TestProviderAcceptance(t *testing.T) {
	var providers []string
	for _, name := range strings.Split(os.Getenv(acceptanceEnv), ",") {
		if name = strings.TrimSpace(name); name != "" {
			providers = append(providers, name)
		}
	}
	if len(providers) == 0 {
		t.Skipf("set %s to the providers to call, such as openai,anthropic", acceptanceEnv)
	}
	vulns := []Vulnerability{
		{
			VulnID: "CVE-2024-24790", PkgName: "stdlib", InstalledVersion: "1.21.0", FixedVersion: "1.21.11", BOMRef: "a",
			Title:       "net/netip: Unexpected behavior from Is methods for IPv4-mapped IPv6 addresses",
			Description: "The various Is methods (IsPrivate, IsLoopback, etc) did not work as expected for IPv4-mapped IPv6 addresses, returning false for addresses which would return true in their traditional IPv4 forms.",
			Severity:    "CRITICAL",
			CVSS:        []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")},
		},
		{
			VulnID: "CVE-2019-1010022", PkgName: "libc6", InstalledVersion: "2.36-9", BOMRef: "b",
			Title:       "glibc: stack guard protection bypass",
			Description: "GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass stack guard protection. NOTE: Upstream comments indicate \"this is being treated as a non-security bug and no real threat.\"",
			Severity:    "LOW", SeveritySource: "debian",
			VendorSeverities: []VendorSeverity{{Source: "debian", Severity: "LOW"}, {Source: "nvd", Severity: "CRITICAL"}},
			CVSS:             []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")},
			Flags:            Flags{MaintainerDisputed: true, SeverityContested: true},
		},
	}
	for _, name := range providers {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			client, provider, model, err := llmfactory.New(ctx, name)
			require.NoError(t, err)
			t.Logf("provider %s, model %s", provider, model)
			logs := withCapturedLogs(t)
			g := newGen(t, Opts{LLM: client, Config: fullConfig()})
			require.NoError(t, g.GenerateRiskScore(ctx, vulns, nil))

			summary := runSummary(t, logs)
			for _, f := range contract.Order() {
				assert.Equal(t, int64(1), summary.attrs["calls."+string(f)], "question %s: one call, every CVE answered", f)
			}
			assert.Equal(t, int64(1), summary.attrs["calls."+adjustmentCall])
			for _, msg := range []string{
				"Model gave an answer off the list; reading it as cannot_tell",
				"Adjustment answer off its list; the baseline stands",
				"Unreadable adjustment reply; the baselines stand",
			} {
				assert.Empty(t, logs.find(slog.LevelWarn, msg), msg)
			}
		})
	}
}
