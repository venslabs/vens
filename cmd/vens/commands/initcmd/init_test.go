// Copyright 2025 venslabs
//
// Licensed under the Apache License, Version 2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package initcmd_test

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/venslabs/vens/cmd/vens/commands/initcmd"
	"github.com/venslabs/vens/pkg/riskconfig"
)

func runInit(t *testing.T, stdin, dir string, extraArgs ...string) string {
	t.Helper()
	out := filepath.Join(dir, "config.yaml")
	cmd := initcmd.New()
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(io.Discard)
	args := append([]string{"--output", out}, extraArgs...)
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}
	return out
}

func TestInitWritesValidConfig(t *testing.T) {
	dir := t.TempDir()
	// An invalid exposure is re-prompted, not fatal; optional questions
	// are skipped with empty lines.
	stdin := strings.Join([]string{
		"my-api",
		"Backend API",
		"public", // invalid: re-prompted
		"internet",
		"HIGH",
		"critical",
		"", // availability: skip
		"gdpr, soc2",
		"", // audit: skip
		"", // notes: skip
	}, "\n") + "\n"
	out := runInit(t, stdin, dir)

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading generated config: %v", err)
	}
	cfg, err := riskconfig.Parse(raw)
	if err != nil {
		t.Fatalf("generated config does not parse: %v", err)
	}
	if cfg.Project.Name != "my-api" || cfg.Project.Description != "Backend API" {
		t.Errorf("project = %+v", cfg.Project)
	}
	if cfg.Context.Exposure != "internet" || cfg.Context.DataSensitivity != "high" || cfg.Context.BusinessCriticality != "critical" {
		t.Errorf("context = %+v", cfg.Context)
	}
	if got := strings.Join(cfg.Context.ComplianceRequirements, ","); got != "GDPR,SOC2" {
		t.Errorf("compliance = %q, want GDPR,SOC2", got)
	}
	if cfg.Context.AvailabilityRequirement != nil || cfg.Context.AuditRequirement != nil {
		t.Errorf("optional fields should be unset, got %+v", cfg.Context)
	}
}

func TestInitRefusesToOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(out, []byte("existing\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := initcmd.New()
	cmd.SetIn(strings.NewReader("x\n"))
	cmd.SetOut(io.Discard)
	cmd.SetArgs([]string{"--output", out})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected an error for an existing output file, got nil")
	}
	if raw, _ := os.ReadFile(out); string(raw) != "existing\n" {
		t.Errorf("existing file was modified: %q", raw)
	}

	// --force overwrites.
	stdin := strings.Join([]string{"my-api", "", "internet", "low", "low", "", "", "", ""}, "\n") + "\n"
	runInit(t, stdin, dir, "--force")
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := riskconfig.Parse(raw); err != nil {
		t.Errorf("forced overwrite produced an invalid config: %v", err)
	}
}
