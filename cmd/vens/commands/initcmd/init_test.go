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

package initcmd_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/venslabs/vens/cmd/vens/commands/initcmd"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// answers joins one answer per question, in the order the wizard asks.
func answers(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

// skipOptional skips every optional question after the three required ones:
// availability, compliance, traceability, listener, data subjects,
// detection, the five controls and notes.
var skipOptional = []string{"", "", "", "", "", "", "", "", "", "", "", ""}

func requiredThenSkip(name string) string {
	return answers(append([]string{name, "", "internet", "low", "low"}, skipOptional...)...)
}

func runInit(t *testing.T, stdin io.Reader, output string, extraArgs ...string) (string, error) {
	t.Helper()
	cmd := initcmd.New()
	cmd.SetIn(stdin)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(append([]string{"--output", output}, extraArgs...))
	err := cmd.Execute()
	return out.String(), err
}

func parseFile(t *testing.T, path string) *riskconfig.Config {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading generated config: %v", err)
	}
	cfg, err := riskconfig.Parse(raw)
	if err != nil {
		t.Fatalf("generated config does not parse: %v\n%s", err, raw)
	}
	return cfg
}

func TestInitWritesValidConfig(t *testing.T) {
	out := filepath.Join(t.TempDir(), "config.yaml")
	// An invalid exposure is re-prompted, not fatal; optional questions are
	// skipped with empty lines.
	stdin := answers(append([]string{
		"my-api",
		"Backend API",
		"public", // invalid: re-prompted
		"internet",
		"HIGH",
		"critical",
		"",           // availability: skip
		"gdpr, soc2", // compliance
	}, skipOptional[2:]...)...)
	if _, err := runInit(t, strings.NewReader(stdin), out); err != nil {
		t.Fatalf("init: %v", err)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.SplitN(string(raw), "\n", 3); len(lines) < 2 || lines[1] != "schema_version: 2" {
		t.Errorf("the generated file does not open with schema_version: 2 after its header:\n%s", raw)
	}
	cfg := parseFile(t, out)
	if cfg.Project.Name != "my-api" || cfg.Project.Description != "Backend API" {
		t.Errorf("project = %+v", cfg.Project)
	}
	if cfg.Context.Exposure != "internet" || cfg.Context.DataSensitivity != "high" || cfg.Context.BusinessCriticality != "critical" {
		t.Errorf("context = %+v", cfg.Context)
	}
	if got := strings.Join(cfg.Context.ComplianceRequirements, ","); got != "GDPR,SOC2" {
		t.Errorf("compliance = %q, want GDPR,SOC2", got)
	}
	if cfg.Context.AvailabilityRequirement != nil || cfg.Context.AuditRequirement != nil || cfg.Context.Listener != "unknown" ||
		cfg.Context.Controls != (riskconfig.SecurityControls{}) || cfg.Context.Notes != "" {
		t.Errorf("optional fields should be unset, got %+v", cfg.Context)
	}
	if got := cfg.Undeclared(); len(got) != 3 {
		t.Errorf("undeclared = %q, want data_subjects, detection and traceability", got)
	}
}

func TestInitAsksTheSchema2Fields(t *testing.T) {
	out := filepath.Join(t.TempDir(), "config.yaml")
	stdin := answers(
		"batch", "", "internal", "low", "medium", "", "",
		"per_request",           // traceability
		"ABSENT",                // listener
		"thousands",             // data subjects
		"y",                     // declare detection
		"active_in_application", // network: application only, re-prompted
		"logged",
		"not_logged",
		"active_in_application",
		"y", "n", "yes", "", "Y", // waf, ddos_protection, segmentation, zero_trust, antivirus
		"nightly job",
	)
	shown, err := runInit(t, strings.NewReader(stdin), out)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	cfg := parseFile(t, out)
	ctx := cfg.Context
	if ctx.Listener != "absent" || *ctx.Traceability != "per_request" || *ctx.DataSubjects != "thousands" {
		t.Errorf("listener %q, traceability %q, data_subjects %q", ctx.Listener, *ctx.Traceability, *ctx.DataSubjects)
	}
	want := riskconfig.DetectionCoverage{Network: "logged", Host: "not_logged", Application: "active_in_application"}
	if ctx.Detection == nil || *ctx.Detection != want {
		t.Errorf("detection = %+v, want %+v", ctx.Detection, want)
	}
	if c := (riskconfig.SecurityControls{WAF: true, Segmentation: true, Antivirus: true}); ctx.Controls != c {
		t.Errorf("controls = %+v, want %+v", ctx.Controls, c)
	}
	if ctx.Notes != "nightly job" {
		t.Errorf("notes = %q", ctx.Notes)
	}
	if got := cfg.Warnings(); len(got) != 0 {
		t.Errorf("a config declaring the three fields warns %q", got)
	}
	if !strings.Contains(shown, "Must be one of: not_logged, logged, logged_and_reviewed.") {
		t.Error("active_in_application on the network channel was not re-prompted")
	}
	for _, text := range promptTexts() {
		if !strings.Contains(shown, text) {
			t.Errorf("the prompts do not show %q", text)
		}
	}
}

// promptTexts are what the prompts must show, in the reference's words: what
// each explained field and value means, the levels only the application
// channel takes marked as such, and each control's description and scope.
func promptTexts() []string {
	texts := []string{"Listener: Does this deployment accept connections others open?\n"}
	for _, f := range []riskconfig.Field{riskconfig.Traceability, riskconfig.Listener, riskconfig.DataSubjects, riskconfig.Detection} {
		texts = append(texts, f.About())
		for _, c := range f.Choices() {
			label := c.Value
			if f == riskconfig.Detection && c.Value == "active_in_application" {
				label += " (application only)"
			}
			texts = append(texts, "  "+label+": "+c.Meaning+"\n")
		}
	}
	for _, f := range []riskconfig.Field{riskconfig.DetectionNetwork, riskconfig.DetectionHost, riskconfig.DetectionApplication} {
		texts = append(texts, f.About())
	}
	texts = append(texts, "\nSecurity controls in operation for this deployment:\n")
	for _, c := range riskconfig.ControlScopes() {
		texts = append(texts, c.Key+": "+c.Description+". Scope: "+c.Scope+" [y/N]: ")
	}
	return texts
}

func TestInitDoesNotAskWhatMovesNoScore(t *testing.T) {
	out := filepath.Join(t.TempDir(), "config.yaml")
	shown, err := runInit(t, strings.NewReader(requiredThenSkip("svc")), out)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	for _, asked := range []string{"ids: ", "siem: ", "edr: ", "Audit requirement"} {
		if strings.Contains(shown, asked) {
			t.Errorf("the wizard asks %q", asked)
		}
	}
}

func TestInitRefusesToOverwriteWithoutForce(t *testing.T) {
	out := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(out, []byte("existing\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := runInit(t, strings.NewReader("x\n"), out); err == nil {
		t.Fatal("expected an error for an existing output file, got nil")
	}
	if raw, _ := os.ReadFile(out); string(raw) != "existing\n" {
		t.Errorf("existing file was modified: %q", raw)
	}

	if _, err := runInit(t, strings.NewReader(requiredThenSkip("my-api")), out, "--force"); err != nil {
		t.Fatalf("init --force: %v", err)
	}
	parseFile(t, out)
}

// createOnFirstRead writes a file the first time the wizard reads an answer,
// after the up-front exists check has passed, as another terminal or an
// editor would while the user is answering.
type createOnFirstRead struct {
	path, content string
	answers       io.Reader
	created       bool
}

func (r *createOnFirstRead) Read(p []byte) (int, error) {
	if !r.created {
		r.created = true
		if err := os.WriteFile(r.path, []byte(r.content), 0644); err != nil {
			return 0, err
		}
	}
	return r.answers.Read(p)
}

func TestInitDoesNotReplaceAFileCreatedWhileAsking(t *testing.T) {
	out := filepath.Join(t.TempDir(), "config.yaml")
	const theirs = "written by someone else\n"
	stdin := &createOnFirstRead{path: out, content: theirs, answers: strings.NewReader(requiredThenSkip("svc"))}
	_, err := runInit(t, stdin, out)
	if err == nil || !strings.Contains(err.Error(), "already exists (use --force to overwrite)") {
		t.Fatalf("got error %v, want the already-exists error", err)
	}
	if !stdin.created {
		t.Fatal("the wizard never read an answer")
	}
	if raw, _ := os.ReadFile(out); string(raw) != theirs {
		t.Errorf("the file created while asking was replaced: %q", raw)
	}
}

func TestInitForceReplacesALongerFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(out, []byte(strings.Repeat("# old\n", 200)), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := runInit(t, strings.NewReader(requiredThenSkip("svc")), out, "--force"); err != nil {
		t.Fatalf("init --force: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "# old") {
		t.Errorf("--force left the old file's lines:\n%s", raw)
	}
	parseFile(t, out)
}

func TestInitFailsFastOnUnwritableTarget(t *testing.T) {
	dir := t.TempDir()

	runExpectError := func(t *testing.T, output, want string) {
		t.Helper()
		_, err := runInit(t, strings.NewReader("x\n"), output)
		if err == nil {
			t.Fatalf("--output %q: expected an error, got nil", output)
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("--output %q: error %q, want it to contain %q", output, err, want)
		}
	}

	// A directory as target: the error must not suggest --force, which
	// would fail with "is a directory" anyway.
	sub := filepath.Join(dir, "subdir")
	if err := os.Mkdir(sub, 0755); err != nil {
		t.Fatal(err)
	}
	runExpectError(t, sub, "is a directory")

	// A missing parent directory: found out before any question is asked.
	runExpectError(t, filepath.Join(dir, "no-such-dir", "config.yaml"), "output directory")

	// An empty output path.
	runExpectError(t, "", "must not be empty")
}
