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

package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/fahedouch/vens/cmd/vens/commands/generate"
	"github.com/fahedouch/vens/pkg/api/types"
	"github.com/fahedouch/vens/pkg/outputhandler"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "scan [flags] -- [trivy flags]",
		Short:   "Run Trivy scan and enrich results with Vens",
		Long:    "Automatically runs 'trivy' with JSON output, then enriches the result using Vens and displays it.",
		Example: `  vens scan --config-file config.yaml --sboms sbom.cdx.json -- image python:3.12.4`,
		RunE:    action,
	}

	flags := cmd.Flags()
	flags.String("config-file", "", "Path to config.yaml file")
	flags.String("sboms", "", "Comma-separated list of CycloneDX SBOMs (assets)")
	flags.String("llm", "auto", "LLM backend")
	flags.String("output-format", "trivytable", "Output format (trivytable, trivyjson)")

	return cmd
}

func action(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()
	configPath, _ := flags.GetString("config-file")
	sboms, _ := flags.GetString("sboms")
	llm, _ := flags.GetString("llm")
	outputFormat, _ := flags.GetString("output-format")
	if outputFormat == "cyclonedxvex" {
		return fmt.Errorf("output-format 'cyclonedxvex' is not supported for 'scan' command. Use 'generate' command for VEX output")
	}

	if configPath == "" || sboms == "" {
		return fmt.Errorf("both --config-file and --sboms are required")
	}

	if len(args) == 0 {
		return fmt.Errorf("no trivy arguments provided. use '--' to separate vens flags from trivy flags")
	}

	// 1. Prepare Trivy command
	trivyArgs := append([]string{}, args...)

	trivyArgs = append(trivyArgs, "--format", "json")

	slog.Info("Running Trivy scan...", "args", strings.Join(trivyArgs, " "))
	trivyCmd := exec.Command("trivy", trivyArgs...)
	var stdout, stderr bytes.Buffer
	trivyCmd.Stdout = &stdout
	trivyCmd.Stderr = &stderr

	// 1. Execute Trivy command
	if err := trivyCmd.Run(); err != nil {
		fmt.Fprint(os.Stderr, stderr.String())
		return fmt.Errorf("trivy scan failed: %w", err)
	}

	// 2. Create temporary file for Trivy JSON
	tmpReport, err := os.CreateTemp("", "trivy-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp report file: %w", err)
	}
	defer os.Remove(tmpReport.Name())

	if _, err := tmpReport.Write(stdout.Bytes()); err != nil {
		return fmt.Errorf("failed to write to temp report file: %w", err)
	}
	tmpReport.Close()

	// 2.5 Create temporary file for VEX
	tmpVEX, err := os.CreateTemp("", "vens-*.vex.cdx.json")
	if err != nil {
		return fmt.Errorf("failed to create temp vex file: %w", err)
	}
	defer os.Remove(tmpVEX.Name())
	tmpVEX.Close()

	// 2. Call Vens Generate logic to generate VEX
	generateCmd := generate.New()
	genArgs := []string{
		tmpReport.Name(),
		tmpVEX.Name(),
		"--config-file", configPath,
		"--sboms", sboms,
		"--llm", llm,
		"--output-format", "cyclonedxvex",
	}

	slog.Info("Generating VEX with Vens...")
	generateCmd.SetArgs(genArgs)
	if err := generateCmd.Execute(); err != nil {
		return err
	}

	// 3. Enrich the original report with the generated VEX
	// Read the original Trivy JSON
	reportB, err := os.ReadFile(tmpReport.Name())
	if err != nil {
		return fmt.Errorf("failed to read report file: %w", err)
	}
	var report types.Report
	if err := json.Unmarshal(reportB, &report); err != nil {
		return fmt.Errorf("failed to unmarshal report: %w", err)
	}

	// Read the generated VEX
	vexB, err := os.ReadFile(tmpVEX.Name())
	if err != nil {
		return fmt.Errorf("failed to read vex file: %w", err)
	}
	var vex cyclonedx.BOM
	if err := json.Unmarshal(vexB, &vex); err != nil {
		return fmt.Errorf("failed to unmarshal vex: %w", err)
	}

	slog.Info("Enriching results with Vens scores...")
	if err := outputhandler.EnrichTrivyReportWithVEX(&report, &vex); err != nil {
		return fmt.Errorf("failed to enrich report: %w", err)
	}

	// 4. Display the enriched report
	return displayReport(outputFormat, &report)
}

func displayReport(format string, report *types.Report) error {
	if format == "trivyjson" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	handler := outputhandler.NewTrivyTableOutputHandler(os.Stdout)
	var ratings []outputhandler.VulnRating
	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			if v.VensRating != nil {
				ratings = append(ratings, outputhandler.VulnRating{
					VulnID:      v.VulnerabilityID,
					AffectedRef: v.PkgID,
					Rating: cyclonedx.VulnerabilityRating{
						Score:         &v.VensRating.Score,
						Severity:      cyclonedx.Severity(v.VensRating.Severity),
						Justification: v.VensRating.Justification,
					},
				})
			}
		}
	}

	if err := handler.HandleVulnRatings(ratings); err != nil {
		return err
	}
	return handler.Close()
}
