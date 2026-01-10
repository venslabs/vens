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

package enrich

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/fahedouch/vens/pkg/trivypluginutil"
	"github.com/fahedouch/vens/pkg/vexenricher"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "enrich --vex VEX_FILE REPORT_FILE",
		Short:                 "Enrich a Trivy report with VEX statements",
		Long:                  "Enrich a Trivy vulnerability report with VEX (Vulnerability Exploitability eXchange) statements, applying ratings and status from the VEX document.",
		Example:               Example(),
		RunE:                  action,
		DisableFlagsInUseLine: true,
	}

	flags := cmd.Flags()
	flags.String("vex", "", "Path to the VEX file (CycloneDX format)")
	flags.String("output", "", "Output file path (if not specified, prints to stdout)")

	_ = cmd.MarkFlagRequired("vex")

	return cmd
}

func Example() string {
	exe := "vens"
	if trivypluginutil.IsTrivyPluginMode() {
		exe = "trivy " + exe
	}
	return fmt.Sprintf(`  # Basic usage
  trivy image python:3.12.4 --format=json --severity HIGH,CRITICAL >report.json

  %s enrich --vex vex.cdx.json report.json

  # With output file
  %s enrich --vex vex.cdx.json --output enriched-report.json report.json
`, exe, exe)
}

func action(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("report file is required")
	}

	ctx := cmd.Context()
	flags := cmd.Flags()

	vexPath, err := flags.GetString("vex")
	if err != nil {
		return err
	}
	if vexPath == "" {
		return fmt.Errorf("--vex flag is required")
	}

	outputPath, err := flags.GetString("output")
	if err != nil {
		return err
	}

	reportPath := args[0]

	// Read the report
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		return fmt.Errorf("failed to read report file: %w", err)
	}

	// Read the VEX document
	vexData, err := os.ReadFile(vexPath)
	if err != nil {
		return fmt.Errorf("failed to read VEX file: %w", err)
	}

	// Enrich the report
	enricher, err := vexenricher.New(vexData)
	if err != nil {
		return fmt.Errorf("failed to create VEX enricher: %w", err)
	}

	enrichedReport, err := enricher.EnrichReport(ctx, reportData)
	if err != nil {
		return fmt.Errorf("failed to enrich report: %w", err)
	}

	// Marshal the enriched report
	outputData, err := json.MarshalIndent(enrichedReport, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal enriched report: %w", err)
	}

	// Write output
	if outputPath != "" {
		if err := os.WriteFile(outputPath, outputData, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		slog.InfoContext(ctx, "Enriched report written", "output", outputPath)
	} else {
		fmt.Println(string(outputData))
	}

	return nil
}
