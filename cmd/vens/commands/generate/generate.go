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

package generate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/cobra"

	trivytypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/fahedouch/vens/pkg/generator"
	"github.com/fahedouch/vens/pkg/llm"
	"github.com/fahedouch/vens/pkg/llm/llmfactory"
	"github.com/fahedouch/vens/pkg/outputhandler"
	"github.com/fahedouch/vens/pkg/riskconfig"
	"github.com/fahedouch/vens/pkg/trivypluginutil"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "generate INPUT OUTPUT",
		Short:                 "Generate VEX using LLM",
		Long:                  "Generate Vulnerability-Exploitability eXchange (VEX) information using an LLM to prioritize CVEs based on risk.",
		Example:               Example(),
		Args:                  cobra.ExactArgs(2),
		RunE:                  action,
		DisableFlagsInUseLine: true,
	}

	flags := cmd.Flags()
	flags.String("llm", llm.Auto, fmt.Sprintf("LLM backend (%v)", llm.Names))
	flags.Float64("llm-temperature", 0.0, "Temperature (0.0 means no explicit temperature)")
	flags.Int("llm-batch-size", generator.DefaultBatchSize, "LLM batch size")
	flags.Int("llm-seed", 0, "Seed (0 means no explicit seed)")
	flags.String("config-file", "", "Path to config.yaml file")
	// We support CycloneDX SBOMs because they are more application-oriented and lighter in terms of data.
	flags.String("sboms", "", "Comma-separated list of CycloneDX SBOMs (assets)")
	flags.String("input-format", "auto", "Input format ([auto trivy])")
	flags.String("output-format", "auto", "Output format ([auto cyclonedxvex trivyjson trivytable])")
	flags.StringSlice("severity", nil, "Filter by severities (e.g., CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN) - only for trivytable")

	return cmd
}

func Example() string {
	exe := "vens"
	if trivypluginutil.IsTrivyPluginMode() {
		exe = "trivy " + exe
	}
	return fmt.Sprintf(`  # Generate VEX with Vens risk scores
  trivy image python:3.12.4 --format=json > python.json
  %s generate --config-file config.yaml --sboms sbom.cdx.json python.json vex.cdx.json

  # Enrich Trivy JSON report with Vens risk scores
  %s generate --config-file config.yaml --sboms sbom.cdx.json python.json enriched.json --output-format trivyjson

  # Display Vens risk scores in Trivy table format
  %s generate --config-file config.yaml --sboms sbom.cdx.json python.json /dev/stdout --output-format trivytable

  # Complete workflow: SBOM -> Scan -> Enrich
  trivy image alpine:3.15 --format cyclonedx --output sbom.json
  trivy sbom sbom.json --format json --output report.json
  %s generate --config-file config.yaml --sboms sbom.json report.json enriched.json --output-format trivyjson`, exe, exe, exe, exe)
}

func action(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	flags := cmd.Flags()

	configPath, _ := flags.GetString("config-file")
	sboms, _ := flags.GetString("sboms")

	if configPath == "" || len(sboms) == 0 {
		return fmt.Errorf("both config-file and sboms must be provided")
	}

	// Load `config.yaml` before `sboms`
	// If the configuration file is invalid or missing, fail fast before starting the expensive SBOM processing.
	// This follows the "fail fast" principle and improves the user experience.
	slog.Info("Loading Vens configuration...", "path", configPath)
	ctxFile, err := riskconfig.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config file %q: %w", configPath, err)
	}
	if ctxFile == nil {
		return fmt.Errorf("config file %q is empty or invalid", configPath)
	}
	slog.InfoContext(ctx, "Config loaded", "entries", len(ctxFile.OWASP))

	var o generator.Opts
	o.Context = ctxFile

	llmName, err := flags.GetString("llm")
	if err != nil {
		return err
	}
	slog.Info("Initializing LLM...", "backend", llmName)
	o.LLM, err = llmfactory.New(ctx, llmName)
	if err != nil {
		return err
	}
	o.Temperature, err = flags.GetFloat64("llm-temperature")
	if err != nil {
		return err
	}
	o.BatchSize, err = flags.GetInt("llm-batch-size")
	if err != nil {
		return err
	}
	o.Seed, err = flags.GetInt("llm-seed")
	if err != nil {
		return err
	}

	g, err := generator.New(o)
	if err != nil {
		return err
	}

	// Load the SBOMs and build the vector index
	slog.Info("Indexing SBOM libraries...")
	sbomPaths := strings.Split(sboms, ",")
	bundle, err := g.IndexSBOMLibraries(ctx, sbomPaths)
	if err != nil {
		return err
	}
	slog.InfoContext(ctx, "SBOM libraries indexed", "count", bundle.Count())

	inputPath, outputPath := args[0], args[1]
	inputFormat, err := flags.GetString("input-format")
	if err != nil {
		return err
	}

	if inputFormat == "" || inputFormat == "auto" {
		inputFormat = "trivy"
		slog.DebugContext(ctx, "Automatically choosing input format", "format", inputFormat)
	}

	switch inputFormat {
	case "trivy":
		// NOP: we currently support only trivy
	default:
		return fmt.Errorf("unknown input format %q", inputFormat)
	}

	// TODO the trivy report should be streamed and embbed like sbom libraries
	// to accelerate proccessing
	slog.Info("Reading Trivy report...", "path", inputPath)
	inputB, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	var trivyReport trivytypes.Report
	if err = json.Unmarshal(inputB, &trivyReport); err != nil {
		return err
	}

	outputFormat, err := flags.GetString("output-format")
	if err != nil {
		return err
	}

	if outputFormat == "" || outputFormat == "auto" {
		outputFormat = "cyclonedxvex"
		slog.DebugContext(ctx, "Automatically choosing output format", "format", outputFormat)
	}

	// Generate VEX with risk scores
	slog.Info("Generating VEX with Vens risk scores...")
	var vexBuf bytes.Buffer
	vexHandler := outputhandler.NewCycloneDxVexOutputHandler(&vexBuf)

	// Collect all vulnerabilities from all results
	var allVulns []generator.Vulnerability
	for _, result := range trivyReport.Results {
		for _, vuln := range result.Vulnerabilities {
			allVulns = append(allVulns, generator.Vulnerability{
				VulnID:      vuln.VulnerabilityID,
				PkgID:       vuln.PkgID,
				Title:       vuln.Title,
				Description: vuln.Description,
				Severity:    vuln.Severity,
			})
		}
	}

	if len(allVulns) == 0 {
		slog.Info("No vulnerabilities found in the report")
		return nil
	}

	// Generate risk scores
	if err := g.GenerateRiskScore(ctx, bundle, allVulns, vexHandler.HandleVulnRatings); err != nil {
		return fmt.Errorf("failed to generate risk scores: %w", err)
	}
	if err := vexHandler.Close(); err != nil {
		return fmt.Errorf("failed to close VEX handler: %w", err)
	}

	// Parse the generated VEX
	var vex cdx.BOM
	if err := json.Unmarshal(vexBuf.Bytes(), &vex); err != nil {
		return fmt.Errorf("failed to unmarshal VEX: %w", err)
	}

	// Handle output based on format
	switch outputFormat {
	case "cyclonedxvex":
		// Output VEX only
		return outputhandler.WriteVEX(outputPath, &vex)

	case "trivyjson", "trivytable":
		// Apply VEX to Trivy report and output in Trivy format
		severity, _ := flags.GetStringSlice("severity")
		return outputhandler.ApplyVEXAndOutputTrivyReport(ctx, outputPath, outputFormat, &trivyReport, &vex, severity)

	default:
		return fmt.Errorf("unknown output format %q", outputFormat)
	}
}
