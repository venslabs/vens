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
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	trivytypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/spf13/cobra"
	"github.com/venslabs/vens/pkg/generator"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/llm/llmfactory"
	outputhandler "github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/riskconfig"
	"github.com/venslabs/vens/pkg/trivypluginutil"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate INPUT OUTPUT",
		Short: "Generate CycloneDX VEX with OWASP risk scores using LLM",
		Long: `Generate Vulnerability-Exploitability eXchange (VEX) information using an LLM to prioritize CVEs based on risk.

The LLM analyzes each vulnerability using the project context hints you provide:
- Exposure: How is the system exposed? (internal, private, internet)
- Data Sensitivity: What type of data is handled? (low, medium, high, critical)
- Business Criticality: How critical is the system? (low, medium, high, critical)

The LLM calculates the OWASP risk score (0-81) for each vulnerability using:
  Risk = Likelihood × Impact
  Where: Likelihood = (Threat Agent + Vulnerability Factor) / 2
         Impact = (Technical Impact + Business Impact) / 2`,
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
	flags.String("config-file", "", "Path to config.yaml file with OWASP factors")
	flags.String("input-format", "auto", "Input format ([auto trivy])")
	flags.String("output-format", "auto", "Output format ([auto cyclonedxvex])")
	flags.String("debug-dir", "", "Directory to save debug files (prompts, responses)")

	return cmd
}

func Example() string {
	exe := "vens"
	if trivypluginutil.IsTrivyPluginMode() {
		exe = "trivy " + exe
	}
	return fmt.Sprintf(`  # Basic usage
  export OPENAI_API_KEY=...
  export OPENAI_MODEL=gpt-4o-mini

  # Scan an image and generate a vulnerability report
  trivy image nginx:1.25 --format=json --severity HIGH,CRITICAL > report.json

  # Generate OWASP risk scores using LLM
  %s generate --config-file config.yaml report.json output.cdx.json

  # Example config.yaml:
  # project:
  #   name: "nginx-production"
  #   description: "Production web server"
  # context:
  #   exposure: "internet"              # internal | private | internet
  #   data_sensitivity: "high"          # low | medium | high | critical
  #   business_criticality: "critical"  # low | medium | high | critical
  #   notes: "Handles customer PII"     # optional
`, exe)
}

func action(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	flags := cmd.Flags()

	configPath, _ := flags.GetString("config-file")
	if configPath == "" {
		return fmt.Errorf("--config-file is required")
	}

	// Load config.yaml with context hints
	cfg, err := riskconfig.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config file %q: %w", configPath, err)
	}
	if cfg == nil {
		return fmt.Errorf("config file %q is empty or invalid", configPath)
	}

	slog.InfoContext(ctx, "Config loaded",
		"project", cfg.Project.Name,
		"exposure", cfg.Context.Exposure,
		"data_sensitivity", cfg.Context.DataSensitivity,
		"business_criticality", cfg.Context.BusinessCriticality,
	)

	var o generator.Opts
	o.Config = cfg

	llmName, err := flags.GetString("llm")
	if err != nil {
		return err
	}
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
	o.DebugDir, err = flags.GetString("debug-dir")
	if err != nil {
		return err
	}

	g, err := generator.New(o)
	if err != nil {
		return err
	}

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

	// Read vulnerability report
	inputB, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var input trivytypes.Report
	if err = json.Unmarshal(inputB, &input); err != nil {
		return fmt.Errorf("failed to parse input as Trivy report: %w", err)
	}

	// Setup output handler
	var h outputhandler.OutputHandler
	outputW, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputW.Close() //nolint:errcheck

	outputFormat, err := flags.GetString("output-format")
	if err != nil {
		return err
	}

	if outputFormat == "" || outputFormat == "auto" {
		outputFormat = "cyclonedxvex"
		slog.DebugContext(ctx, "Automatically choosing output format", "format", outputFormat)
	}

	switch outputFormat {
	case "cyclonedxvex":
		h = outputhandler.NewCycloneDxVexOutputHandler(outputW)
	default:
		return fmt.Errorf("unknown output format %q", outputFormat)
	}

	// Convert Trivy vulnerabilities to generator format
	var vulns []generator.Vulnerability
	for _, result := range input.Results {
		for _, v := range result.Vulnerabilities {
			vulns = append(vulns, generator.Vulnerability{
				VulnID:      v.VulnerabilityID,
				PkgID:       v.PkgID,
				PkgName:     v.PkgName,
				Title:       v.Title,
				Description: v.Description,
				Severity:    v.Severity,
			})
		}
	}

	if len(vulns) == 0 {
		slog.WarnContext(ctx, "No vulnerabilities found in the report")
		if err := h.Close(); err != nil {
			return fmt.Errorf("failed to close output: %w", err)
		}
		return nil
	}

	slog.InfoContext(ctx, "Processing vulnerabilities", "count", len(vulns))

	// Generate risk scores using LLM
	if err = g.GenerateRiskScore(ctx, vulns, h.HandleVulnRatings); err != nil {
		return fmt.Errorf("failed to generate risk scores: %w", err)
	}

	return h.Close()
}
