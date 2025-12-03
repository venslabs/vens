package generate

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	trivytypes "github.com/fahedouch/vens/pkg/api/types"
	"github.com/fahedouch/vens/pkg/generator"
	"github.com/fahedouch/vens/pkg/llm"
	"github.com/fahedouch/vens/pkg/llm/llmfactory"
	outputhandler "github.com/fahedouch/vens/pkg/outputhandler"
	"github.com/fahedouch/vens/pkg/riskconfig"
	"github.com/spf13/cobra"
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
	flags.String("sboms", "", "Comma-separated list of CycloneDX SBOMs")
	flags.String("input-format", "auto", "Input format ([auto trivy])")
	flags.String("output-format", "auto", "Output format ([auto cyclonedxvex])")

	return cmd
}

func Example() string {
	return "vens generate --config-file config.yaml --sboms sbom1.cdx.json,sbom2.cdx.json trivy.json output.cdx"
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
	sbomPaths := strings.Split(sboms, ",")
	idx, err := g.IndexSBOMLibraries(ctx, sbomPaths)
	if err != nil {
		return err
	}
	slog.InfoContext(ctx, "SBOM libraries indexed", "count", idx.Count())

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
	inputB, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	var input trivytypes.Report
	if err = json.Unmarshal(inputB, &input); err != nil {
		return err
	}

	// For now, use CycloneDX VEX as the output.
	// In parallel, encourage scanners to consider ratings originating from the VEX.
	// Request that OpenVEX add support for ratings in the OpenVEX format.
	var h outputhandler.OutputHandler
	outputW, err := os.Create(outputPath)
	if err != nil {
		return err
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
	defer h.Close() //nolint:errcheck

	vulns := make([]generator.Vulnerability, len(input.Results[0].Vulnerabilities))
	for i, f := range input.Results[0].Vulnerabilities {
		vulns[i] = generator.Vulnerability{
			VulnID:      f.VulnerabilityID,
			PkgID:       f.PkgID,
			Title:       f.Title,
			Description: f.Description,
			Severity:    f.Severity,
			// TODO: CVSS
		}
	}

	if err = g.GenerateScores(ctx, vulns, nil); err != nil {
		return err
	}

	return h.Close()
}
