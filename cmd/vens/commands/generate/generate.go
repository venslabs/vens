package generate

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/AkihiroSuda/vexllm/pkg/llm"
	"github.com/AkihiroSuda/vexllm/pkg/llm/llmfactory"
	"github.com/AkihiroSuda/vexllm/pkg/outputhandler"
	"github.com/AkihiroSuda/vexllm/pkg/trivypluginutil"
	"github.com/fahedouch/vens/pkg/api/types"
	"github.com/fahedouch/vens/pkg/generator"
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

	return cmd
}

func action(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	flags := cmd.Flags()

	inputPath, outputPath := args[0], args[1]
	inputFormat, err := flags.GetString("input-format")
	if err != nil {
		return err
	}

	if inputFormat == "" || inputPath == "auto" {
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

	g, err := generator.New(o)
	if err != nil {
		return err
	}

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
