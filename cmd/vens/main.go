package main

import (
	"log/slog"
	"os"

	"github.com/fahedouch/vens/cmd/vens/commands/generate"
	"github.com/fahedouch/vens/cmd/vens/version"
	"github.com/fahedouch/vens/pkg/envutil"
	"github.com/spf13/cobra"
)

var logLevel = new(slog.LevelVar)

func main() {
	logHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	slog.SetDefault(slog.New(logHandler))
	if err := newRootCommand().Execute(); err != nil {
		slog.Error("Error", "error", err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "vens",
		Short:         "Evaluate and prioritize vulnerabilities based on context",
		Example:       generate.Example(),
		Version:       version.GetVersion(),
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	flags := cmd.PersistentFlags()

	// The debug flag value is determined by: CLI flag > DEBUG env var > default (false)
	flags.Bool("debug", envutil.Bool("DEBUG", false), "debug mode [$DEBUG]")

	cmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if debug, _ := cmd.Flags().GetBool("debug"); debug {
			logLevel.Set(slog.LevelDebug)
		}
		return nil
	}

	// TODO add generate cmd
	cmd.AddCommand(generate.New())

	return cmd
}
