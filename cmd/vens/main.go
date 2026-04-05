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

package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/venslabs/vens/cmd/vens/commands/enrich"
	"github.com/venslabs/vens/cmd/vens/commands/generate"
	"github.com/venslabs/vens/cmd/vens/version"
	"github.com/venslabs/vens/pkg/envutil"
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

	cmd.AddCommand(
		generate.New(),
		enrich.New(),
	)

	return cmd
}
