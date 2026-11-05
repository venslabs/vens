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

package notify

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/venslabs/vens/pkg/notifier"
	"github.com/venslabs/vens/pkg/trivypluginutil"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "notify --vex VEX_FILE",
		Short:                 "Send scan findings to Slack",
		Long:                  "Read the CycloneDX VEX produced by 'vens generate' and ship a human-readable summary to a notification target.\n\nThe VEX stays the artifact of record; notify is a separate step you can re-run without re-running the scan.",
		Example:               Example(),
		Args:                  cobra.NoArgs,
		RunE:                  action,
		DisableFlagsInUseLine: true,
	}

	flags := cmd.Flags()
	flags.String("vex", "", "Path to the VEX file (CycloneDX format)")
	flags.String("to", "slack", "Notification target (slack)")
	flags.String("slack-webhook", "", "Slack incoming webhook URL [$SLACK_WEBHOOK_URL]")
	flags.Bool("dry-run", false, "Print the message instead of sending it")

	_ = cmd.MarkFlagRequired("vex")

	return cmd
}

func Example() string {
	exe := "vens"
	if trivypluginutil.IsTrivyPluginMode() {
		exe = "trivy " + exe
	}
	return fmt.Sprintf(`  %s generate --config-file config.yaml report.json vex.cdx.json
  %s notify --vex vex.cdx.json --to slack --slack-webhook https://hooks.slack.com/...

  # Preview the message without sending
  %s notify --vex vex.cdx.json --to slack --dry-run
`, exe, exe, exe)
}

func action(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	flags := cmd.Flags()

	vexPath, _ := flags.GetString("vex")
	target, _ := flags.GetString("to")
	webhook, _ := flags.GetString("slack-webhook")
	dryRun, _ := flags.GetBool("dry-run")

	if webhook == "" {
		webhook = os.Getenv("SLACK_WEBHOOK_URL")
	}

	vexData, err := os.ReadFile(vexPath)
	if err != nil {
		return fmt.Errorf("failed to read VEX file: %w", err)
	}
	report, err := notifier.ParseVEX(vexData)
	if err != nil {
		return err
	}
	slog.InfoContext(ctx, "VEX parsed", "vulnerabilities", report.Total)

	n, err := notifier.New(target, notifier.SlackOpts{WebhookURL: webhook})
	if err != nil {
		return err
	}

	if dryRun {
		fmt.Println(n.FormatMessage(report))
		return nil
	}

	if err := n.Send(ctx, report); err != nil {
		return err
	}
	slog.InfoContext(ctx, "Notification sent", "target", n.Name(), "vulnerabilities", report.Total)
	return nil
}
