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

// Package notifier routes vens scan output to human-facing destinations
// instead of only writing a VEX file. It reads the CycloneDX VEX that
// `vens generate` produces, so notify re-runs without re-running the scan.
package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Finding is one scored vulnerability from the VEX.
type Finding struct {
	VulnID   string
	Severity string // critical/high/medium/low/info/unknown
	Score    float64
	Vector   string
	Affects  []string // component refs the VEX marks affected
}

// Report summarizes a VEX document for human notification.
type Report struct {
	Total      int
	BySeverity map[string]int
	Findings   []Finding // sorted by severity band, then score, descending
}

// ParseVEX reads a CycloneDX VEX (as written by `vens generate`) and builds
// the notification report from its OWASP ratings. Non-OWASP ratings are
// ignored; a vulnerability with no OWASP rating lands as severity "unknown".
func ParseVEX(data []byte) (*Report, error) {
	var doc cdx.BOM
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse VEX document: %w", err)
	}
	r := &Report{BySeverity: map[string]int{}}
	if doc.Vulnerabilities == nil {
		return r, nil
	}
	for _, v := range *doc.Vulnerabilities {
		f := Finding{VulnID: v.ID, Severity: "unknown"}
		if v.Affects != nil {
			for _, a := range *v.Affects {
				f.Affects = append(f.Affects, a.Ref)
			}
		}
		if v.Ratings != nil {
			for _, rating := range *v.Ratings {
				if rating.Method != cdx.ScoringMethodOWASP || rating.Score == nil {
					continue
				}
				f.Score = *rating.Score
				f.Vector = rating.Vector
				f.Severity = strings.ToLower(string(rating.Severity))
				if f.Severity == "" {
					f.Severity = "unknown"
				}
			}
		}
		r.Findings = append(r.Findings, f)
		r.BySeverity[f.Severity]++
	}
	r.Total = len(r.Findings)
	sort.Slice(r.Findings, func(i, j int) bool {
		si, sj := severityRank(r.Findings[i].Severity), severityRank(r.Findings[j].Severity)
		if si != sj {
			return si < sj
		}
		return r.Findings[i].Score > r.Findings[j].Score
	})
	return r, nil
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	default:
		return 5
	}
}

// Notifier ships a scan report to one destination. New targets (Jira,
// Linear, ...) implement this interface; New wires the --to flag to the
// right one, so the interface stays unchanged as targets are added.
type Notifier interface {
	// Name returns the --to value this notifier handles ("slack", ...).
	Name() string
	// FormatMessage renders the report in the target's message format.
	FormatMessage(r *Report) string
	// Send delivers the report. Implementations must be stateless: one
	// message per run, nothing remembered between runs.
	Send(ctx context.Context, r *Report) error
}

// SlackOpts configures the Slack notifier.
type SlackOpts struct {
	// WebhookURL is the incoming-webhook URL (from --slack-webhook or
	// $SLACK_WEBHOOK_URL).
	WebhookURL string
	// HTTPClient, when nil, defaults to a 15s-timeout client.
	HTTPClient *http.Client
}

// New returns the notifier for target ("slack" today). Unknown targets
// error naming the supported ones, so adding jira/linear is one case here
// plus a constructor — the interface stays unchanged.
//
// The Slack webhook is only required at Send time, not here: building a
// notifier for formatting alone (e.g. `vens notify --dry-run`) must work
// without one.
func New(target string, o SlackOpts) (Notifier, error) {
	switch target {
	case "slack":
		return &SlackNotifier{opts: o}, nil
	default:
		return nil, fmt.Errorf("unknown notify target %q (supported: slack)", target)
	}
}

// SlackNotifier posts the report to a Slack incoming webhook.
type SlackNotifier struct {
	opts SlackOpts
}

// Name implements Notifier.
func (n *SlackNotifier) Name() string { return "slack" }

// FormatMessage implements Notifier: a compact mrkdwn summary — totals by
// severity band, then the top 5 findings.
func (n *SlackNotifier) FormatMessage(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "*vens scan:* %d %s scored\n", r.Total, pluralize(r.Total, "vulnerability", "vulnerabilities"))
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if c := r.BySeverity[sev]; c > 0 {
			fmt.Fprintf(&b, "• %s: %d\n", sev, c)
		}
	}
	top := r.Findings
	if len(top) > 5 {
		top = top[:5]
	}
	if len(top) > 0 {
		b.WriteString("\n*Top findings:*\n")
		for _, f := range top {
			fmt.Fprintf(&b, "• `%s` — %.1f (%s)\n", f.VulnID, f.Score, f.Severity)
		}
	}
	return b.String()
}

func pluralize(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Send implements Notifier: one stateless message per run.
func (n *SlackNotifier) Send(ctx context.Context, r *Report) error {
	if n.opts.WebhookURL == "" {
		return fmt.Errorf("slack notifier needs a webhook URL: pass --slack-webhook or set SLACK_WEBHOOK_URL")
	}
	payload, err := json.Marshal(map[string]string{"text": n.FormatMessage(r)})
	if err != nil {
		return fmt.Errorf("failed to build slack payload: %w", err)
	}
	client := n.opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.opts.WebhookURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to build slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to post to slack: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned %s", resp.Status)
	}
	return nil
}
