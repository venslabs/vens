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

// Package generator rates the vulnerabilities of a scanner report in one
// deployment by OWASP's Risk Rating Methodology. A model answers closed
// questions about each CVE, one question per call; Go turns the answers, the
// config and the CVE's CVSS vectors into the 16 levels, and the levels into
// the vector, the severity and the score. Its batching of LLM calls is
// inspired by github.com/AkihiroSuda/vexllm.
package generator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/riskconfig"
)

const (
	DefaultBatchSize        = 10
	DefaultSleepOnRateLimit = 10 * time.Second
	DefaultRetryOnRateLimit = 10
)

// Vulnerability represents a single vulnerability from a scanner report.
// Contains all fields needed for VEX generation.
type Vulnerability struct {
	VulnID           string
	PkgID            string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	BOMRef           string // CycloneDX BOM-Ref (calculated using Trivy's logic)
	Title            string
	Description      string
	Severity         string // NVD/vendor severity
	SourceName       string
	SourceURL        string

	// CVSS is every vector the row's advisory publishes, each with its source
	// and version.
	CVSS []cvss.Vector
	// SeveritySource is where Severity comes from: Trivy's SeveritySource,
	// the matched record's namespace on Grype.
	SeveritySource string
	// VendorSeverities is each source's own severity: Trivy's VendorSeverity,
	// the related records' on Grype.
	VendorSeverities []VendorSeverity
	// Flags are the row's flags, which the scanner parser sets.
	Flags Flags
}

// Opts configures the Generator.
type Opts struct {
	LLM llm.Client
	// Temperature is the sampling temperature forwarded to the provider, nil
	// when the user did not pass --llm-temperature.
	Temperature *float64
	// BatchSize is how many CVEs a batch holds: each of its calls asks one
	// question about the batch's CVEs that get it.
	BatchSize int
	Seed      int

	SleepOnRateLimit time.Duration
	RetryOnRateLimit int
	// DebugDir gets one run-* directory per Generator, holding the prompts
	// and the raw response of every LLM call, and the run's answers.json.
	DebugDir string

	// Config is the deployment, loaded from config.yaml.
	Config *riskconfig.Config
	// Strict refuses a run that would fall back to a worst case: a config
	// leaving data_subjects, detection or traceability undeclared, and a CVE
	// with no usable CVSS v3 vector or that no row describes, both before any
	// call; then the first answer Go reads as cannot_tell, right after the
	// call that gave it.
	Strict bool
}

// Generator produces OWASP risk scores using LLM analysis.
type Generator struct {
	o Opts
	// deployment is the config as the questions read it, and system the
	// system prompt every call of the run shares.
	deployment contract.Deployment
	system     string
	attestor   *attestation.Builder
	// debugRunDir is this run's own directory under Opts.DebugDir, empty
	// when debug files are off.
	debugRunDir string
	// debugCalls numbers the LLM calls written to debugRunDir. A split call,
	// an ask-again and an adjustment are calls of their own (#359).
	debugCalls int
}

// New creates a Generator. It refuses a config the questions cannot be
// asked in and, for a strict run, one that leaves a field Go reads
// undeclared, so that nothing is spent on a run that cannot finish.
func New(o Opts) (*Generator, error) {
	if o.LLM == nil {
		return nil, errors.New("no model")
	}
	if o.Config == nil {
		return nil, errors.New("config not initialized; load config.yaml first")
	}
	d := deploymentOf(o.Config)
	system, err := contract.SystemPrompt(d)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if o.Strict {
		if err := CheckStrictConfig(o.Config); err != nil {
			return nil, err
		}
	}
	if o.BatchSize == 0 {
		o.BatchSize = DefaultBatchSize
	}
	if o.SleepOnRateLimit == 0 {
		o.SleepOnRateLimit = DefaultSleepOnRateLimit
	}
	if o.RetryOnRateLimit == 0 {
		o.RetryOnRateLimit = DefaultRetryOnRateLimit
	}
	g := &Generator{o: o, deployment: d, system: system}
	if o.DebugDir != "" {
		g.debugRunDir = newDebugRunDir(o.DebugDir)
	}
	return g, nil
}

// SetAttestor attaches an attestation Builder after construction. Pass nil to disable.
func (g *Generator) SetAttestor(b *attestation.Builder) { g.attestor = b }

// GenerateRiskScore rates every CVE of the report. Rows are grouped by CVE in
// first-seen scanner order and cut into batches of BatchSize CVEs. A batch
// asks its questions, one call each in the declared order, then adjusts its
// flagged CVEs, then hands h one rating per row. A run that stops never hands
// h the stopped batch's ratings.
func (g *Generator) GenerateRiskScore(ctx context.Context, vulns []Vulnerability, h func([]outputhandler.VulnRating) error) (err error) {
	cves, err := g.plan(ctx, vulns)
	if err != nil {
		return err
	}
	run := newScoringRun()
	// Logged and written on a failed run too, the one usually debugged.
	defer func() {
		run.summarize(ctx, len(vulns), len(cves), err)
		g.writeAnswers(ctx, run)
	}()
	if g.o.Strict {
		if err := preflight(cves); err != nil {
			return err
		}
	}
	if ids := undescribed(cves); len(ids) > 0 {
		slog.WarnContext(ctx, "No description in the scanner's report; Motive, Opportunity and Ease of exploit are not asked, each at its worst level",
			"cves", len(ids), "vulns", strings.Join(ids, ","))
	}
	if ids := vectorless(cves); len(ids) > 0 {
		slog.WarnContext(ctx, "No usable CVSS v3 vector in the scanner's report; Loss of confidentiality, integrity and availability take their worst level",
			"cves", len(ids), "vulns", strings.Join(ids, ","))
	}
	size := max(g.o.BatchSize, 1)
	for start := 0; start < len(cves); start += size {
		batch := cves[start:min(start+size, len(cves))]
		slog.DebugContext(ctx, "scoring batch",
			"cves", len(batch),
			"vulns", strings.Join(cveIDs(batch), ","),
		)
		ratings, err := g.scoreBatch(ctx, run, batch)
		if err != nil {
			return err
		}
		if h != nil && len(ratings) > 0 {
			if err := h(ratings); err != nil {
				return err
			}
		}
	}
	return nil
}
