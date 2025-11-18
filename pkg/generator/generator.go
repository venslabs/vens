package generator

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/fahedouch/vens/pkg/score/contextual/llm"
	"github.com/tmc/langchaingo/llms"
)

const (
	DefaultBatchSize        = 10
	DefaultSleepOnRateLimit = 10 * time.Second
	DefaultRetryOnRateLimit = 10
)

type Vulnerability struct {
	VulnID      string `json:"vulnId"`
	PkgID       string `json:"pkgId"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

type Opts struct {
	LLM       llms.Model
	BatchSize int // Avoid high values to avoid rate limit

	SleepOnRateLimit time.Duration
	RetryOnRateLimit int
	DebugDir         string
}

type Generator struct {
	o Opts
}

func New(o Opts) (*Generator, error) {
	g := &Generator{
		o: o,
	}
	if g.o.LLM == nil {
		return nil, errors.New("no model")
	}
	if g.o.BatchSize == 0 {
		g.o.BatchSize = DefaultBatchSize
	}
	if g.o.SleepOnRateLimit == 0 {
		g.o.SleepOnRateLimit = DefaultSleepOnRateLimit
	}
	if g.o.RetryOnRateLimit == 0 {
		g.o.RetryOnRateLimit = DefaultRetryOnRateLimit
	}
	if g.o.DebugDir != "" {
		if err := os.MkdirAll(g.o.DebugDir, 0755); err != nil {
			slog.Error("failed to create the debug dir", "error", err)
			g.o.DebugDir = ""
		}
	}
	return g, nil
}

// GenerateScores will generate contextual and community scores for the given vulnerabilities.
func (g *Generator) GenerateScores(ctx context.Context, vulns []Vulnerability, h func([]cyclonedx.VulnerabilityRating) error) error {
	batchSize := g.o.BatchSize // TODO: optimize automatically
	for i := 0; i < len(vulns); i += batchSize {
		batch := vulns[i:min(i+batchSize, len(vulns))]
		// By default we run context score and community score computations in parallel for each batch.
		// TODO: add a mechanism to enable or disable either computation.
		if err := llm.RetryOnRateLimit(ctx, g.o.SleepOnRateLimit, g.o.RetryOnRateLimit,
			func(ctx context.Context) error {
				return g.generateContextualScores(ctx, batch, h)
			}); err != nil {

			return err
		}
	}
	return nil
}

func (g *Generator) generateContextualScores(ctx context.Context, vulns []Vulnerability, h func([]cyclonedx.VulnerabilityRating) error) error {
	// TODO
	return nil
}

func (g *Generator) generateCommunityScores(ctx context.Context, vulns []Vulnerability, h func([]cyclonedx.VulnerabilityRating) error) error {
	return nil
}
