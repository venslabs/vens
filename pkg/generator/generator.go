package generator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	trivytypes "github.com/fahedouch/vens/pkg/api/types"
	"github.com/fahedouch/vens/pkg/llm"
	"github.com/fahedouch/vens/pkg/riskconfig"
	"github.com/fahedouch/vens/pkg/sbom"
	"github.com/fahedouch/vens/pkg/vecindex"
	langemb "github.com/tmc/langchaingo/embeddings"
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
	LLM         llms.Model
	Temperature float64
	BatchSize   int // Avoid high values to avoid rate limit
	Seed        int

	SleepOnRateLimit time.Duration
	RetryOnRateLimit int
	DebugDir         string

	// Context carries user-provided OWASP scores and factors loaded from config.yaml.
	Context *riskconfig.Config
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
				// implement a fallback mechanism for the LLM
				// heuristic matching to map vulnerability library entries to SBOM library entries
				return g.generateContextualScores(ctx, batch, h)
			}); err != nil {

			return err
		}
	}
	return nil
}

func (g *Generator) generateContextualScores(ctx context.Context, vulns []Vulnerability, h func([]cyclonedx.VulnerabilityRating) error) error {
	// MVP: if no LLM configured, do nothing
	if g.o.LLM == nil {
		slog.Debug("No LLM configured; skipping contextual scoring (MVP no-op)")
		return nil
	}
	// Future: call LLM with prompt and parse ratings, then pass to handler.
	_ = fmt.Sprintf
	_ = os.Stderr
	return nil
}

func (g *Generator) generateCommunityScores(ctx context.Context, vulns []Vulnerability, h func([]cyclonedx.VulnerabilityRating) error) error {
	return nil
}

// IndexSBOMLibraries streams CycloneDX SBOMs and builds an in-memory vector index
// of their components. Embeddings are generated via the configured LLM, in batches,
// with rate-limit retry. Returns the populated index.
func (g *Generator) IndexSBOMLibraries(ctx context.Context, sbomPaths []string) (vecindex.Index, error) {
	idx := vecindex.NewSBOMVecIndex()

	type embBatch struct {
		comps []trivytypes.SBOMComponent
		ids   []string
	}

	batches := make(chan embBatch, 2)
	errCh := make(chan error, 1)
	done := make(chan struct{})

	// Worker: consumes batches, computes embeddings and indexes
	go func() {
		defer close(done)
		for b := range batches {
			vecs, err := g.ComponentEmbeddings(ctx, b.comps)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			for i, id := range b.ids {
				if err := idx.Add(id, vecs[i]); err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
			}
		}
	}()

	// Producer: stream SBOMs and send batches to worker
	for _, p := range sbomPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		curComps := make([]trivytypes.SBOMComponent, 0, g.BatchSize())
		curIDs := make([]string, 0, g.BatchSize())

		flushSend := func() error {
			if len(curComps) == 0 {
				return nil
			}
			// copier/swapper pour libérer le producteur immédiatement
			comps := make([]trivytypes.SBOMComponent, len(curComps))
			copy(comps, curComps)
			ids := make([]string, len(curIDs))
			copy(ids, curIDs)
			curComps = curComps[:0]
			curIDs = curIDs[:0]

			select {
			case batches <- embBatch{comps: comps, ids: ids}:
				return nil
			case err := <-errCh:
				return err
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		if err := sbom.StreamCycloneDXLibraries(p, func(c trivytypes.SBOMComponent) error {
			id := c.PURL
			if id == "" {
				if c.Group != "" {
					id = c.Group + "/" + c.Name
				} else {
					id = c.Name
				}
				if c.Version != "" {
					id = id + "@" + c.Version
				}
			}
			curComps = append(curComps, c)
			curIDs = append(curIDs, id)
			if len(curComps) >= g.BatchSize() {
				return flushSend()
			}
			// if the worker has already failed, stop the stream
			select {
			case err := <-errCh:
				return err
			default:
			}
			return nil
		}); err != nil {
			close(batches)
			<-done
			return nil, fmt.Errorf("failed to process SBOM %s: %w", p, err)
		}

		if err := flushSend(); err != nil {
			close(batches)
			<-done
			return nil, fmt.Errorf("failed to finalize SBOM %s: %w", p, err)
		}
	}

	close(batches)
	<-done
	select {
	case err := <-errCh:
		return nil, err
	default:
	}
	return idx, nil
}

// BatchSize returns the configured batch size for LLM operations.
func (g *Generator) BatchSize() int { return g.o.BatchSize }

// ComponentEmbeddings generates embeddings for a batch of components using the LLM.
// It retries on rate limit using llm.RetryOnRateLimit and the configured batch size.
// Returns an error if the LLM call fails or the output cannot be parsed (no fallback).
func (g *Generator) ComponentEmbeddings(ctx context.Context, comps []trivytypes.SBOMComponent) ([][]float32, error) {
	if g.o.LLM == nil {
		return nil, errors.New("no LLM configured")
	}
	out := make([][]float32, 0, len(comps))
	// Prepare embedder once per call.
	embedder, err := g.newEmbedder(ctx)
	if err != nil {
		return nil, err
	}
	batchSize := g.o.BatchSize

	for i := 0; i < len(comps); i += batchSize {
		batch := comps[i:min(i+batchSize, len(comps))]
		// Build texts for the batch
		texts := make([]string, len(batch))
		for j, c := range batch {
			texts[j] = componentText(c)
		}
		var vecs [][]float32
		if err := llm.RetryOnRateLimit(ctx, g.o.SleepOnRateLimit, g.o.RetryOnRateLimit, func(ctx context.Context) error {
			var eerr error
			vecs, eerr = embedder.EmbedDocuments(ctx, texts)
			return eerr
		}); err != nil {
			return nil, err
		}
		// Keep vectors as returned by the provider (native dimensionality).
		// TODO: fix dimensionality if it is too large for available memory
		out = append(out, vecs...)
	}
	return out, nil
}

// ComponentEmbedding convenience wrapper for a single component.
func (g *Generator) ComponentEmbedding(ctx context.Context, c trivytypes.SBOMComponent) []float32 {
	vecs, err := g.ComponentEmbeddings(ctx, []trivytypes.SBOMComponent{c})
	if err != nil || len(vecs) == 0 {
		slog.ErrorContext(ctx, "failed to generate embedding", "error", err, "component", c.PURL)
		return nil
	}
	return vecs[0]
}

// newEmbedder builds a langchaingo embeddings.Embedder aligned with the selected LLM backend.
func (g *Generator) newEmbedder(ctx context.Context) (langemb.Embedder, error) {
	type embeddingLLM interface {
		CreateEmbedding(context.Context, []string) ([][]float32, error)
	}
	embModel, ok := g.o.LLM.(embeddingLLM)
	if !ok {
		return nil, fmt.Errorf("configured LLM of type %T does not support embeddings", g.o.LLM)
	}
	client := langemb.EmbedderClientFunc(func(c context.Context, texts []string) ([][]float32, error) {
		return embModel.CreateEmbedding(c, texts)
	})
	return langemb.NewEmbedder(client,
		langemb.WithBatchSize(g.o.BatchSize),
		langemb.WithStripNewLines(true),
	)
}

// componentText builds a deterministic text for the component to feed the embedder.
func componentText(c trivytypes.SBOMComponent) string {
	// Prefer PURL when available; include group/name/version for extra signal.
	base := c.PURL
	if base == "" {
		if c.Group != "" {
			base = c.Group + "/" + c.Name
		} else {
			base = c.Name
		}
		if c.Version != "" {
			base += "@" + c.Version
		}
	}
	// Include structured fields to keep text stable across providers.
	return fmt.Sprintf("%s | group=%s name=%s version=%s", base, c.Group, c.Name, c.Version)
}
