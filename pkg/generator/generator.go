package generator

import (
	"bytes"
	"context"
	"encoding/json"
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
	PkgName     string `json:"pkgName"`
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

// SBOMIndexBundle is a lightweight wrapper returned by IndexSBOMLibraries.
// It contains the in-memory vector index and a minimal resolver from
// component IDs to normalized ParentPURLs.
type SBOMIndexBundle struct {
	sbomIndex vecindex.Index
	compByID  map[string]string // ID -> normalized ParentPURL
}

// Count returns number of indexed vectors.
func (b *SBOMIndexBundle) Count() int {
	if b == nil || b.sbomIndex == nil {
		return 0
	}
	return b.sbomIndex.Count()
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

// GenerateRiskScore will generate contextual risk score for the given vulnerabilities.
func (g *Generator) GenerateRiskScore(ctx context.Context, bundle *SBOMIndexBundle, vulns []Vulnerability, h func([]cyclonedx.VulnerabilityRating) error) error {
	batchSize := g.o.BatchSize // TODO: optimize automatically
	for i := 0; i < len(vulns); i += batchSize {
		batch := vulns[i:min(i+batchSize, len(vulns))]
		if err := llm.RetryOnRateLimit(ctx, g.o.SleepOnRateLimit, g.o.RetryOnRateLimit,
			func(ctx context.Context) error {
				return g.generateRiskScore(ctx, bundle, batch, h)
			}); err != nil {

			return err
		}
	}
	return nil
}

func (g *Generator) generateRiskScore(ctx context.Context, bundle *SBOMIndexBundle, vulns []Vulnerability, h func([]cyclonedx.VulnerabilityRating) error) error {
	if bundle == nil || bundle.sbomIndex == nil {
		return errors.New("SBOM index not initialized; call IndexSBOMLibraries first")
	}

	// Aggregate all ratings across the batch
	ratings := make([]cyclonedx.VulnerabilityRating, 0)

	for _, v := range vulns {
		// Find top-k candidate SBOM libraries matching the vulnerability library
		// Keep k small; we will use LLM to filter further.
		const topK = 5
		ids, err := g.MatchVulnLibrary(ctx, bundle.sbomIndex, v, topK)
		if err != nil {
			slog.ErrorContext(ctx, "failed to match vuln library to sbom(s) libraries", "vuln", v.VulnID, "error", err)
			continue
		}
		if len(ids) == 0 {
			continue
		}

		vulnName := g.vulnerableLibraryName(v)

		filteredIDs, err := g.classifyImpactedLibraries(ctx, vulnName, ids)
		if err != nil {
			slog.ErrorContext(ctx, "LLM classification failed", "vuln", v.VulnID, "error", err)
			// If classification fails, skip scoring for this vulnerability.
			continue
		}
		if len(filteredIDs) == 0 {
			continue
		}

		// 3) Use ParentPURL of selected SBOM components to retrieve risk scores
		for _, id := range filteredIDs {
			parent, ok := bundle.compByID[id]
			if !ok {
				continue
			}
			if parent == "" {
				continue
			}
			score, ok := g.o.Context.ScoreForPURL(parent)
			if !ok {
				// no score configured for this parent purl
				continue
			}
			ratings = append(ratings, cyclonedx.VulnerabilityRating{
				// Per CycloneDX, baseScore is typically 0..10, but our OWASP score is 0..81.
				// We keep the native score in "severity" textual field and set score as-is.
				// Consumers of this MVP JSON can interpret accordingly.
				Method:   cyclonedx.ScoringMethodOther, // OWASP custom risk
				Score:    &score,
				Severity: cyclonedx.SeverityUnknown,
				Vector:   fmt.Sprintf("OWASP(parent=%s) score=%0.2f", parent, score),
				Source:   &cyclonedx.Source{Name: "vens-owasp"},
				// Supply an URL-like context pointing to the parent (optional)
				// Just informational in MVP
			})
		}
	}

	if len(ratings) == 0 {
		return nil
	}
	if h != nil {
		return h(ratings)
	}
	return nil
}

// vulnerableLibraryName derives a concise vulnerable library name from vulnerability fields.
func (g *Generator) vulnerableLibraryName(v Vulnerability) string {
	// Prefer PkgID when available; otherwise fall back to PkgName, then Title, then VulnID.
	if s := strings.TrimSpace(v.PkgID); s != "" {
		return s
	}
	if s := strings.TrimSpace(v.PkgName); s != "" {
		return s
	}
	if s := strings.TrimSpace(v.Title); s != "" {
		return s
	}
	return strings.TrimSpace(v.VulnID)
}

// classifyImpactedLibraries calls the LLM to decide which of the candidate SBOM libraries
// are actually impacted by the vulnerable library name. Returns a filtered subset of candidates.
func (g *Generator) classifyImpactedLibraries(ctx context.Context, vulnerable string, candidates []string) ([]string, error) {
	if g.o.LLM == nil {
		return nil, errors.New("no LLM configured")
	}

	systemPrompt := "You are an advanced language model that takes in a software library (which has a vulnerability) and a list of software libraries and determines which (if any) of the libraries in the given list of libraries are at risk.\n\nWhen classifying software library names based on input text, follow these guidelines:\n    \n1. **Identify Specificity**: Select the most relevant and specific library name(s) directly associated with the input text.\n    \n2. **Avoid Over-Inclusion**: Do not include unrelated or broader library names that do not directly match the input text.\n    \n3. **Prioritize Primary Libraries**: If the input text refers to a well-known software or tool, prioritize the primary library name(s) associated with it.\n    \n4. **Handle Ambiguity**: If the input text is ambiguous or does not clearly refer to a specific library, return ['No Library'].\n    \n5. **No Library Found**: If no relevant library(s) is found, return ['No Library'].\n    \nExamples:\n    \n- Input: GStreamer, [\"gstreamer1.0-plugins-base\",\"gstreamer1.0-clutter-3.0\",\"gstreamer1.0-gl\",\"gstreamer1.0-pulseaudio\",\"gstreamer1.0-x\",\"gstreamer1.0-libav\",\"gstreamer1.0-plugins-good\"]\n    \n- Output: ['gstreamer1.0-plugins-base', 'gstreamer1.0-clutter-3.0', 'gstreamer1.0-gl', 'gstreamer1.0-pulseaudio', 'gstreamer1.0-x', 'gstreamer1.0-libav', 'gstreamer1.0-plugins-good']\n    \n- Input: radeon_rx_6700, [\"libdrm-radeon1\", \"xserver-xorg-video-radeon\"]\n    \n- Output: ['No Library']\n\nOnly output a JSON array of strings representing the selected library names."

	// Represent candidates as a JSON array to help the model return a proper array.
	candJ, _ := json.Marshal(candidates)
	humanPrompt := fmt.Sprintf("Input: %s, %s", vulnerable, string(candJ))

	var buf bytes.Buffer
	msgs := []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeSystem, systemPrompt),
		llms.TextParts(llms.ChatMessageTypeHuman, humanPrompt),
	}

	callOpts := []llms.CallOption{
		llms.WithTemperature(g.o.Temperature),
		llms.WithStreamingFunc(func(ctx context.Context, chunk []byte) error {
			buf.Write(chunk)
			return nil
		}),
	}
	if g.o.Seed != 0 {
		callOpts = append(callOpts, llms.WithSeed(g.o.Seed))
	}

	// Retry on rate limit
	if err := llm.RetryOnRateLimit(ctx, g.o.SleepOnRateLimit, g.o.RetryOnRateLimit, func(c context.Context) error {
		buf.Reset()
		_, err := g.o.LLM.GenerateContent(c, msgs, callOpts...)
		return err
	}); err != nil {
		return nil, err
	}

	// Parse the output as a JSON array of strings. Accept len==0 as no selection.
	// Some models may wrap in code fences; strip common fences/backticks/newlines.
	out := strings.TrimSpace(buf.String())
	out = strings.TrimPrefix(out, "```json")
	out = strings.TrimPrefix(out, "```")
	out = strings.TrimSuffix(out, "```")
	out = strings.TrimSpace(out)

	var arr []string
	if err := json.Unmarshal([]byte(out), &arr); err != nil {
		// Try to coerce simple comma-separated values
		// As a last resort, return no selection to avoid false positives.
		return nil, fmt.Errorf("unable to parse LLM output as JSON array: %w: %q", err, out)
	}
	// If model returns ['No Library'], treat as empty selection.
	filtered := make([]string, 0, len(arr))
	for _, s := range arr {
		s = strings.TrimSpace(s)
		if s == "" || strings.EqualFold(s, "No Library") {
			continue
		}
		// Keep only if it exists in candidates to avoid hallucinations.
		for _, c := range candidates {
			if s == c {
				filtered = append(filtered, s)
				break
			}
		}
	}
	return filtered, nil
}

// IndexSBOMLibraries streams CycloneDX SBOMs and builds an in-memory vector index
// of their components. Embeddings are generated via the configured LLM, in batches,
// with rate-limit retry. Returns the populated index bundle.
func (g *Generator) IndexSBOMLibraries(ctx context.Context, sbomPaths []string) (*SBOMIndexBundle, error) {
	idx := vecindex.NewSBOMVecIndex()
	compByExtID := make(map[string]string)

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
			// store normalized ParentPURL mapping now; last seen wins which is fine
			compByExtID[id] = riskconfig.NormalizePURL(c.ParentPURL)
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

	return &SBOMIndexBundle{sbomIndex: idx, compByID: compByExtID}, nil
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
	embedder, err := g.newEmbedder()
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
func (g *Generator) newEmbedder() (langemb.Embedder, error) {
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

// vulnLibraryText builds a search query text from a vulnerability to match SBOM libraries.
func vulnLibraryText(v Vulnerability) string {
	// Favor matching order: PkgID, PkgName, Title, Description (truncated).
	desc := v.Description
	// TODO: evaluate whether truncating the description is beneficial; run tests to decide.
	if len(desc) > 256 {
		desc = desc[:256]
	}
	return fmt.Sprintf("PkgID=%s | PkgName=%s | title=%s | desc=%s", v.PkgID, v.PkgName, v.Title, desc)
}

// MatchVulnLibrary embeds the vulnerability library text and searches top-k matches in the index.
// TODO: the retry on rate limit is handled by the caller.
func (g *Generator) MatchVulnLibrary(ctx context.Context, idx vecindex.Index, v Vulnerability, k int) ([]string, error) {
	if g.o.LLM == nil {
		return nil, errors.New("no LLM configured for embeddings")
	}
	emb, err := g.newEmbedder()
	if err != nil {
		return nil, err
	}

	vecs, err := emb.EmbedDocuments(ctx, []string{vulnLibraryText(v)})
	if err != nil {
		return nil, err
	}
	if len(vecs) == 0 {
		return nil, fmt.Errorf("no embedding returned for vulnerability %s", v.VulnID)
	}

	if k <= 0 {
		k = 1
	}

	ids, err := idx.Search(vecs[0], k)
	if err != nil {
		return nil, err
	}
	return ids, nil
}
