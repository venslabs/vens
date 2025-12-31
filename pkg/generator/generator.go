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
	"github.com/fahedouch/vens/pkg/api/types"
	"github.com/fahedouch/vens/pkg/llm"
	outputhandler "github.com/fahedouch/vens/pkg/outputhandler"
	"github.com/fahedouch/vens/pkg/riskconfig"
	"github.com/fahedouch/vens/pkg/sbom"
	"github.com/fahedouch/vens/pkg/vecindex"
	langemb "github.com/tmc/langchaingo/embeddings"
	"github.com/tmc/langchaingo/jsonschema"
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

type llmOutputEntry struct {
	Vuln     string   `json:"vuln"`
	Selected []string `json:"selected"`
}

type llmOutput struct {
	Results []llmOutputEntry `json:"results"`
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
// component IDs to ComponentContext, which holds SBOM metadata and BOMLink references.
type SBOMIndexBundle struct {
	sbomIndex vecindex.Index
	ctxByID   map[string]ComponentContext // ID -> Context
}

type ComponentContext struct {
	Metadata types.SBOMMetadata
	Ref      string
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
// It groups ratings by vulnerability ID for downstream VEX document generation.
func (g *Generator) GenerateRiskScore(ctx context.Context, bundle *SBOMIndexBundle, vulns []Vulnerability, h func([]outputhandler.VulnRating) error) error {
	batchSize := g.o.BatchSize // TODO: optimize automatically
	for i := 0; i < len(vulns); i += batchSize {
		batch := vulns[i:min(i+batchSize, len(vulns))]
		if err := g.generateRiskScore(ctx, bundle, batch, h); err != nil {
			return err
		}
	}
	return nil
}

func (g *Generator) generateRiskScore(ctx context.Context, bundle *SBOMIndexBundle, vulnBatch []Vulnerability, h func([]outputhandler.VulnRating) error) error {
	if bundle == nil || bundle.sbomIndex == nil {
		return errors.New("SBOM index not initialized; call IndexSBOMLibraries first")
	}

	group := make([]outputhandler.VulnRating, 0, len(vulnBatch))

	vulnTexts := make([]string, len(vulnBatch))
	for i, v := range vulnBatch {
		vulnTexts[i] = vulnLibraryText(v)
	}

	// 1) Retrieve top-k candidate SBOM libraries for each vuln.
	const topK = 5
	candidatesPerVuln, err := g.matchCandidatesForVulns(ctx, bundle.sbomIndex, vulnTexts, topK)
	if err != nil {
		return fmt.Errorf("match candidates for vulnerabilities: %w", err)
	}

	items := make([]VulnCandidates, 0, len(vulnBatch))
	for i, v := range vulnBatch {
		candidateIds := candidatesPerVuln[i]
		// Log the raw vector search candidates for each vulnerability
		// This shows which SBOM components were returned before LLM filtering.
		slog.InfoContext(ctx, "vuln_candidates",
			"vuln", v.VulnID,
			"pkgId", v.PkgID,
			"title", v.Title,
			"candidates", candidateIds,
		)
		if len(candidateIds) == 0 {
			continue
		}
		items = append(items, VulnCandidates{
			VulnID:      v.VulnID,
			VulnLibrary: computeVulnLibrary(v),
			Candidates:  candidateIds,
		})
	}

	// If nothing to filter, return early
	if len(items) == 0 {
		return nil
	}

	// 2) LLM call to determine impacted libraries for all items
	impactedLibraries, err := g.determineImpactedLibrariesForVulns(ctx, items)
	if err != nil {
		return fmt.Errorf("LLM filtreing failed: %w", err)
	}

	// 3) Build VulnRating group using selected library IDs and ParentPURLs
	for vulnID, filteredIDs := range impactedLibraries {
		if len(filteredIDs) == 0 {
			continue
		}
		for _, id := range filteredIDs {
			cCtx, ok := bundle.ctxByID[id]
			if !ok || cCtx.Metadata.ParentPURL == "" {
				continue
			}
			score, ok := g.o.Context.ScoreForPURL(riskconfig.NormalizePURL(cCtx.Metadata.ParentPURL))
			if !ok {
				continue
			}
			group = append(group, outputhandler.VulnRating{
				VulnID:      vulnID,
				AffectedRef: cCtx.Ref,
				Rating: cyclonedx.VulnerabilityRating{
					Method: cyclonedx.ScoringMethodOWASP,
					Score:  &score,
				},
			})
		}
	}

	if len(group) == 0 {
		return nil
	}
	if h != nil {
		return h(group)
	}
	return nil
}

// VulnCandidates describes one classification unit sent to the LLM in a single call.
type VulnCandidates struct {
	VulnID string `json:"vuln"`
	// vulnLibrary représente la meilleure clé d’association pour la vulnérabilité,
	// calculée en priorité par PkgID puis par PkgName.
	VulnLibrary string   `json:"vulnLibrary"`
	Candidates  []string `json:"candidates"`
}

// determineImpactedLibrariesForVulns performs a single LLM call to filter all items.
// It returns a map from VulnID to the subset of Candidates that are actually impacted.
func (g *Generator) determineImpactedLibrariesForVulns(ctx context.Context, items []VulnCandidates) (map[string][]string, error) {
	if g.o.LLM == nil {
		return nil, errors.New("no LLM configured")
	}

	var buf bytes.Buffer
	callOpts := []llms.CallOption{
		llms.WithJSONMode(),
		llms.WithStreamingFunc(func(ctx context.Context, chunk []byte) error {
			// Note: printed for debugging; do not parse from stdout.
			//fmt.Fprint(os.Stdout, string(chunk))
			buf.Write(chunk)
			return nil
		}),
	}

	if g.o.Temperature > 0.0 {
		slog.Debug("Using temperature", "temperature", g.o.Temperature)
		callOpts = append(callOpts, llms.WithTemperature(g.o.Temperature))
	}
	if g.o.Seed != 0 {
		slog.Debug("Using seed", "seed", g.o.Seed)
		callOpts = append(callOpts, llms.WithSeed(g.o.Seed))
	}

	// System prompt guiding the model to determine which libraries are at risk.
	systemPrompt := `You are an advanced language model and a cybersecurity expert specialized in Software Supply Chain analysis.
Your mission is to determine which software libraries (represented by PURLs) from a given list are at risk based on a vulnerable library name.

Follow these guidelines when classifying software library PURLs:

1. **Identify Specificity**: Select the most relevant and specific library PURL(s) directly associated with the "vulnLibrary".
2. **Avoid Over-Inclusion**: Do not include unrelated or broader library PURLs that do not directly match the "vulnLibrary".
3. **Prioritize Primary Libraries**: If "vulnLibrary" refers to a well-known software or tool, prioritize the primary library PURL(s) associated with it.
4. **Handle Ambiguity**: If the input is ambiguous or does not clearly refer to a specific library, return ["No Library"].
5. **No Library Found**: If no relevant library PURL is found in the "candidates" list, return ["No Library"].

### Golden Rule:
Do not guess. If you have reasonable doubt about the match between "vulnLibrary" and a candidate, do not select it.
`

	schema := &jsonschema.Definition{
		Type: jsonschema.Object,
		Properties: map[string]jsonschema.Definition{
			"results": {
				Type: jsonschema.Array,
				Items: &jsonschema.Definition{
					Type: jsonschema.Object,
					Properties: map[string]jsonschema.Definition{
						"vuln": {
							Type:        jsonschema.String,
							Description: "Vulnerability ID",
						},
						"selected": {
							Type: jsonschema.Array,
							Items: &jsonschema.Definition{
								Type: jsonschema.String,
							},
							Description: "List of selected library PURL or ['No Library']",
						},
					},
					Required: []string{"vuln", "selected"},
				},
			},
		},
		Required: []string{"results"},
	}
	schemaJ, err := schema.MarshalJSON()
	if err != nil {
		return nil, err
	}

	llmInputExample := `items: [
  {"vuln":"CVE-2023-1234","vulnLibrary":"GStreamer","candidates":["pkg:deb/debian/gstreamer1.0-plugins-base@1.20.3-2","pkg:deb/debian/gstreamer1.0-clutter-3.0@1.20.3-2","pkg:deb/debian/gstreamer1.0-gl@1.20.3-2","pkg:deb/debian/gstreamer1.0-pulseaudio@1.20.3-2","pkg:deb/debian/gstreamer1.0-x@1.20.3-2","pkg:deb/debian/gstreamer1.0-libav@1.20.3-2","pkg:deb/debian/gstreamer1.0-plugins-good@1.20.3-2"]},
  {"vuln":"CVE-2024-5678","vulnLibrary":"radeon_rx_6700","candidates":["pkg:deb/debian/libdrm-radeon1@2.4.112-3", "pkg:deb/debian/xserver-xorg-video-radeon@1:19.1.0-2"]}
]`

	llmOutputExample := `{"results":[
  {"vuln":"CVE-2023-1234","selected":["pkg:deb/debian/gstreamer1.0-plugins-base@1.20.3-2","pkg:deb/debian/gstreamer1.0-clutter-3.0@1.20.3-2","pkg:deb/debian/gstreamer1.0-gl@1.20.3-2","pkg:deb/debian/gstreamer1.0-pulseaudio@1.20.3-2","pkg:deb/debian/gstreamer1.0-x@1.20.3-2","pkg:deb/debian/gstreamer1.0-libav@1.20.3-2","pkg:deb/debian/gstreamer1.0-plugins-good@1.20.3-2"]},
  {"vuln":"CVE-2024-5678","selected":["No Library"]}
]}`

	systemPrompt += "#### Input Example\n"
	systemPrompt += "```json\n" + llmInputExample + "\n```\n"
	systemPrompt += "#### Output format: JSON Schema\n"
	systemPrompt += string(schemaJ) + "\n"
	systemPrompt += "#### Output Example\n"
	systemPrompt += "```json\n" + llmOutputExample + "\n```\n"

	// Marshal items to JSON for a deterministic and valid payload to the LLM
	itemsJSON, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal items: %w", err)
	}
	humanPrompt := fmt.Sprintf("items: %s", string(itemsJSON))

	// Only ollama and openai supports WithJSONSchema
	// https://github.com/tmc/langchaingo/pull/1302
	callOpts = append(callOpts, llms.WithJSONSchema(schema))

	msgs := []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeSystem, systemPrompt),
		llms.TextParts(llms.ChatMessageTypeHuman, humanPrompt),
	}

	if err := llm.RetryOnRateLimit(ctx, g.o.SleepOnRateLimit, g.o.RetryOnRateLimit, func(c context.Context) error {
		buf.Reset()
		_, err := g.o.LLM.GenerateContent(c, msgs, callOpts...)
		return err
	}); err != nil {
		return nil, err
	}

	var resp llmOutput
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("unable to parse LLM output: %w: %q", err, buf.String())
	}

	impactedLibrariesPerVuln := make(map[string][]string)
	for _, r := range resp.Results {
		vulnID := strings.TrimSpace(r.Vuln)
		if vulnID == "" {
			continue
		}
		cleaned := make([]string, 0, len(r.Selected))
		for _, s := range r.Selected {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			cleaned = append(cleaned, s)
		}
		// Log final matching results selected by the LLM for each vulnerability
		slog.InfoContext(ctx, "vuln_match_selected",
			"vuln", vulnID,
			"selected", cleaned,
		)
		impactedLibrariesPerVuln[vulnID] = append(impactedLibrariesPerVuln[vulnID], cleaned...)
	}
	return impactedLibrariesPerVuln, nil
}

// matchCandidatesForVulns embeds vulnerability texts and searches the index for top-k matches per text.
func (g *Generator) matchCandidatesForVulns(ctx context.Context, idx vecindex.Index, vulnTexts []string, k int) ([][]string, error) {
	if g.o.LLM == nil {
		return nil, errors.New("no LLM configured for embeddings")
	}
	if k <= 0 {
		k = 1
	}

	emb, err := g.newEmbedder()
	if err != nil {
		return nil, err
	}

	var vecs [][]float32
	if err := llm.RetryOnRateLimit(ctx, g.o.SleepOnRateLimit, g.o.RetryOnRateLimit, func(c context.Context) error {
		var e error
		vecs, e = emb.EmbedDocuments(c, vulnTexts)
		return e
	}); err != nil {
		return nil, err
	}
	if len(vecs) != len(vulnTexts) {
		return nil, fmt.Errorf("embedding count mismatch: got %d, want %d", len(vecs), len(vulnTexts))
	}

	matchedCandidates := make([][]string, len(vulnTexts))
	for i, vec := range vecs {
		ids, err := idx.Search(vec, k)
		if err != nil {
			return nil, err
		}
		matchedCandidates[i] = ids
	}
	return matchedCandidates, nil
}

// IndexSBOMLibraries streams CycloneDX SBOMs and builds an in-memory vector index
// of their components. Embeddings are generated via the configured LLM, in batches,
// with rate-limit retry. Returns the populated index bundle.
func (g *Generator) IndexSBOMLibraries(ctx context.Context, sbomPaths []string) (*SBOMIndexBundle, error) {
	idx := vecindex.NewSBOMVecIndex()
	ctxByID := make(map[string]ComponentContext)

	type embBatch struct {
		comps []types.SBOMComponent
		ids   []string
	}

	batches := make(chan embBatch, 2)
	errCh := make(chan error, 1)
	done := make(chan struct{})

	// Worker: consumes batches, computes embeddings and indexes
	go func() {
		defer close(done)
		for b := range batches {
			vecs, err := g.componentEmbeddings(ctx, b.comps)
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

		curComps := make([]types.SBOMComponent, 0, g.o.BatchSize)
		curIDs := make([]string, 0, g.o.BatchSize)

		flushSend := func() error {
			if len(curComps) == 0 {
				return nil
			}
			// copier/swapper pour libérer le producteur immédiatement
			comps := make([]types.SBOMComponent, len(curComps))
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

		if err := sbom.StreamCycloneDXLibraries(p, func(c types.SBOMComponent) error {
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

			// Construct BOMLink if possible: urn:cdx:serialNumber/version#bom-ref
			// See: https://cyclonedx.org/capabilities/bomlink/
			ref := c.BomRef
			if ref == "" {
				ref = id // fallback to id if bom-ref is missing
			}
			if c.Metadata.SerialNumber != "" {
				ref = fmt.Sprintf("urn:cdx:%s/%d#%s", c.Metadata.SerialNumber, c.Metadata.Version, ref)
			}

			// store component context now; last seen wins which is fine
			ctxByID[id] = ComponentContext{
				Metadata: c.Metadata,
				Ref:      ref,
			}

			if len(curComps) >= g.o.BatchSize {
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

	return &SBOMIndexBundle{
		sbomIndex: idx,
		ctxByID:   ctxByID,
	}, nil
}

// componentEmbeddings generates embeddings for a batch of components using the LLM.
// It retries on rate limit using llm.RetryOnRateLimit and the configured batch size.
// Returns an error if the LLM call fails or the output cannot be parsed (no fallback).
func (g *Generator) componentEmbeddings(ctx context.Context, comps []types.SBOMComponent) ([][]float32, error) {
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
func componentText(c types.SBOMComponent) string {
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

// computeVulnLibrary calcule la clé vulnLibrary en priorité sur PkgID puis PkgName.
func computeVulnLibrary(v Vulnerability) string {
	if s := strings.TrimSpace(v.PkgID); s != "" {
		return s
	}
	return strings.TrimSpace(v.PkgName)
}
