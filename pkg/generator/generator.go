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

// Package generator provides LLM-based OWASP risk scoring for vulnerabilities.
// The approach is inspired by github.com/AkihiroSuda/vexllm for LLM prompt structure.
package generator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/owasp"
	"github.com/venslabs/vens/pkg/riskconfig"
	"github.com/venslabs/vens/pkg/vuln"
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
}

// LLMVulnerability contains only the fields needed for LLM analysis.
// This is sent to the LLM to minimize token usage.
type LLMVulnerability struct {
	VulnID           string `json:"vulnId"`
	PkgID            string `json:"pkgId"`
	PkgName          string `json:"pkgName"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	FixedVersion     string `json:"fixedVersion,omitempty"`
	Title            string `json:"title"`
	Description      string `json:"description,omitempty"`
	Severity         string `json:"severity,omitempty"` // NVD/vendor severity as context
}

// llmOutputEntry represents the LLM response for a single vulnerability.
// The LLM rates each of the 16 OWASP factors on that factor's own levels, and
// the vector, severity and score are calculated in Go by owasp.Vector.Rate.
type llmOutputEntry struct {
	VulnID string `json:"vulnId"`
	// Levels is read at parse time from the 16 factor keys, each checked
	// against its factor's levels; an entry failing that check is dropped.
	Levels    owasp.Vector `json:"-"`
	Reasoning string       `json:"reasoning"` // Brief explanation of the scoring
}

// factor is one OWASP factor as the prompt and the schema ask it: its
// vector key, its line in OWASP's Risk Rating Methodology (name, question,
// options) and its distinct levels, those of pkg/owasp's levels.go.
type factor struct {
	key      string
	name     string
	question string
	options  string
	levels   []int
}

// factors lists the 16 factors in the vector's order, four per group: threat
// agent, vulnerability, technical impact, business impact.
var factors = []factor{
	{"SL", "Skill Level", "How technically skilled is this group of threat agents?",
		"No technical skills (1), some technical skills (3), advanced computer user (5), network and programming skills (6), security penetration skills (9)",
		[]int{1, 3, 5, 6, 9}},
	{"M", "Motive", "How motivated is this group of threat agents to find and exploit this vulnerability?",
		"Low or no reward (1), possible reward (4), high reward (9)",
		[]int{1, 4, 9}},
	{"O", "Opportunity", "What resources and opportunities are required for this group of threat agents to find and exploit this vulnerability?",
		"Full access or expensive resources required (0), special access or resources required (4), some access or resources required (7), no access or resources required (9)",
		[]int{0, 4, 7, 9}},
	{"S", "Size", "How large is this group of threat agents?",
		"Developers (2), system administrators (2), intranet users (4), partners (5), authenticated users (6), anonymous Internet users (9)",
		[]int{2, 4, 5, 6, 9}},
	{"ED", "Ease of Discovery", "How easy is it for this group of threat agents to discover this vulnerability?",
		"Practically impossible (1), difficult (3), easy (7), automated tools available (9)",
		[]int{1, 3, 7, 9}},
	{"EE", "Ease of Exploit", "How easy is it for this group of threat agents to actually exploit this vulnerability?",
		"Theoretical (1), difficult (3), easy (5), automated tools available (9)",
		[]int{1, 3, 5, 9}},
	{"A", "Awareness", "How well known is this vulnerability to this group of threat agents?",
		"Unknown (1), hidden (4), obvious (6), public knowledge (9)",
		[]int{1, 4, 6, 9}},
	{"ID", "Intrusion Detection", "How likely is an exploit to be detected?",
		"Active detection in application (1), logged and reviewed (3), logged without review (8), not logged (9)",
		[]int{1, 3, 8, 9}},
	{"LC", "Loss of Confidentiality", "How much data could be disclosed and how sensitive is it?",
		"Minimal non-sensitive data disclosed (2), minimal critical data disclosed (6), extensive non-sensitive data disclosed (6), extensive critical data disclosed (7), all data disclosed (9)",
		[]int{2, 6, 7, 9}},
	{"LI", "Loss of Integrity", "How much data could be corrupted and how damaged is it?",
		"Minimal slightly corrupt data (1), minimal seriously corrupt data (3), extensive slightly corrupt data (5), extensive seriously corrupt data (7), all data totally corrupt (9)",
		[]int{1, 3, 5, 7, 9}},
	{"LAV", "Loss of Availability", "How much service could be lost and how vital is it?",
		"Minimal secondary services interrupted (1), minimal primary services interrupted (5), extensive secondary services interrupted (5), extensive primary services interrupted (7), all services completely lost (9)",
		[]int{1, 5, 7, 9}},
	{"LAC", "Loss of Accountability", "Are the threat agents' actions traceable to an individual?",
		"Fully traceable (1), possibly traceable (7), completely anonymous (9)",
		[]int{1, 7, 9}},
	{"FD", "Financial damage", "How much financial damage will result from an exploit?",
		"Less than the cost to fix the vulnerability (1), minor effect on annual profit (3), significant effect on annual profit (7), bankruptcy (9)",
		[]int{1, 3, 7, 9}},
	{"RD", "Reputation damage", "Would an exploit result in reputation damage that would harm the business?",
		"Minimal damage (1), Loss of major accounts (4), loss of goodwill (5), brand damage (9)",
		[]int{1, 4, 5, 9}},
	{"NC", "Non-compliance", "How much exposure does non-compliance introduce?",
		"Minor violation (2), clear violation (5), high profile violation (7)",
		[]int{2, 5, 7}},
	{"PV", "Privacy violation", "How much personally identifiable information could be disclosed?",
		"One individual (3), hundreds of people (5), thousands of people (7), millions of people (9)",
		[]int{3, 5, 7, 9}},
}

// llmOutput wraps the array of results from LLM.
type llmOutput struct {
	Results []llmOutputEntry `json:"results"`
}

// Opts configures the Generator.
type Opts struct {
	LLM llm.Client
	// Temperature is the sampling temperature forwarded to the provider, nil
	// when the user did not pass --llm-temperature.
	Temperature *float64
	BatchSize   int // Avoid high values to avoid rate limit
	Seed        int

	SleepOnRateLimit time.Duration
	RetryOnRateLimit int
	// DebugDir gets one run-* directory per Generator, holding the prompts
	// and the raw response of every LLM call.
	DebugDir string

	// Config carries user-provided context hints loaded from config.yaml.
	Config *riskconfig.Config
}

// Generator produces OWASP risk scores using LLM analysis.
type Generator struct {
	o        Opts
	attestor *attestation.Builder
	// debugRunDir is this run's own directory under Opts.DebugDir, empty
	// when debug files are off.
	debugRunDir string
	// debugBatches numbers the LLM calls written to debugRunDir. A split
	// batch and an ask-again are calls of their own (#359).
	debugBatches int
}

// New creates a new Generator with the given options.
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
		g.debugRunDir = newDebugRunDir(g.o.DebugDir)
	}
	return g, nil
}

// newDebugRunDir creates this run's directory under parent, private to the
// user: runs sharing a --debug-dir, even in parallel, never overwrite each
// other's files. It returns "" when it can't, which turns debug files off.
func newDebugRunDir(parent string) string {
	if err := os.MkdirAll(parent, 0755); err != nil {
		slog.Error("failed to create the debug dir", "dir", parent, "error", err)
		return ""
	}
	dir, err := os.MkdirTemp(parent, "run-*")
	if err != nil {
		slog.Error("failed to create the debug dir", "dir", parent, "error", err)
		return ""
	}
	slog.Info("Writing debug files", "dir", dir)
	return dir
}

// writeDebugFile writes one file of the run's debug directory, readable by the
// user only since it holds the deployment context and the CVE inventory. A
// failure is logged and the run goes on.
func (g *Generator) writeDebugFile(ctx context.Context, name, content string) {
	path := filepath.Join(g.debugRunDir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		slog.ErrorContext(ctx, "failed to write a debug file", "file", path, "error", err)
	}
}

// SetAttestor attaches an attestation Builder after construction. Pass nil to disable.
func (g *Generator) SetAttestor(b *attestation.Builder) { g.attestor = b }

// scoringRun is the state shared by the batches of one GenerateRiskScore call.
type scoringRun struct {
	scored  map[string]bool            // CVEs a finished batch emitted
	scores  map[string]answer          // first answer per CVE, reused by later batches
	missing map[string]bool            // unanswered CVEs a later row can still score
	pending map[string][]Vulnerability // rows held back until their CVE is scored
	lastRow map[string]int             // index of each CVE's last row in the run

	// Counters for the end-of-run summary: evaluateOWASPScores invocations,
	// asks-again for CVEs the model skipped, and truncated-batch splits.
	llmCalls   int
	askedAgain int
	splits     int
}

// GenerateRiskScore generates contextual OWASP risk scores for the given vulnerabilities.
// It uses the LLM to calculate the OWASP risk score for each vulnerability based on
// the project context hints provided in config.yaml.
func (g *Generator) GenerateRiskScore(ctx context.Context, vulns []Vulnerability, h func([]outputhandler.VulnRating) error) (err error) {
	run := &scoringRun{
		scored:  make(map[string]bool),
		scores:  make(map[string]answer),
		missing: make(map[string]bool),
		pending: make(map[string][]Vulnerability),
		lastRow: make(map[string]int, len(vulns)),
	}
	for i, v := range vulns {
		// A row without an ID is never asked about, and is not a CVE.
		if v.VulnID != "" {
			run.lastRow[v.VulnID] = i
		}
	}
	// Logged on a failed run too, the one usually debugged. Counts are
	// distinct CVEs, not rows; llm_calls counts every evaluateOWASPScores
	// invocation (rate-limit retries happen inside it), asked_again the
	// asks-again for skipped CVEs, splits the truncated-batch splits.
	defer func() {
		slog.InfoContext(ctx, "Scoring run finished",
			"rows", len(vulns),
			"cves", len(run.lastRow),
			"llm_calls", run.llmCalls,
			"asked_again", run.askedAgain,
			"splits", run.splits,
			"failed", err != nil,
		)
	}()
	if err := g.scoreInBatches(ctx, vulns, 0, g.o.BatchSize, run, h); err != nil {
		return err
	}
	return run.checkUnassessed()
}

// checkUnassessed is a safety net: scoreAll already stops the run when an
// unanswered CVE has no later row. Counts are distinct CVEs, not rows.
func (run *scoringRun) checkUnassessed() error {
	if len(run.missing) == 0 {
		return nil
	}
	return fmt.Errorf("model returned no score for %d of %d vulnerabilities, after asking again: %s",
		len(run.missing), len(run.scored)+len(run.missing), strings.Join(sortedKeys(run.missing), ", "))
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// scoreInBatches scores vulns batchSize at a time; offset is the run index of
// vulns[0]. A batch the provider truncates (llm.ErrTruncated) is split in half
// and retried, down to a single CVE; only a lone CVE that still truncates fails
// the run.
func (g *Generator) scoreInBatches(ctx context.Context, vulns []Vulnerability, offset, batchSize int, run *scoringRun, h func([]outputhandler.VulnRating) error) error {
	if batchSize < 1 {
		batchSize = 1
	}
	for i := 0; i < len(vulns); i += batchSize {
		batch := vulns[i:min(i+batchSize, len(vulns))]
		slog.DebugContext(ctx, "scoring batch",
			"rows", len(batch),
			"vulns", strings.Join(rowIDs(batch), ","),
		)
		err := g.generateRiskScore(ctx, batch, offset+i+len(batch), run, h)
		if err == nil {
			continue
		}
		if errors.Is(err, llm.ErrTruncated) && len(batch) > 1 {
			half := (len(batch) + 1) / 2
			run.splits++
			slog.WarnContext(ctx, "LLM truncated the batch; retrying with smaller batches",
				"from", len(batch), "to", half)
			// The WARN above doesn't show which rows each half keeps, which
			// is what you reach for when a split behaves oddly.
			slog.DebugContext(ctx, "splitting truncated batch",
				"first_half", strings.Join(rowIDs(batch[:half]), ","),
				"second_half", strings.Join(rowIDs(batch[half:]), ","),
			)
			if err := g.scoreInBatches(ctx, batch, offset+i, half, run, h); err != nil {
				return err
			}
			continue
		}
		return err
	}
	return nil
}

// rowIDs lists the VulnID of every row in scanner order, once per row.
func rowIDs(vs []Vulnerability) []string {
	ids := make([]string, len(vs))
	for i, v := range vs {
		ids[i] = v.VulnID
	}
	return ids
}

// generateRiskScore scores one batch; end is the run index just past it.
func (g *Generator) generateRiskScore(ctx context.Context, vulnBatch []Vulnerability, end int, run *scoringRun, h func([]outputhandler.VulnRating) error) error {
	if g.o.Config == nil {
		return errors.New("config not initialized; load config.yaml first")
	}

	// A CVE can affect several components in one batch, so group every component
	// under its VulnID. Keying by VulnID alone would keep only the last one.
	vulnsByID := make(map[string][]Vulnerability, len(vulnBatch))
	llmBatch := make([]LLMVulnerability, len(vulnBatch))
	for i, v := range vulnBatch {
		vulnsByID[v.VulnID] = append(vulnsByID[v.VulnID], v)
		llmBatch[i] = LLMVulnerability{
			VulnID:           v.VulnID,
			PkgID:            v.PkgID,
			PkgName:          v.PkgName,
			InstalledVersion: v.InstalledVersion,
			FixedVersion:     v.FixedVersion,
			Title:            v.Title,
			Description:      v.Description,
			Severity:         v.Severity,
		}
	}

	answers, err := g.scoreAll(ctx, llmBatch, end, run)
	if err != nil {
		return err
	}
	for _, a := range answers {
		run.scored[a.entry.VulnID] = true
	}

	group := make([]outputhandler.VulnRating, 0, len(vulnBatch))
	for _, answer := range answers {
		entry, evidenceRef := answer.entry, answer.evidenceRef

		// The 16 levels passed their factors' levels at parse time, so Rate
		// cannot refuse them; its score is likelihood x max(technical,
		// business) from the exact averages, neither rounded nor clamped.
		rating, err := entry.Levels.Rate()
		if err != nil {
			return fmt.Errorf("vulnerability %s: %w", entry.VulnID, err)
		}
		score := rating.Score
		severity := rating.Severity
		vectorString := rating.Vector

		comps := vulnsByID[entry.VulnID]
		if pend, ok := run.pending[entry.VulnID]; ok {
			// This CVE finally got a score: fill in the rows earlier batches
			// held back when they couldn't score it, instead of dropping them
			// from the VEX. Theirs come first, to keep scanner order.
			merged := make([]Vulnerability, 0, len(pend)+len(comps))
			merged = append(merged, pend...)
			merged = append(merged, comps...)
			comps = merged
			delete(run.pending, entry.VulnID)
		}

		for _, v := range comps {
			slog.InfoContext(ctx, "Scored vulnerability",
				"vuln", entry.VulnID,
				"pkg", v.BOMRef,
				"score", fmt.Sprintf("%.1f", score),
				"severity", severity,
				"vector", vectorString,
			)

			var source *cyclonedx.Source
			if v.SourceName != "" {
				source = &cyclonedx.Source{
					Name: v.SourceName,
					URL:  v.SourceURL,
				}
			} else {
				source = vuln.Source(entry.VulnID)
			}

			s := score
			group = append(group, outputhandler.VulnRating{
				VulnID: entry.VulnID,
				BOMRef: v.BOMRef,
				Rating: cyclonedx.VulnerabilityRating{
					Method:   cyclonedx.ScoringMethodOWASP,
					Score:    &s,
					Severity: cyclonedx.Severity(severity),
					Vector:   vectorString,
				},
				Source: source,
			})

			if g.attestor != nil {
				g.attestor.AddClaim(evidenceRef, attestation.ClaimInput{
					VulnID:      entry.VulnID,
					CompRef:     v.BOMRef,
					CompName:    v.PkgName,
					CompVersion: v.InstalledVersion,
					PURL:        v.BOMRef,
					Score:       score,
					Severity:    severity,
					Reasoning:   entry.Reasoning,
					// Mark the claim when its row was not in the cited
					// call's prompt: a reused first score for another
					// batch's package, or a held-back row filled in by a
					// later batch.
					Reused: !answer.prompted[promptRow{v.PkgName, v.InstalledVersion}],
				})
			}
		}
	}

	// CVEs this batch asked about but never got an answer for keep no rows
	// yet: hold their components back as pending so a later batch that scores
	// the CVE fills their rows in, instead of dropping them from the VEX.
	answered := make(map[string]bool, len(answers))
	for _, a := range answers {
		answered[a.entry.VulnID] = true
	}
	heldBack := make(map[string]bool)
	for _, v := range llmBatch {
		if v.VulnID == "" || answered[v.VulnID] || heldBack[v.VulnID] {
			continue
		}
		heldBack[v.VulnID] = true
		run.pending[v.VulnID] = append(run.pending[v.VulnID], vulnsByID[v.VulnID]...)
	}

	if len(group) == 0 {
		return nil
	}
	if h != nil {
		return h(group)
	}
	return nil
}

// answer pairs a model entry with the evidence bundle of the call it came from.
// A retry is a second call, so the entries it recovers cite a different bundle.
// prompted is the set of (package, version) rows the call behind this answer
// was asked about; a claim whose row is not in it must say so, because its
// cited evidence bundle's prompt never mentioned that package.
type answer struct {
	entry       llmOutputEntry
	evidenceRef string
	prompted    map[promptRow]bool
}

// promptRow identifies one package row a prompt was asked about.
type promptRow struct {
	name    string
	version string
}

// scoreAll scores every vulnerability in the batch. A model can leave some out of
// its answer without saying so; those are asked for again on their own. A CVE
// still unanswered stops the run unless it has a row at or after end, since no
// other batch could score it. CVEs an earlier batch already scored are left
// out of the prompt and their first score is reused, so every component keeps
// its row in the VEX.
func (g *Generator) scoreAll(ctx context.Context, batch []LLMVulnerability, end int, run *scoringRun) ([]answer, error) {
	answers := make([]answer, 0, len(batch))
	scored := make(map[string]bool, len(batch))

	// Leave out every CVE an earlier batch already scored: asking the model
	// about it again would only have its answer dropped.
	var toAsk []LLMVulnerability
	for _, v := range batch {
		if v.VulnID == "" {
			continue
		}
		if _, ok := run.scores[v.VulnID]; ok {
			continue
		}
		toAsk = append(toAsk, v)
	}

	collect := func(entries []llmOutputEntry, asked []LLMVulnerability, evidenceRef string) {
		askedIDs := make(map[string]bool, len(asked))
		prompted := make(map[promptRow]bool, len(asked))
		for _, v := range asked {
			if v.VulnID != "" {
				askedIDs[v.VulnID] = true
			}
			prompted[promptRow{v.PkgName, v.InstalledVersion}] = true
		}
		for _, e := range entries {
			// Only keep answers for CVEs that were in this call's prompt. An
			// entry for a CVE we didn't ask about is noise the model made up
			// or leaked from another batch's context; keeping it would let
			// later batches reuse it instead of asking, as happened when a
			// critical CVE came out as info from a stale answer.
			if e.VulnID == "" || !askedIDs[e.VulnID] || scored[e.VulnID] {
				if e.VulnID != "" && !askedIDs[e.VulnID] {
					slog.DebugContext(ctx, "ignoring answer for a CVE that wasn't asked about in this call",
						"vuln", e.VulnID)
				}
				continue
			}
			scored[e.VulnID] = true
			delete(run.missing, e.VulnID)
			a := answer{entry: e, evidenceRef: evidenceRef, prompted: prompted}
			run.scores[e.VulnID] = a
			answers = append(answers, a)
		}
	}

	// reuseFirstScores appends the first score of every batch CVE an earlier
	// batch already scored, so this batch's components keep their rows in the
	// VEX even though the CVE was left out of the prompt.
	reuseFirstScores := func() {
		seen := make(map[string]bool, len(answers))
		for _, a := range answers {
			seen[a.entry.VulnID] = true
		}
		for _, v := range batch {
			if v.VulnID == "" || seen[v.VulnID] {
				continue
			}
			if first, ok := run.scores[v.VulnID]; ok {
				// Pulled from an earlier batch's score, not obtained in this
				// call. Whether the claim for this batch's row says the cited
				// prompt skipped its package is decided per row from the
				// answer's prompted set, in generateRiskScore.
				slog.DebugContext(ctx, "reusing an earlier batch's first score",
					"vuln", v.VulnID,
					"evidence_ref", first.evidenceRef,
				)
				answers = append(answers, first)
				seen[v.VulnID] = true
			}
		}
	}

	if len(toAsk) > 0 {
		run.llmCalls++
		entries, evidenceRef, err := g.evaluateOWASPScores(ctx, toAsk)
		if err != nil {
			return nil, fmt.Errorf("LLM evaluation failed: %w", err)
		}
		collect(entries, toAsk, evidenceRef)

		if skipped := unscored(toAsk, scored); len(skipped) > 0 {
			// Counts go by distinct CVE: one hitting several components is several rows.
			slog.WarnContext(ctx, "Model skipped vulnerabilities; asking again for those alone",
				"skipped", len(skipped), "of", len(unscored(toAsk, nil)), "vulns", strings.Join(vulnIDs(skipped), ","))

			run.askedAgain++
			run.llmCalls++
			entries, evidenceRef, err = g.evaluateOWASPScores(ctx, skipped)
			if err != nil {
				return nil, fmt.Errorf("LLM evaluation failed while asking again for %d vulnerabilities: %w", len(skipped), err)
			}
			collect(entries, skipped, evidenceRef)

			// Still unanswered: a later row of the same CVE can still score
			// it (its rows wait in pending). Without one, stop now rather than
			// pay for the remaining batches.
			var uncovered []string
			for _, v := range unscored(toAsk, scored) {
				if run.lastRow[v.VulnID] >= end {
					run.missing[v.VulnID] = true
					slog.DebugContext(ctx, "holding back rows until a later batch scores the CVE",
						"vuln", v.VulnID,
					)
					continue
				}
				uncovered = append(uncovered, v.VulnID)
			}
			if len(uncovered) > 0 {
				sort.Strings(uncovered)
				return nil, fmt.Errorf("model returned no score for %s after asking again; stopping the run",
					strings.Join(uncovered, ", "))
			}
		}
	}
	reuseFirstScores()
	return answers, nil
}

func vulnIDs(vs []LLMVulnerability) []string {
	ids := make([]string, len(vs))
	for i, v := range vs {
		ids[i] = v.VulnID
	}
	return ids
}

// unscored lists the vulnerabilities the model has not answered for, once each.
// A nil scored map lists them all.
func unscored(batch []LLMVulnerability, scored map[string]bool) []LLMVulnerability {
	var out []LLMVulnerability
	seen := make(map[string]bool, len(batch))
	for _, v := range batch {
		if v.VulnID == "" || scored[v.VulnID] || seen[v.VulnID] {
			continue
		}
		seen[v.VulnID] = true
		out = append(out, v)
	}
	return out
}

// evaluateOWASPScores calls the LLM to calculate the OWASP risk score for each vulnerability.
// The LLM uses the project context hints to determine the appropriate score.
func (g *Generator) evaluateOWASPScores(ctx context.Context, vulns []LLMVulnerability) ([]llmOutputEntry, string, error) {
	if g.o.LLM == nil {
		return nil, "", errors.New("no LLM configured")
	}

	systemPrompt := g.buildSystemPrompt()

	// Build the JSON schema for structured output and embed it in the prompt so
	// the contract is self-documented even for weaker models.
	schema := g.buildOutputSchema()
	systemPrompt += "#### Output format: JSON Schema\n"
	systemPrompt += string(schema) + "\n"

	vulnsJSON, err := json.Marshal(vulns)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal vulnerabilities: %w", err)
	}
	humanPrompt := string(vulnsJSON)

	// One numbered file set per LLM call: fixed names would let every call
	// overwrite the previous one, hiding what the model was asked (#359).
	var debugName string
	if g.debugRunDir != "" {
		g.debugBatches++
		debugName = fmt.Sprintf("batch-%05d", g.debugBatches)
		g.writeDebugFile(ctx, debugName+".system.prompt", systemPrompt)
		g.writeDebugFile(ctx, debugName+".human.prompt", humanPrompt)
	}

	req := llm.Request{
		System:      systemPrompt,
		Human:       humanPrompt,
		Schema:      schema,
		Temperature: g.o.Temperature,
		Seed:        g.o.Seed,
	}

	var raw string
	if err := llm.RetryOnRateLimit(ctx, g.o.SleepOnRateLimit, g.o.RetryOnRateLimit, func(c context.Context) error {
		var e error
		raw, e = g.o.LLM.Generate(c, req)
		return e
	}); err != nil {
		return nil, "", err
	}

	// Written before parsing, so a reply that fails to parse is on disk too. A
	// failed call, such as a truncated one, has no reply: its prompts stay alone.
	if debugName != "" {
		g.writeDebugFile(ctx, debugName+".response", raw)
	}

	var evidenceRef string
	if g.attestor != nil {
		evidenceRef = g.attestor.AddBatch(systemPrompt, humanPrompt, []byte(raw))
	}

	entries, err := parseReply(ctx, raw)
	if err != nil {
		return nil, "", err
	}
	return entries, evidenceRef, nil
}

// parseReply reads the model's reply. Nothing is rounded, clamped or snapped:
// an entry whose factor is missing, null, not an integer or off its factor's
// levels is dropped and logged at WARN, which leaves its CVE unanswered, so it
// is asked again like any CVE the model skipped.
func parseReply(ctx context.Context, raw string) ([]llmOutputEntry, error) {
	var resp llmOutput
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return nil, fmt.Errorf("unable to parse LLM output: %w: %q", err, raw)
	}
	// The same text again, each result kept raw for its factor keys; it
	// decoded above, so it decodes here into as many results.
	var items struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal([]byte(raw), &items); err != nil || len(items.Results) != len(resp.Results) {
		return nil, fmt.Errorf("unable to parse LLM output: results read twice disagree: %q", raw)
	}

	// The first entry for a CVE decides, as on main: once it is dropped, a later
	// entry for the same CVE in this reply is skipped too, so the CVE is asked
	// again.
	seen := make(map[string]bool, len(resp.Results))
	droppedFirst := make(map[string]bool)
	entries := make([]llmOutputEntry, 0, len(resp.Results))
	for i, entry := range resp.Results {
		if droppedFirst[entry.VulnID] {
			continue
		}
		first := !seen[entry.VulnID]
		seen[entry.VulnID] = true
		levels, invalid := readLevels(items.Results[i])
		if len(invalid) > 0 {
			slog.WarnContext(ctx, "Dropping an answer whose factor levels are invalid; its CVE stays unanswered",
				"vuln", entry.VulnID,
				"field", invalid.keys(),
				"why", invalid.String(),
			)
			if first {
				droppedFirst[entry.VulnID] = true
			}
			continue
		}
		entry.Levels = vectorOf(levels)

		slog.DebugContext(ctx, "owasp_levels",
			"vuln", entry.VulnID,
			"levels", levelsString(levels),
			"reasoning", entry.Reasoning,
		)
		entries = append(entries, entry)
	}
	return entries, nil
}

// invalidLevel is one factor of an entry that fails its check, and why.
type invalidLevel struct {
	key string
	why string
}

type invalidLevels []invalidLevel

func (l invalidLevels) keys() string {
	keys := make([]string, len(l))
	for i, f := range l {
		keys[i] = f.key
	}
	return strings.Join(keys, ",")
}

func (l invalidLevels) String() string {
	parts := make([]string, len(l))
	for i, f := range l {
		parts[i] = f.key + ": " + f.why
	}
	return strings.Join(parts, "; ")
}

// readLevels reads the 16 factor levels of one result, in factors' order. item
// has already decoded into an llmOutputEntry, so it is an object or null.
func readLevels(item json.RawMessage) ([]int, invalidLevels) {
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(item, &fields)

	levels := make([]int, len(factors))
	var invalid invalidLevels
	for i, f := range factors {
		raw, ok := fields[f.key]
		if !ok {
			invalid = append(invalid, invalidLevel{f.key, "missing"})
			continue
		}
		raw = bytes.TrimSpace(raw)
		if string(raw) == "null" {
			invalid = append(invalid, invalidLevel{f.key, "null"})
			continue
		}
		n, whole := exactLevel(raw)
		if !whole {
			invalid = append(invalid, invalidLevel{f.key, "not an integer: " + string(raw)})
			continue
		}
		if !slices.Contains(f.levels, n) {
			invalid = append(invalid, invalidLevel{f.key, fmt.Sprintf("%s is off its levels %v", raw, f.levels)})
			continue
		}
		levels[i] = n
	}
	return levels, invalid
}

// jsonNumber is the grammar of a JSON number: sign, integer part, fraction
// and exponent.
var jsonNumber = regexp.MustCompile(`^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$`)

// exactLevel reads raw as the exact value of a JSON number, never through a
// float: 5, 5.0, 5e0 and 50e-1 all read 5, while 5.5 and 4.9999999999999999
// are not whole numbers. whole is false for a value that is not a number or
// not a whole number; a whole number outside 0 to 9 reads -1, on no factor's
// levels.
func exactLevel(raw []byte) (level int, whole bool) {
	m := jsonNumber.FindSubmatch(raw)
	if m == nil {
		return 0, false
	}
	sign, integer, fraction, exponent := string(m[1]), string(m[2]), string(m[3]), string(m[4])
	// The value is digits x 10^shift.
	digits := strings.TrimLeft(integer+fraction, "0")
	if digits == "" {
		return 0, true
	}
	var shift int64
	if exponent != "" {
		var err error
		if shift, err = strconv.ParseInt(exponent, 10, 32); err != nil {
			// An exponent beyond 32 bits: a whole number far above 9, or a
			// fraction far below 1.
			return -1, !strings.HasPrefix(exponent, "-")
		}
	}
	significant := strings.TrimRight(digits, "0")
	shift += int64(len(digits)-len(significant)) - int64(len(fraction))
	switch {
	case shift < 0:
		return 0, false
	case sign == "-" || shift > 0 || len(significant) > 1:
		return -1, true
	}
	return int(significant[0] - '0'), true
}

// vectorOf turns 16 levels, in factors' order, into an owasp.Vector.
func vectorOf(l []int) owasp.Vector {
	return owasp.Vector{
		SL:  owasp.SkillLevel(l[0]),
		M:   owasp.Motive(l[1]),
		O:   owasp.Opportunity(l[2]),
		S:   owasp.Size(l[3]),
		ED:  owasp.EaseOfDiscovery(l[4]),
		EE:  owasp.EaseOfExploit(l[5]),
		A:   owasp.Awareness(l[6]),
		ID:  owasp.IntrusionDetection(l[7]),
		LC:  owasp.LossOfConfidentiality(l[8]),
		LI:  owasp.LossOfIntegrity(l[9]),
		LAV: owasp.LossOfAvailability(l[10]),
		LAC: owasp.LossOfAccountability(l[11]),
		FD:  owasp.FinancialDamage(l[12]),
		RD:  owasp.ReputationDamage(l[13]),
		NC:  owasp.NonCompliance(l[14]),
		PV:  owasp.PrivacyViolation(l[15]),
	}
}

func levelsString(l []int) string {
	parts := make([]string, len(factors))
	for i, f := range factors {
		parts[i] = fmt.Sprintf("%s:%d", f.key, l[i])
	}
	return strings.Join(parts, "/")
}

// buildSystemPrompt creates the system prompt for OWASP score calculation.
// Inspired by github.com/AkihiroSuda/vexllm prompt structure.
func (g *Generator) buildSystemPrompt() string {
	prompt := `You are a talented security expert scoring vulnerabilities using OWASP Risk Rating Methodology.

SYSTEM CONTEXT:
`
	if g.o.Config != nil {
		prompt += g.o.Config.FormatForLLM()
	}

	prompt += `
TASK: For EACH vulnerability, analyze its specific characteristics and rate the 16 OWASP factors below, each separately, on that factor's own levels:

1. THREAT_AGENT (Who can exploit THIS vuln in THIS system?)
   - Consider: Does system exposure match vuln attack vector?
   - Internet-exposed remote vuln: 7-9 | Private network local vuln: 3-5 | Mismatch: lower
   - Adjust for attacker motivation based on business value`
	prompt += factorLines(factors[0:4])

	prompt += `

2. VULNERABILITY (How exploitable is THIS specific vuln?)
   CRITICAL: Score the ACTUAL vulnerability, not the system
   - Analyze: CVE/description reveals public exploits? Known PoC? Automated scanners detect it?
   - Easy discovery + exploit available: 7-9 | Requires expertise: 4-6 | Theoretical/complex: 1-3`

	if g.o.Config != nil {
		controls := g.o.Config.Context.Controls
		hasControls := controls.WAF || controls.IDS || controls.EDR || controls.Segmentation || controls.ZeroTrust
		if hasControls {
			prompt += `
   - Reduce if controls block this vuln type (WAF blocks web exploits, IDS detects network attacks)`
		}
	}
	prompt += factorLines(factors[4:8])

	prompt += `

3. TECHNICAL_IMPACT (What does THIS vuln compromise?)
   - Identify what the vulnerability exposes (confidentiality/integrity/availability/accountability)
   - Map impact to system sensitivity:`

	prompt += `
     * C/I breach: score = data_sensitivity`
	if g.o.Config != nil && g.o.Config.Context.AvailabilityRequirement != nil {
		prompt += `
     * Availability loss: score = availability_requirement`
	} else {
		prompt += `
     * Availability loss: score = business_criticality`
	}
	if g.o.Config != nil && g.o.Config.Context.AuditRequirement != nil {
		prompt += `
     * Accountability loss: score = audit_requirement`
	}
	prompt += factorLines(factors[8:12])

	prompt += `

4. BUSINESS_IMPACT (Business damage if THIS vuln exploited?)
   - Base: business_criticality`

	if g.o.Config != nil && len(g.o.Config.Context.ComplianceRequirements) > 0 {
		prompt += `
   - +2 if vuln triggers compliance violation (data breach/audit failure)`
	}
	prompt += `
   - Cap at 9`
	prompt += factorLines(factors[12:16])

	prompt += `

SCORING SCALE: low:1-3, medium:4-6, high:7-8, critical:9
OUTPUT: the 16 factor levels + brief reasoning for THIS specific vulnerability in THIS context.
`
	return prompt
}

// factorLines lists a group's four factors under its guidance lines, each
// with its line from OWASP's Risk Rating Methodology.
func factorLines(group []factor) string {
	s := "\n   Factors, each rated separately:"
	for _, f := range group {
		s += "\n   - " + f.key + ": " + f.name + " - " + f.question + " " + f.options
	}
	return s
}

// buildOutputSchema returns the JSON Schema the LLM output must satisfy.
// Every property is required and additionalProperties is false so the schema is
// valid for OpenAI strict mode; the same document is then enforced natively by
// each provider.
func (g *Generator) buildOutputSchema() json.RawMessage {
	return json.RawMessage(outputSchema)
}

// outputSchema asks, per result, the vulnId, then each factor as an integer
// on its own levels with OWASP's question as its description, in the vector's
// order, then the reasoning.
var outputSchema = schemaFor(factors)

func schemaFor(fs []factor) string {
	var props, required strings.Builder
	props.WriteString(`          "vulnId": {"type": "string", "description": "The vulnerability ID from the input (e.g., CVE-2024-1234)"},` + "\n")
	required.WriteString(`"vulnId"`)
	for _, f := range fs {
		levels := make([]string, len(f.levels))
		for i, l := range f.levels {
			levels[i] = fmt.Sprint(l)
		}
		question, _ := json.Marshal(f.question)
		fmt.Fprintf(&props, `          "%s": {"type": "integer", "enum": [%s], "description": %s},`+"\n",
			f.key, strings.Join(levels, ", "), question)
		fmt.Fprintf(&required, `, "%s"`, f.key)
	}
	props.WriteString(`          "reasoning": {"type": "string", "description": "Brief explanation of each score (2-3 sentences)"}` + "\n")
	required.WriteString(`, "reasoning"`)

	return `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "results": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
` + props.String() + `        },
        "required": [` + required.String() + `]
      }
    }
  },
  "required": ["results"]
}`
}
