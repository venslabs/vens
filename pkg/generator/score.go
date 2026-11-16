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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/venslabs/vens/pkg/attestation"
	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/outputhandler"
	"github.com/venslabs/vens/pkg/owasp"
	"github.com/venslabs/vens/pkg/vuln"
)

// assessment is what the calls of a batch gathered for one CVE.
type assessment struct {
	answers contract.Answers
	// read lists the factors answered, in call order, and raw their answers
	// as the replies wrote them.
	read     []contract.Factor
	raw      map[contract.Factor]json.RawMessage
	adjusted *contract.Adjusted
	// reasons holds each answer's sentence in call order, as "factor
	// (answer): sentence", the adjustment's last.
	reasons []string
	// evidence lists the evidence of every call whose answer Go kept, in
	// call order, each once.
	evidence []string
}

func (a *assessment) answer(f contract.Factor, r reply) {
	if f == contract.ID {
		a.answers.ID = r.answer
	} else {
		*answerField(&a.answers, f) = r.answer[0]
	}
	if a.raw == nil {
		a.raw = map[contract.Factor]json.RawMessage{}
	}
	a.read = append(a.read, f)
	a.raw[f] = r.raw
	a.note(fmt.Sprintf("%s (%s): %s", f, strings.Join(r.answer, ", "), oneLine(r.reasoning)), r.evidenceRef)
}

// oneLine collapses each run of whitespace, line breaks included, to one
// space: a claim's reasoning holds one line per answer.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func (a *assessment) note(reason, evidenceRef string) {
	a.reasons = append(a.reasons, reason)
	if evidenceRef != "" && !slices.Contains(a.evidence, evidenceRef) {
		a.evidence = append(a.evidence, evidenceRef)
	}
}

// answerField is the field of a that holds factor f's answer, f one of the
// model-answered factors whose answer is one id.
func answerField(a *contract.Answers, f contract.Factor) *string {
	return map[contract.Factor]*string{
		contract.M: &a.M, contract.O: &a.O, contract.EE: &a.EE, contract.LC: &a.LC, contract.LI: &a.LI,
		contract.LAV: &a.LAV, contract.LAC: &a.LAC, contract.FD: &a.FD, contract.RD: &a.RD,
		contract.NC: &a.NC, contract.PV: &a.PV,
	}[f]
}

// scoreBatch asks the batch's questions, then rates each CVE, one rating per
// row. When it fails, the run keeps, unrated, every CVE of the batch it read
// an answer for and did not rate: a failed run is the one debugged.
func (g *Generator) scoreBatch(ctx context.Context, run *scoringRun, batch []*cve) (ratings []outputhandler.VulnRating, err error) {
	assessed := make(map[string]*assessment, len(batch))
	for _, c := range batch {
		assessed[c.id()] = &assessment{}
	}
	rated := 0
	defer func() {
		if err != nil {
			for _, c := range batch[rated:] {
				run.unrated(c, assessed[c.id()])
			}
		}
	}()
	if err := g.askBatch(ctx, run, batch, assessed); err != nil {
		return nil, err
	}
	for _, c := range batch {
		r, err := g.rate(ctx, run, c, assessed[c.id()])
		if err != nil {
			return nil, err
		}
		rated++
		ratings = append(ratings, r...)
	}
	return ratings, nil
}

// askBatch asks the batch's questions, one call per question in the declared
// order, each about the batch's CVEs that get it, so that the order never
// depends on which questions the first CVE gets; then makes each flagged
// CVE's adjustment call.
func (g *Generator) askBatch(ctx context.Context, run *scoringRun, batch []*cve, assessed map[string]*assessment) error {
	for _, f := range contract.Order() {
		var asked []*cve
		for _, c := range batch {
			if c.asks(f) {
				asked = append(asked, c)
			}
		}
		if len(asked) == 0 {
			continue
		}
		if err := g.ask(ctx, run, f, asked, assessed); err != nil {
			return err
		}
	}
	for _, c := range batch {
		if len(c.flags) > 0 {
			if err := g.adjust(ctx, run, c, assessed[c.id()]); err != nil {
				return err
			}
		}
	}
	return nil
}

// rate computes a CVE's 16 levels and their rating, records them for the run,
// and returns one rating per row, each with its attestation claim. A vector
// off the calculator's levels stops the run: the rules' tests keep that from
// happening.
func (g *Generator) rate(ctx context.Context, run *scoringRun, c *cve, a *assessment) ([]outputhandler.VulnRating, error) {
	levels, err := contract.Compute(g.deployment, c.in, c.applicability.Floored, a.answers, a.adjusted)
	if err != nil {
		return nil, err
	}
	rating, err := levels.Vector.Rate()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.id(), err)
	}
	run.rated(c, a, levels)
	out := make([]outputhandler.VulnRating, 0, len(c.rows))
	for _, v := range c.rows {
		slog.InfoContext(ctx, "Scored vulnerability",
			"vuln", c.id(),
			"pkg", v.BOMRef,
			"score", rating.Score,
			"severity", rating.Severity,
			"vector", rating.Vector,
		)
		out = append(out, vulnRating(c.id(), v, rating))
		if g.attestor != nil {
			g.attestor.AddClaim(a.evidence, attestation.ClaimInput{
				VulnID:      c.id(),
				CompRef:     v.BOMRef,
				CompName:    v.PkgName,
				CompVersion: v.InstalledVersion,
				PURL:        v.BOMRef,
				Score:       rating.Score,
				Severity:    rating.Severity,
				Reasoning:   strings.Join(a.reasons, "\n"),
			})
		}
	}
	return out, nil
}

func vulnRating(id string, v Vulnerability, r owasp.Rating) outputhandler.VulnRating {
	source := vuln.Source(id)
	if v.SourceName != "" {
		source = &cyclonedx.Source{Name: v.SourceName, URL: v.SourceURL}
	}
	score := r.Score
	return outputhandler.VulnRating{
		VulnID: id,
		BOMRef: v.BOMRef,
		Rating: cyclonedx.VulnerabilityRating{
			Method:   cyclonedx.ScoringMethodOWASP,
			Score:    &score,
			Severity: cyclonedx.Severity(r.Severity),
			Vector:   r.Vector,
		},
		Source: source,
	}
}
