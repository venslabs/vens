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

package outputhandler

import (
	"io"

	"github.com/CycloneDX/cyclonedx-go"
)

// NewCycloneDxVexOutputHandler returns an OutputHandler that accumulates
// vulnerability ratings and emits a proper CycloneDX VEX BOM on Close.
func NewCycloneDxVexOutputHandler(w io.Writer) OutputHandler { return &cycloneDxVexWriter{w: w} }

type cycloneDxVexWriter struct {
	w      io.Writer
	r      []VulnRating
	closed bool
}

func (c *cycloneDxVexWriter) HandleVulnRatings(vr []VulnRating) error {
	if len(vr) == 0 {
		return nil
	}
	c.r = append(c.r, vr...)
	return nil
}

func (c *cycloneDxVexWriter) Close() error {
	if c.closed {
		return nil
	}
	// Build a CycloneDX VEX with vulnerabilities and dedicated rating
	bom := cyclonedx.NewBOM()

	vulns := make([]cyclonedx.Vulnerability, 0, len(c.r))
	for _, g := range c.r {
		rs := []cyclonedx.VulnerabilityRating{g.Rating}
		v := cyclonedx.Vulnerability{
			ID:      g.VulnID,
			Ratings: &rs,
		}
		if g.AffectedRef != "" {
			v.Affects = &[]cyclonedx.Affects{{Ref: g.AffectedRef}}
		}
		vulns = append(vulns, v)
	}

	if len(vulns) > 0 {
		bom.Vulnerabilities = &vulns
	}

	enc := cyclonedx.NewBOMEncoder(c.w, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.Encode(bom); err != nil {
		return err
	}
	c.closed = true
	return nil
}
