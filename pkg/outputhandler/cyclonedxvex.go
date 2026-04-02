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
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/venslabs/vens/cmd/vens/version"
)

// NewCycloneDxVexOutputHandler returns an OutputHandler that accumulates
// vulnerability ratings and emits a proper CycloneDX VEX BOM on Close.
func NewCycloneDxVexOutputHandler(w io.Writer, sbomUUID string, sbomVersion int) OutputHandler {
	return &cycloneDxVexWriter{
		w:           w,
		sbomUUID:    sbomUUID,
		sbomVersion: sbomVersion,
	}
}

type cycloneDxVexWriter struct {
	w           io.Writer
	r           []VulnRating
	sbomUUID    string
	sbomVersion int
	closed      bool
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
	bom := cyclonedx.NewBOM()
	bom.SerialNumber = "urn:uuid:" + uuid.New().String()
	bom.Version = c.sbomVersion
	bom.Metadata = &cyclonedx.Metadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					Type:    cyclonedx.ComponentTypeApplication,
					Name:    "vens",
					Version: version.GetVersion(),
				},
			},
		},
	}

	vulnMap := make(map[string]*cyclonedx.Vulnerability)
	affectsSet := make(map[string]map[string]bool)
	for _, g := range c.r {
		if g.BOMRef == "" {
			slog.Warn("Skipping vulnerability without BOMRef", "vuln", g.VulnID)
			continue
		}

		bomLink := fmt.Sprintf("urn:cdx:%s/%d#%s", c.sbomUUID, c.sbomVersion, g.BOMRef)

		if existing, ok := vulnMap[g.VulnID]; ok {
			if !affectsSet[g.VulnID][bomLink] {
				affectsSet[g.VulnID][bomLink] = true
				*existing.Affects = append(*existing.Affects, cyclonedx.Affects{Ref: bomLink})
			}
			continue
		}

		vulnMap[g.VulnID] = &cyclonedx.Vulnerability{
			ID:      g.VulnID,
			Source:  g.Source,
			Ratings: &[]cyclonedx.VulnerabilityRating{g.Rating},
			Affects: &[]cyclonedx.Affects{{Ref: bomLink}},
		}
		affectsSet[g.VulnID] = map[string]bool{bomLink: true}
	}

	vulns := make([]cyclonedx.Vulnerability, 0, len(vulnMap))
	for _, v := range vulnMap {
		vulns = append(vulns, *v)
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
