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
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/venslabs/vens/cmd/vens/version"
)

// DefaultSpecVersion is the CycloneDX spec version emitted when the caller does
// not request a specific one. It is 1.6 because no released Dependency-Track
// can ingest 1.7 yet; 1.7 stays available via --cyclonedx-spec-version.
const DefaultSpecVersion = "1.6"

// specVersionEntry pairs a CycloneDX spec version string with its
// cyclonedx.SpecVersion. specVersions is the single ordered source of truth;
// SupportedSpecVersions and specVersionsByString are both derived from it.
type specVersionEntry struct {
	name string
	spec cyclonedx.SpecVersion
}

var specVersions = []specVersionEntry{
	{"1.6", cyclonedx.SpecVersion1_6},
	{"1.7", cyclonedx.SpecVersion1_7},
}

// SupportedSpecVersions lists the CycloneDX spec versions vens can emit, in
// ascending order. Used for validation and help/error text.
var SupportedSpecVersions = func() []string {
	names := make([]string, len(specVersions))
	for i, e := range specVersions {
		names[i] = e.name
	}
	return names
}()

var specVersionsByString = func() map[string]cyclonedx.SpecVersion {
	m := make(map[string]cyclonedx.SpecVersion, len(specVersions))
	for _, e := range specVersions {
		m[e.name] = e.spec
	}
	return m
}()

// ParseSpecVersion maps a CycloneDX spec version string (e.g. "1.6", "1.7") to
// its cyclonedx.SpecVersion. It returns an error for any value outside
// SupportedSpecVersions.
func ParseSpecVersion(s string) (cyclonedx.SpecVersion, error) {
	if v, ok := specVersionsByString[s]; ok {
		return v, nil
	}
	return 0, fmt.Errorf("unsupported CycloneDX spec version %q (supported: %s)", s, strings.Join(SupportedSpecVersions, ", "))
}

// NewCycloneDxVexOutputHandler returns an OutputHandler that accumulates
// vulnerability ratings and emits a proper CycloneDX VEX BOM on Close.
// vexUUID is the VEX document's serialNumber UUID; pass "" to generate one.
// specVersion selects the CycloneDX spec version the BOM is encoded to.
func NewCycloneDxVexOutputHandler(w io.Writer, sbomUUID string, sbomVersion int, vexUUID string, specVersion cyclonedx.SpecVersion) OutputHandler {
	return &cycloneDxVexWriter{
		w:           w,
		sbomUUID:    sbomUUID,
		sbomVersion: sbomVersion,
		vexUUID:     vexUUID,
		specVersion: specVersion,
	}
}

type cycloneDxVexWriter struct {
	w           io.Writer
	r           []VulnRating
	sbomUUID    string
	sbomVersion int
	vexUUID     string
	specVersion cyclonedx.SpecVersion
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
	serial := c.vexUUID
	if serial == "" {
		serial = uuid.New().String()
	}
	bom.SerialNumber = "urn:uuid:" + serial
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
	var unreferenced []string
	seenUnreferenced := make(map[string]bool)
	for _, g := range c.r {
		if g.BOMRef == "" {
			if !seenUnreferenced[g.VulnID] {
				seenUnreferenced[g.VulnID] = true
				unreferenced = append(unreferenced, g.VulnID)
			}
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

	// A rating we cannot attach to a component would drop out of the VEX. Silence
	// there is a one-way failure: a CVE missing from the document can never block
	// a build.
	if len(unreferenced) > 0 {
		return fmt.Errorf("no component to reference for %d scored vulnerabilities: %s",
			len(unreferenced), strings.Join(unreferenced, ", "))
	}

	if len(vulns) > 0 {
		bom.Vulnerabilities = &vulns
	}

	enc := cyclonedx.NewBOMEncoder(c.w, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.EncodeVersion(bom, c.specVersion); err != nil {
		return err
	}
	c.closed = true
	return nil
}
