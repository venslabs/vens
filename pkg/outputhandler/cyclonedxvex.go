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
// analysisDetail is opt-in: when true each vulnerability carries an analysis
// block with the score justification in detail; when false no analysis
// block is emitted at all. Dependency-Track 5.1+ unsuppresses findings on
// an analysis block that carries no state, so the default stays off (#316).
func NewCycloneDxVexOutputHandler(w io.Writer, sbomUUID string, sbomVersion int, vexUUID string, specVersion cyclonedx.SpecVersion, analysisDetail bool) OutputHandler {
	return &cycloneDxVexWriter{
		w:              w,
		sbomUUID:       sbomUUID,
		sbomVersion:    sbomVersion,
		vexUUID:        vexUUID,
		specVersion:    specVersion,
		analysisDetail: analysisDetail,
	}
}

type cycloneDxVexWriter struct {
	w              io.Writer
	r              []VulnRating
	sbomUUID       string
	sbomVersion    int
	vexUUID        string
	specVersion    cyclonedx.SpecVersion
	analysisDetail bool
	closed         bool
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
	for _, g := range c.r {
		if g.BOMRef == "" {
			// Dropping it leaves the run at exit code 0 with a VEX short of a CVE,
			// which for a gate only fails one way. Kept as a warning for now, see
			// https://github.com/venslabs/vens/issues/272.
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
		if c.analysisDetail {
			// A short justification derived from the (score, severity,
			// vector) triple only — everything it cites is already in the
			// VEX, so it leaks nothing and is stable across runs. Opt-in
			// only: Dependency-Track 5.1+ unsuppresses findings when an
			// analysis block carries no state (#316).
			vulnMap[g.VulnID].Analysis = &cyclonedx.VulnerabilityAnalysis{
				Detail: analysisDetail(g.Rating),
			}
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

	// Encode() rather than EncodeVersion(): cyclonedx-go copies the BOM
	// through encoding/gob, which omits a *float64 that points at 0, so
	// OWASP ratings that scored exactly 0 lost their score key (#306).
	bom.SpecVersion = c.specVersion
	if schema := jsonSchemaFor(c.specVersion); schema != "" {
		bom.JSONSchema = schema
	}
	enc := cyclonedx.NewBOMEncoder(c.w, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.Encode(bom); err != nil {
		return err
	}
	c.closed = true
	return nil
}

// analysisDetail builds the short justification for a score from the
// (score, severity, vector) triple only — everything it cites is already
// in the VEX, so it leaks nothing and is stable across runs. The score is
// printed with two decimals so the text never rounds differently than the
// published value (e.g. 56.25 reads 56.25, not 56.2). See #316.
func analysisDetail(r cyclonedx.VulnerabilityRating) string {
	score := 0.0
	if r.Score != nil {
		score = *r.Score
	}
	return fmt.Sprintf("%s risk rating %.2f (%s) from vector %q.", r.Method, score, r.Severity, r.Vector)
}

func jsonSchemaFor(v cyclonedx.SpecVersion) string {
	switch v {
	case cyclonedx.SpecVersion1_6:
		return "http://cyclonedx.org/schema/bom-1.6.schema.json"
	case cyclonedx.SpecVersion1_7:
		return "http://cyclonedx.org/schema/bom-1.7.schema.json"
	default:
		return ""
	}
}
