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
	"slices"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/venslabs/vens/cmd/vens/version"
	"github.com/venslabs/vens/pkg/owasp"
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
// Close fails and writes nothing when a rating has an empty BOMRef.
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
		Properties: &[]cyclonedx.Property{{Name: RatingPolicyProperty, Value: RatingPolicy}},
	}

	vulnMap := make(map[string]*cyclonedx.Vulnerability)
	affectsSet := make(map[string]map[string]bool)
	var unreferenced []string
	for _, g := range c.r {
		if g.BOMRef == "" {
			// A scored vulnerability with no component to point at must fail
			// the run, not drop out with a warning: a warning still exits 0
			// with a VEX short of a CVE, which a gate cannot tell from
			// clean (#272). The same call #269 already made for a missing
			// score. Nothing is encoded yet, so failing here writes no VEX.
			unreferenced = append(unreferenced, g.VulnID)
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
			Properties: &[]cyclonedx.Property{
				{Name: ImpactProvenanceProperty, Value: g.ImpactProvenance},
				{Name: ImpactBasisProperty, Value: string(g.ImpactBasis)},
			},
		}
		affectsSet[g.VulnID] = map[string]bool{bomLink: true}
	}

	if err := UnreferencedError("cannot emit VEX", unreferenced); err != nil {
		return err
	}
	if err := markerError("cannot emit VEX", bom.Metadata, c.r); err != nil {
		return err
	}

	vulns := make([]cyclonedx.Vulnerability, 0, len(vulnMap))
	for _, v := range vulnMap {
		vulns = append(vulns, *v)
	}

	// Go map iteration order is randomized per run; sort by vulnerability ID
	// so the emitted vulnerabilities[] array is byte-stable for identical
	// inputs (spurious diffs and unstable content hashes otherwise).
	slices.SortFunc(vulns, func(a, b cyclonedx.Vulnerability) int {
		return strings.Compare(a.ID, b.ID)
	})

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

// markers are the properties each VEX vulnerability carries once: the values
// vens writes for each, and the rating field it is read from.
var markers = []struct {
	name   string
	values []string
	of     func(VulnRating) string
}{
	{"impact provenance", []string{ImpactFromCVSSv3, ImpactFromFallback},
		func(g VulnRating) string { return g.ImpactProvenance }},
	{"impact basis", []string{string(owasp.BasisTechnical), string(owasp.BasisBusiness)},
		func(g VulnRating) string { return string(g.ImpactBasis) }},
}

// markerError names, after prefix, metadata that does not carry RatingPolicy
// once, and each vulnerability a rating gives no value vens writes for a
// marker, or whose rows give two; nil when there is none. Without the policy
// a consumer cannot tell which rules the ratings follow, without the
// provenance it cannot tell an impact read from the CVSS v3 vectors from the
// missing-input rule's worst case, and without the basis it cannot recompute
// the severity from the vector, so Close writes no VEX, as for a missing
// component.
func markerError(prefix string, metadata *cyclonedx.Metadata, ratings []VulnRating) error {
	var policies, problems []string
	if metadata != nil && metadata.Properties != nil {
		for _, p := range *metadata.Properties {
			if p.Name == RatingPolicyProperty {
				policies = append(policies, p.Value)
			}
		}
	}
	if !slices.Equal(policies, []string{RatingPolicy}) {
		problems = append(problems, fmt.Sprintf("rating policy %q is not %s", strings.Join(policies, ", "), RatingPolicy))
	}
	for _, m := range markers {
		first := map[string]string{}
		for _, g := range ratings {
			v := m.of(g)
			p, seen := first[g.VulnID]
			switch {
			case !slices.Contains(m.values, v):
				problems = append(problems, fmt.Sprintf("%s: %s %q is not %s",
					g.VulnID, m.name, v, strings.Join(m.values, " or ")))
			case !seen:
				first[g.VulnID] = v
			case p != v:
				problems = append(problems, fmt.Sprintf("%s: rows rated with %s %s and %s", g.VulnID, m.name, p, v))
			}
		}
	}
	if len(problems) == 0 {
		return nil
	}
	slices.Sort(problems)
	return fmt.Errorf("%s: %s", prefix, strings.Join(slices.Compact(problems), "; "))
}
