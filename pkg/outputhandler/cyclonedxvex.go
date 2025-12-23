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
		id := g.VulnID
		rs := []cyclonedx.VulnerabilityRating{g.Rating}
		vulns = append(vulns, cyclonedx.Vulnerability{
			ID:      id,
			Ratings: &rs,
		})
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
