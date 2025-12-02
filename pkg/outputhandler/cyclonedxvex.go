package outputhandler

import (
	"encoding/json"
	"io"

	"github.com/CycloneDX/cyclonedx-go"
)

// NewCycloneDxVexOutputHandler returns a minimal OutputHandler that writes
// vulnerability ratings as a JSON array to the provided writer. This is an MVP
// implementation and can be replaced later with proper CycloneDX VEX generation.
func NewCycloneDxVexOutputHandler(w io.Writer) OutputHandler {
	return &cycloneDxVexWriter{w: w}
}

type cycloneDxVexWriter struct {
	w io.Writer
}

func (c *cycloneDxVexWriter) HandleScores(ratings []cyclonedx.VulnerabilityRating) error {
	enc := json.NewEncoder(c.w)
	enc.SetIndent("", "  ")
	return enc.Encode(ratings)
}

func (c *cycloneDxVexWriter) Close() error { return nil }
