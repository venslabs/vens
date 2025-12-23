package outputhandler

import (
	"github.com/CycloneDX/cyclonedx-go"
)

type OutputHandler interface {
	// HandleVulnRatings ingests ratings grouped by vulnerability ID (e.g., CVE).
	HandleVulnRatings([]VulnRating) error
	Close() error
}

// VulnRating carries a single CycloneDX rating for one vulnerability ID.
type VulnRating struct {
	VulnID string
	Rating cyclonedx.VulnerabilityRating
}
