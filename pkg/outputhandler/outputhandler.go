package outputhandler

import (
	"github.com/CycloneDX/cyclonedx-go"
)

type OutputHandler interface {
	HandleScores([]cyclonedx.VulnerabilityRating) error
	Close() error
}
