package types

// SBOMComponent holds only the fields we need from CycloneDX components for indexing.
type SBOMComponent struct {
	Type    string `json:"type"`
	Group   string `json:"group,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	PURL    string `json:"purl,omitempty"`
	// ParentPURL is the purl of metadata.component (the SBOM's top-level component).
	// Filled during SBOM streaming/decoding for easy linkage to the parent.
	// Not part of the original component JSON; kept out of JSON encoding on purpose.
	ParentPURL string `json:"-"`
}
