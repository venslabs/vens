package riskconfig

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

// Config represents the structure of config.yaml provided by users.
// The schema is intentionally simple to keep the file easy to edit.
//
// Example YAML:
//
//	owasp:
//	  # Use version-less PURLs as keys (preferred):
//	  pkg:golang/github.com/acme/lib:
//	    score: 45      # optionnel; 0..81 (si fourni directement, échelle OWASP native)
//	    likelihood: 5  # optionnel; 0..9 (OWASP 0..9)
//	    impact: 9      # optionnel; 0..9 (OWASP 0..9)
//
//	# Remarque: si une version est présente dans la clé ("@version"),
//	# elle est IGNORÉE lors du chargement. Les clés sont normalisées
//	# en PURL sans version pour refléter un impact indépendant de la version.
//
// If score is not provided, it will be computed from likelihood and impact
// as OWASP Risk: score = (likelihood * impact). With both factors in [0..9],
// the computed risk is in [0..81].
// If neither score nor both likelihood and impact are provided, the entry is invalid.
type Config struct {
	OWASP map[string]OWASPEntry `yaml:"owasp"`
}

// OWASPEntry holds either a direct score, or the minimal pair of factors
// (likelihood and impact) to compute a score.
type OWASPEntry struct {
	Score      *float64 `yaml:"score,omitempty"`
	Likelihood *float64 `yaml:"likelihood,omitempty"`
	Impact     *float64 `yaml:"impact,omitempty"`
}

// Load parses a config.yaml file from the given path and validates entries.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f Config
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if len(f.OWASP) == 0 {
		return &f, nil
	}
	// Normalize keys to version-less PURLs and validate ranges.
	normMap := make(map[string]OWASPEntry, len(f.OWASP))
	for purl, e := range f.OWASP {
		norm := NormalizePURL(purl)
		// At least one of: score OR (likelihood and impact) must be provided.
		hasScore := e.Score != nil
		hasFactors := e.Likelihood != nil && e.Impact != nil

		if !hasScore && !hasFactors {
			return nil, fmt.Errorf("owasp entry for %s must have either score or both likelihood and impact", norm)
		}
		if hasScore && !inRange0081(*e.Score) {
			return nil, fmt.Errorf("score for %s must be between 0 and 81 (OWASP native scale)", norm)
		}
		if hasFactors {
			if !inRange09(*e.Likelihood) || !inRange09(*e.Impact) {
				return nil, fmt.Errorf("likelihood/impact for %s must be between 0 and 9 (OWASP native scale)", norm)
			}
		}
		// Keep the last occurrence in case of duplicates (versioned and unversioned keys).
		normMap[norm] = e
	}
	f.OWASP = normMap
	return &f, nil
}

// ScoreForPURL returns the OWASP score in range [0,81] for the given purl if present.
func (f *Config) ScoreForPURL(purl string) (float64, bool) {
	if f == nil || len(f.OWASP) == 0 {
		return 0, false
	}
	// NOTE: Keys were normalized during Load. Callers should pass a version-less PURL here.
	// No additional normalization is performed at lookup time.
	e, ok := f.OWASP[purl]
	if !ok {
		return 0, false
	}
	if e.Score != nil {
		return *e.Score, true
	}
	if e.Likelihood != nil && e.Impact != nil {
		// OWASP Risk combination: Risk = Likelihood * Impact (0..81)
		l, i := *e.Likelihood, *e.Impact
		return (l * i), true
	}
	return 0, false
}

// NormalizePURL returns the PURL without a version part (sub-string after '@').
// This is a simple best-effort normalization and does not parse full PURL grammar.
func NormalizePURL(purl string) string {
	for i := 0; i < len(purl); i++ {
		if purl[i] == '@' {
			return purl[:i]
		}
	}
	return purl
}

func inRange09(v float64) bool   { return v >= 0 && v <= 9 }
func inRange0081(v float64) bool { return v >= 0 && v <= 81 }
