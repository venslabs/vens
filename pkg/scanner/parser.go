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

package scanner

import (
	"encoding/json"
	"fmt"

	"github.com/venslabs/vens/pkg/generator"
)

// ReportScanner interface for different vulnerability scanner formats.
// Implementations parse scanner-specific reports into a common Vulnerability format.
type ReportScanner interface {
	// Parse reads and converts a scanner report to common Vulnerability format
	Parse(data []byte) ([]generator.Vulnerability, error)

	// Name returns the scanner name (e.g., "trivy", "grype")
	Name() string
}

// ScannerType represents supported scanner types
type ScannerType string

const (
	ScannerTrivy ScannerType = "trivy"
	ScannerGrype ScannerType = "grype"
)

// DetectFormat automatically detects the scanner format by examining JSON structure.
// Returns the appropriate scanner or an error if format is unknown.
func DetectFormat(data []byte) (ReportScanner, error) {
	// Unmarshal into a generic map to detect discriminator fields
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Grype reports have a "matches" field at the root
	if _, hasMatches := raw["matches"]; hasMatches {
		return &GrypeScanner{}, nil
	}

	// Trivy reports have a "Results" field at the root
	if _, hasResults := raw["Results"]; hasResults {
		return &TrivyScanner{}, nil
	}

	return nil, fmt.Errorf("unknown report format: unable to detect scanner type")
}

// NewScanner creates a scanner for the specified scanner type.
func NewScanner(scannerType ScannerType) (ReportScanner, error) {
	switch scannerType {
	case ScannerTrivy:
		return &TrivyScanner{}, nil
	case ScannerGrype:
		return &GrypeScanner{}, nil
	default:
		return nil, fmt.Errorf("unsupported scanner type: %s", scannerType)
	}
}
