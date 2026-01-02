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
	"github.com/aquasecurity/table"
	"github.com/aquasecurity/tml"
	"io"
	"os"
)

type trivyTableOutputHandler struct {
	w io.Writer
	r []VulnRating
}

func NewTrivyTableOutputHandler(w io.Writer) OutputHandler {
	if w == nil {
		w = os.Stdout
	}
	return &trivyTableOutputHandler{w: w}
}

func (h *trivyTableOutputHandler) HandleVulnRatings(vr []VulnRating) error {
	h.r = append(h.r, vr...)
	return nil
}

func (h *trivyTableOutputHandler) Close() error {
	if len(h.r) == 0 {
		return nil
	}

	t := table.New(h.w)
	// Trivy uses its own table library which might have a different API.
	// Let's check the API for github.com/aquasecurity/table
	t.SetHeaders("Vulnerability ID", "Package", "Vens Severity", "Vens Score", "Justification")

	for _, r := range h.r {
		pkg := r.AffectedRef
		if pkg == "" {
			pkg = "unknown"
		}
		score := 0.0
		if r.Rating.Score != nil {
			score = *r.Rating.Score
		}

		severity := string(r.Rating.Severity)
		coloredSeverity := colorSeverity(severity)

		t.AddRow(
			r.VulnID,
			pkg,
			coloredSeverity,
			fmt.Sprintf("%.1f", score),
			r.Rating.Justification,
		)
	}
	t.Render()
	return nil
}

func colorSeverity(severity string) string {
	switch severity {
	case "CRITICAL":
		return tml.Sprintf("<red><bold>CRITICAL</bold></red>")
	case "HIGH":
		return tml.Sprintf("<red>HIGH</red>")
	case "MEDIUM":
		return tml.Sprintf("<yellow>MEDIUM</yellow>")
	case "LOW":
		return tml.Sprintf("<blue>LOW</blue>")
	default:
		return severity
	}
}
