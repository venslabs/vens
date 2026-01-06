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
	"encoding/json"
	"io"
)

type trivyJsonOutputHandler struct {
	w         io.Writer
	rawReport []byte
	r         []VulnRating
}

func NewTrivyJsonOutputHandler(w io.Writer, rawReport []byte) OutputHandler {
	return &trivyJsonOutputHandler{
		w:         w,
		rawReport: rawReport,
	}
}

func (h *trivyJsonOutputHandler) HandleVulnRatings(vr []VulnRating) error {
	h.r = append(h.r, vr...)
	return nil
}

func (h *trivyJsonOutputHandler) Close() error {
	// Map ratings by VulnID and PkgID (if available)
	ratingsMap := make(map[string]VulnRating)
	for _, r := range h.r {
		key := r.VulnID
		if r.AffectedRef != "" {
			key += "@" + r.AffectedRef
		}
		ratingsMap[key] = r
	}

	var data map[string]interface{}
	if err := json.Unmarshal(h.rawReport, &data); err != nil {
		return err
	}

	// Update the report
	if results, ok := data["Results"].([]interface{}); ok {
		for _, res := range results {
			if resMap, ok := res.(map[string]interface{}); ok {
				if vulns, ok := resMap["Vulnerabilities"].([]interface{}); ok {
					for _, vuln := range vulns {
						if vulnMap, ok := vuln.(map[string]interface{}); ok {
							vulnID, _ := vulnMap["VulnerabilityID"].(string)
							pkgID, _ := vulnMap["PkgID"].(string)

							key := vulnID
							if pkgID != "" {
								key += "@" + pkgID
							}

							if r, ok := ratingsMap[key]; ok {
								ratingData := map[string]interface{}{
									"severity":      string(r.Rating.Severity),
									"justification": r.Rating.Justification,
								}
								if r.Rating.Score != nil {
									ratingData["score"] = *r.Rating.Score
								}
								vulnMap["vens_rating"] = ratingData
							} else if r, ok := ratingsMap[vulnID]; ok {
								ratingData := map[string]interface{}{
									"severity":      string(r.Rating.Severity),
									"justification": r.Rating.Justification,
								}
								if r.Rating.Score != nil {
									ratingData["score"] = *r.Rating.Score
								}
								vulnMap["vens_rating"] = ratingData
							}
						}
					}
				}
			}
		}
	}

	enc := json.NewEncoder(h.w)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}
