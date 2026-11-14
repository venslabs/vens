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

package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/venslabs/vens/pkg/cvss"
)

// CVE is one vulnerability of a batch with every row the scanner reported for
// it, one per affected package, in scanner order. vens asks for one answer
// per CVE, which every row then carries.
type CVE struct {
	ID   string
	Rows []Row
}

// Row is what the scanner reported for a CVE on one package.
type Row struct {
	PkgID            string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	Title            string
	Description      string
	Severity         string
	// SeveritySource is the source the scanner took Severity from: Trivy's
	// SeveritySource, the matched record's namespace on Grype. Only the
	// adjustment shows it.
	SeveritySource string
	// CVSS is every vector the row's advisory publishes, each with its
	// source and version.
	CVSS []cvss.Vector
	// VendorSeverities is each source's own severity, which only the
	// adjustment shows.
	VendorSeverities []VendorSeverity
}

// VendorSeverity is one source's severity for a CVE.
type VendorSeverity struct {
	Source   string
	Severity string
}

// described reports whether a row of the CVE has a description.
func (c CVE) described() bool {
	return slices.ContainsFunc(c.Rows, func(r Row) bool { return strings.TrimSpace(r.Description) != "" })
}

// vectors returns every vector of every row, in row order.
func (c CVE) vectors() []cvss.Vector {
	var vectors []cvss.Vector
	for _, r := range c.Rows {
		vectors = append(vectors, r.CVSS...)
	}
	return vectors
}

// entry is a CVE as a request lists it. A field every row gives alike is
// written once for the CVE, and a field the rows disagree on is written in
// each package instead, so no row's value is dropped. Empty fields are left
// out.
type entry struct {
	VulnID         string         `json:"vulnId"`
	Title          string         `json:"title,omitempty"`
	Description    string         `json:"description,omitempty"`
	Severity       string         `json:"severity,omitempty"`
	SeveritySource string         `json:"severitySource,omitempty"`
	Packages       []entryPackage `json:"packages"`
}

type entryPackage struct {
	PkgID            string `json:"pkgId,omitempty"`
	Name             string `json:"name,omitempty"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	FixedVersion     string `json:"fixedVersion,omitempty"`
	Title            string `json:"title,omitempty"`
	Description      string `json:"description,omitempty"`
	Severity         string `json:"severity,omitempty"`
	SeveritySource   string `json:"severitySource,omitempty"`
}

// newEntry writes the CVE's entry. The ordinary questions are shown the
// scanner's fields without the severity's source; the adjustment, whose flag
// can rest on it, is shown it too.
func newEntry(c CVE, withSource bool) entry {
	e := entry{VulnID: c.ID, Packages: []entryPackage{}}
	title, sharedTitle := alike(c.Rows, func(r Row) string { return r.Title })
	description, sharedDescription := alike(c.Rows, func(r Row) string { return r.Description })
	severity, sharedSeverity := alike(c.Rows, func(r Row) string { return r.Severity })
	source, sharedSource := alike(c.Rows, func(r Row) string { return r.SeveritySource })
	if !withSource {
		source, sharedSource = "", true
	}
	if sharedTitle {
		e.Title = title
	}
	if sharedDescription {
		e.Description = description
	}
	if sharedSeverity {
		e.Severity = severity
	}
	if sharedSource {
		e.SeveritySource = source
	}
	for _, r := range c.Rows {
		p := entryPackage{PkgID: r.PkgID, Name: r.PkgName, InstalledVersion: r.InstalledVersion, FixedVersion: r.FixedVersion}
		if !sharedTitle {
			p.Title = r.Title
		}
		if !sharedDescription {
			p.Description = r.Description
		}
		if !sharedSeverity {
			p.Severity = r.Severity
		}
		if !sharedSource {
			p.SeveritySource = r.SeveritySource
		}
		if !slices.Contains(e.Packages, p) {
			e.Packages = append(e.Packages, p)
		}
	}
	return e
}

// alike returns the value every row gives a field, and false when two rows
// differ on it.
func alike(rows []Row, field func(Row) string) (string, bool) {
	for _, r := range rows[1:] {
		if field(r) != field(rows[0]) {
			return "", false
		}
	}
	return field(rows[0]), true
}

// entriesJSON is the batch's entries as encoding/json writes them, in batch
// order.
func entriesJSON(batch []CVE) (string, error) {
	if err := checkBatch(batch); err != nil {
		return "", err
	}
	entries := make([]entry, len(batch))
	for i, c := range batch {
		entries[i] = newEntry(c, false)
	}
	b, err := json.Marshal(entries)
	return string(b), err
}

func checkBatch(batch []CVE) error {
	if len(batch) == 0 {
		return errors.New("the batch holds no CVE")
	}
	seen := map[string]bool{}
	for _, c := range batch {
		if err := checkCVE(c); err != nil {
			return err
		}
		if seen[c.ID] {
			return fmt.Errorf("%s is twice in the batch", c.ID)
		}
		seen[c.ID] = true
	}
	return nil
}

func checkCVE(c CVE) error {
	if c.ID == "" {
		return errors.New("a CVE has no id")
	}
	if len(c.Rows) == 0 {
		return fmt.Errorf("%s has no row", c.ID)
	}
	return nil
}
