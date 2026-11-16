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

package generator

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/venslabs/vens/pkg/contract"
	"github.com/venslabs/vens/pkg/cvss"
)

// VendorSeverity is one source's severity for a vulnerability, as the
// scanner report names both.
type VendorSeverity struct {
	Source   string
	Severity string
}

// Flags are the two flags that send a CVE to the adjustment call, and
// whether the second could be checked at all.
type Flags struct {
	// MaintainerDisputed: the description says the CVE is disputed, or not a
	// security issue.
	MaintainerDisputed bool
	// SeverityContested: the severity is low and not NVD's, while NVD rates
	// the CVE high or critical with a vector of the newest CVSS version the
	// row carries.
	SeverityContested bool
	// SeverityContestedUnavailable: the report has no NVD record to check the
	// severity against, so SeverityContested could not fire.
	SeverityContestedUnavailable bool
}

// Flagged reports whether either flag fired.
func (f Flags) Flagged() bool {
	return f.MaintainerDisputed || f.SeverityContested
}

// CVEFlags reads one CVE's flags from its rows: a flag fires when it fires on
// any row, and the second is unavailable only when it is on every row.
func CVEFlags(rows []Vulnerability) Flags {
	f := Flags{SeverityContestedUnavailable: len(rows) > 0}
	for _, r := range rows {
		f.MaintainerDisputed = f.MaintainerDisputed || r.Flags.MaintainerDisputed
		f.SeverityContested = f.SeverityContested || r.Flags.SeverityContested
		f.SeverityContestedUnavailable = f.SeverityContestedUnavailable && r.Flags.SeverityContestedUnavailable
	}
	return f
}

// CVEApplicability reads Applicability over every vector of one CVE's rows.
func CVEApplicability(rows []Vulnerability) cvss.Applicability {
	var vectors []cvss.Vector
	for _, r := range rows {
		vectors = append(vectors, r.CVSS...)
	}
	return cvss.ApplicabilityOf(vectors)
}

// disputed is the wording by which a description says its CVE is disputed or
// not a security issue. None of its forms holds a sentence break.
var disputed = regexp.MustCompile(`(?i)\bdisput|non-security|not a security issue|no real threat`)

// quoteLimit is the most characters of a description a dispute quote holds.
const quoteLimit = 200

// DisputeQuote returns the sentence of a description that says its CVE is
// disputed or not a security issue, or "" when none does. A sentence longer
// than quoteLimit is cut around the words that matched, an ellipsis marking
// each cut.
func DisputeQuote(description string) string {
	for line := range strings.SplitSeq(description, "\n") {
		for sentence := range strings.SplitAfterSeq(line, ". ") {
			sentence = strings.TrimSpace(sentence)
			if loc := disputed.FindStringIndex(sentence); loc != nil {
				return clip(sentence, loc)
			}
		}
	}
	return ""
}

// clip cuts s to quoteLimit characters around the match at loc, byte
// offsets into s.
func clip(s string, loc []int) string {
	runes := []rune(s)
	if len(runes) <= quoteLimit {
		return s
	}
	start, end := utf8.RuneCountInString(s[:loc[0]]), utf8.RuneCountInString(s[:loc[1]])
	from := max(0, min(start-(quoteLimit-(end-start))/2, len(runes)-quoteLimit))
	to := from + quoteLimit
	quote := strings.TrimSpace(string(runes[from:to]))
	if from > 0 {
		quote = "…" + quote
	}
	if to < len(runes) {
		quote += "…"
	}
	return quote
}

// rowFlags lists, row by row, each flag a row raised with what the
// adjustment quotes for it and the row's package, each distinct one once. A
// row with no package name is named by its package id, else its BOM-Ref.
func rowFlags(rows []Vulnerability) []contract.Flag {
	var flags []contract.Flag
	add := func(f contract.Flag) {
		if !slices.Contains(flags, f) {
			flags = append(flags, f)
		}
	}
	for _, r := range rows {
		pkg := contractRow(r).Package()
		if r.Flags.MaintainerDisputed {
			add(contract.Flag{Name: contract.MaintainerDisputed, Evidence: DisputeQuote(r.Description), Package: pkg})
		}
		if r.Flags.SeverityContested {
			add(contract.Flag{Name: contract.SeverityContested, Evidence: contestQuote(r), Package: pkg})
		}
	}
	return flags
}

// contestQuote quotes the two severities severity_contested compares: the
// row's, with its source, and NVD's.
func contestQuote(r Vulnerability) string {
	source := r.SeveritySource
	if source == "" {
		source = "no named source"
	}
	quote := fmt.Sprintf("severity %s from %s", r.Severity, source)
	for _, s := range r.VendorSeverities {
		if strings.HasPrefix(s.Source, "nvd") && (strings.EqualFold(s.Severity, "high") || strings.EqualFold(s.Severity, "critical")) {
			return quote + fmt.Sprintf(", while %s rates it %s", s.Source, s.Severity)
		}
	}
	return quote
}
