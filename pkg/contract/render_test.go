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
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/venslabs/vens/pkg/cvss"
)

func v31(source, metrics string) cvss.Vector {
	return cvss.Vector{Source: source, Version: "3.1", Vector: "CVSS:3.1/" + metrics}
}

// text and data stop the test on an error, else return the text rendered.
func text(t *testing.T) func(string, error) string {
	return func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
}

func data(t *testing.T) func([]byte, error) string {
	return func(b []byte, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}

// conflicting is a CVE whose two rows disagree on the description, the
// severity, the vendor severities and the vectors, two of them distinct
// with the same source and version, so that evidence keyed by source or by
// version alone would lose one.
var conflicting = CVE{ID: "CVE-C", Rows: []Row{
	{PkgID: "libfoo@1.0", PkgName: "libfoo", InstalledVersion: "1.0", FixedVersion: "1.1",
		Title: "Overflow in libfoo", Description: "A crafted header overflows a buffer.", Severity: "HIGH",
		CVSS:             []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"), v31("redhat", "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")},
		VendorSeverities: []VendorSeverity{{"nvd", "HIGH"}, {"redhat", "MEDIUM"}}},
	{PkgID: "libfoo-dev@1.0", PkgName: "libfoo-dev", InstalledVersion: "1.0", FixedVersion: "1.1",
		Title: "Overflow in libfoo", Description: "A crafted header overflows a buffer; the maintainer disputes it.", Severity: "MEDIUM",
		CVSS:             []cvss.Vector{v31("nvd", "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"), {Source: "nvd", Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"}},
		VendorSeverities: []VendorSeverity{{"nvd", "HIGH"}, {"redhat", "LOW"}}},
}}

// cvssBatch holds a CVE at each CVSS version vens reads, one with no vector,
// and one whose newest vector does not parse.
var cvssBatch = []CVE{
	conflicting,
	{ID: "CVE-D", Rows: []Row{{PkgName: "libbar", CVSS: []cvss.Vector{
		v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
		{Source: "ghsa", Version: "4.0", Vector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
	}}}},
	{ID: "CVE-E", Rows: []Row{{PkgName: "libbaz"}}},
	{ID: "CVE-G", Rows: []Row{{PkgName: "libqux", CVSS: []cvss.Vector{{Source: "nvd", Version: "2.0", Vector: "AV:N/AC:M/Au:N/C:P/I:P/A:P"}}}}},
	{ID: "CVE-H", Rows: []Row{{PkgName: "libquux", CVSS: []cvss.Vector{v31("nvd", "AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")}}}},
}

var (
	adjustFlags = []Flag{{Name: SeverityContested, Evidence: "LOW from debian, NVD says HIGH", Package: "libfoo"}}
	adjustGiven = Answers{O: "no_access_or_resources_required", LC: "all", LI: "extensive_seriously_corrupt", LAV: "minimal_primary_interrupted"}
)

func TestCVSSLines(t *testing.T) {
	want := map[Factor][]string{
		O: {
			"- CVE-C: CVSS 3.1, nvd: AV:N PR:N UI:N",
			"- CVE-C: CVSS 3.1, redhat: AV:L PR:L UI:N",
			"- CVE-C: CVSS 3.1, nvd: AV:N PR:N UI:R",
			"- CVE-D: CVSS 4.0, ghsa: AV:N AT:P PR:N UI:A",
			"- CVE-G: CVSS 2.0, nvd: AV:N",
			"- CVE-H: CVSS 3.1, nvd: AV:L PR:N UI:N",
		},
		EE: {
			"- CVE-C: CVSS 3.1, nvd: AC:L PR:N UI:N",
			"- CVE-C: CVSS 3.1, redhat: AC:L PR:L UI:N",
			"- CVE-C: CVSS 3.1, nvd: AC:H PR:N UI:R",
			"- CVE-D: CVSS 4.0, ghsa: AC:L AT:P PR:N UI:A",
			"- CVE-G: CVSS 2.0, nvd: AC:M",
			"- CVE-H: CVSS 3.1, nvd: AC:L PR:N UI:N",
		},
	}
	for f, metrics := range cvssShown {
		if got := cvssLines(metrics, cvssBatch); !slices.Equal(got, want[f]) {
			t.Errorf("%s:\n got %q\nwant %q", f, got, want[f])
		}
	}
	// A line is written once, however many rows carry its vector.
	twice := CVE{ID: "CVE-T", Rows: []Row{{CVSS: conflicting.Rows[0].CVSS[:1]}, {CVSS: conflicting.Rows[0].CVSS[:1]}}}
	if got := cvssLines(cvssShown[O], []CVE{twice}); len(got) != 1 {
		t.Errorf("one vector on two rows: %q", got)
	}
}

// A vector published at the newest version always gets its line, showing
// its metrics as written: a CVE with no line has no published vector.
func TestCVSSLinesShowWhatWasPublished(t *testing.T) {
	for _, c := range []struct {
		name   string
		vector cvss.Vector
		parses bool
		want   []string
	}{
		{"a value off its version's scale", v31("nvd", "AV:Z/AC:L/PR:N/UI:N"), true, []string{"- CVE-X: CVSS 3.1, nvd: AV:Z PR:N UI:N"}},
		{"a metric written twice, its last value", v31("nvd", "AV:N/PR:N/UI:N/AV:A"), false, []string{"- CVE-X: CVSS 3.1, nvd: AV:A PR:N UI:N"}},
		{"a vector that does not parse", v31("nvd", "AV:N//PR:L:x/UI"), false, []string{"- CVE-X: CVSS 3.1, nvd: AV:N PR:L:x"}},
		{"none of the metrics shown", v31("nvd", "S:U/C:H/I:H/A:H"), true, []string{"- CVE-X: CVSS 3.1, nvd:"}},
		{"a version vens does not read", cvss.Vector{Source: "nvd", Version: "5.0", Vector: "CVSS:5.0/AV:N"}, false, nil},
	} {
		if _, err := c.vector.Parse(); (err == nil) != c.parses {
			t.Fatalf("%s: Parse() = %v", c.name, err)
		}
		got := cvssLines(cvssShown[O], []CVE{{ID: "CVE-X", Rows: []Row{{CVSS: []cvss.Vector{c.vector}}}}})
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// The newest version is the one the scanner reports, whatever the text.
	older := cvss.Vector{Source: "nvd", Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:P/I:P/A:P"}
	newer := v31("ghsa", "garbled")
	if got := cvssLines(cvssShown[O], []CVE{{ID: "CVE-X", Rows: []Row{{CVSS: []cvss.Vector{older, newer}}}}}); !slices.Equal(got, []string{"- CVE-X: CVSS 3.1, ghsa:"}) {
		t.Errorf("a garbled v3.1 beside a v2: %q", got)
	}
}

// Ease of exploit shows the controls in one order, whatever order the config
// gives them in.
func TestControlsShownInOneOrder(t *testing.T) {
	control := func(key string) Control {
		return Control{Key: key, Description: key + " description", Scope: key + " scope"}
	}
	var all []Control
	for _, key := range []string{"antivirus", "zero_trust", "segmentation", "ddos_protection", "waf"} {
		all = append(all, control(key))
	}
	want := "Controls in front of this deployment: waf (waf description; scope: waf scope); " +
		"ddos_protection (ddos_protection description; scope: ddos_protection scope); " +
		"segmentation (segmentation description; scope: segmentation scope); " +
		"zero_trust (zero_trust description; scope: zero_trust scope); " +
		"antivirus (antivirus description; scope: antivirus scope)"
	if got := controlsLine(all); got != want {
		t.Errorf("all five:\n got %s\nwant %s", got, want)
	}
	want = "Controls in front of this deployment: segmentation (segmentation description; scope: segmentation scope); " +
		"antivirus (antivirus description; scope: antivirus scope)"
	if got := controlsLine([]Control{control("antivirus"), control("segmentation")}); got != want {
		t.Errorf("antivirus with segmentation:\n got %s\nwant %s", got, want)
	}
}

// What each question shows besides the deployment: exactly its background
// lines and, for Opportunity and Ease of exploit only, their own CVSS
// metrics. Asserted on the blocks the renderer builds: a CVE's text can hold
// any word.
func TestFactsPerQuestion(t *testing.T) {
	d := base()
	d.Frameworks = []string{"PCI-DSS"}
	d.Controls = []Control{{"zero_trust", "Zero-trust architecture", "Authentication bypass, lateral movement"}, {"waf", "Web Application Firewall", "SQL injection, XSS, path traversal"}}
	labels := map[Factor][]string{
		M:  {"Business criticality: high", "Data sensitivity: low"},
		EE: {"Controls in front of this deployment: waf (Web Application Firewall; scope: SQL injection, XSS, path traversal); zero_trust ("},
		LI: {"Data sensitivity: low"}, LAV: {"Business criticality: high"},
		FD: {"Business criticality: high"}, RD: {"Business criticality: high"}, PV: {"Data sensitivity: low"},
	}
	for _, f := range Order() {
		got := background(f, d)
		if len(got) != len(labels[f]) {
			t.Errorf("%s shows %q, want %d lines", f, got, len(labels[f]))
			continue
		}
		for i, prefix := range labels[f] {
			if !strings.HasPrefix(got[i], prefix) {
				t.Errorf("%s line %d is %q, want it to start %q", f, i, got[i], prefix)
			}
		}
		block := facts(f, d, cvssBatch)
		_, shown := cvssShown[f]
		if strings.Contains(block, "CVSS metrics") != shown {
			t.Errorf("%s: CVSS lines shown %t, want %t", f, !shown, shown)
		}
		if metrics := regexp.MustCompile(`\b(C|I|A|VC|VI|VA|SC|SI|SA):[A-Z]\b`).FindAllString(block, -1); len(metrics) > 0 {
			t.Errorf("%s's facts show impact metrics %v", f, metrics)
		}
	}
	// Availability requirement replaces the business criticality once set.
	d.AvailabilityRequirement = &Setting{"critical", "Zero downtime tolerance"}
	if got := background(LAV, d); !slices.Equal(got, []string{"Availability requirement: critical (Zero downtime tolerance)"}) {
		t.Errorf("LAV with availability_requirement set shows %q", got)
	}
	// No control set to true, no controls line, and no block at all without
	// Ease of exploit's CVSS lines.
	d.Controls = nil
	if got := background(EE, d); got != nil {
		t.Errorf("EE without controls shows %q", got)
	}
	if got := facts(LC, d, cvssBatch); got != "" {
		t.Errorf("LC's request has a facts block: %q", got)
	}
}

// traceability, data_subjects and detection are Go's: two deployments that
// differ only in them send the same bytes.
func TestHiddenFieldsAreNeverSent(t *testing.T) {
	render := func(d Deployment) []string {
		out := []string{text(t)(SystemPrompt(d))}
		for _, f := range Order() {
			out = append(out, text(t)(Request(f, d, cvssBatch)))
		}
		return append(out, text(t)(AdjustmentRequest(d, conflicting, [3]bool{}, adjustFlags, adjustGiven)))
	}
	plain := base()
	plain.Frameworks = []string{"PCI-DSS"}
	want := render(plain)
	full := declared()
	full.Traceability, full.DataSubjects = ptr("per_individual"), ptr("millions")
	full.Detection = &Detection{Network: "logged_and_reviewed", Host: "logged", Application: activeInApplication}
	if got := render(full); !slices.Equal(got, want) {
		t.Error("declaring traceability, data_subjects and detection changed what is sent")
	}
}

var digit = regexp.MustCompile(`[0-9]`)

// No factor level and no 0-9 scale reaches the model from what vens writes:
// the frames, the questions and the answer lines name answers, never their
// level. The digits Privacy violation's bands hold are people, data the
// answers are about.
func TestNoLevelIsShown(t *testing.T) {
	for _, s := range []string{
		systemTemplate, projectLine, descriptionLine, exposureLine, listenerLine, notesLine,
		requestTemplate, cvssSentence, adjustmentTemplate, adjustOpportunityLine, adjustAxisLine,
	} {
		if digit.MatchString(s) {
			t.Errorf("a frame holds a digit: %q", s)
		}
	}
	for f, q := range table {
		if digit.MatchString(q.question) {
			t.Errorf("%s's question holds a digit", f)
		}
		for i, text := range q.texts {
			if f != PV && digit.MatchString(text) {
				t.Errorf("%s %s's text holds a digit: %q", f, q.ids[i], text)
			}
		}
	}
	for _, a := range privacyViolation.answers {
		if regexp.MustCompile(`\b` + string(rune('0'+a.value)) + `\b`).MatchString(a.text) {
			t.Errorf("PV %s's text shows its level %d: %q", a.id, a.value, a.text)
		}
	}
	request := text(t)(Request(PV, base(), cvssBatch))
	if !strings.Contains(request, "\n- hundreds: Hundreds: 2 to 999 people; a count under 100 belongs here.\n") {
		t.Errorf("PV's answer line is not `- id: text`:\n%s", request)
	}
}

// One table: the answer lines a request shows, its schema's enum and the
// map Go reads are the same ids in the same order.
func TestOneTable(t *testing.T) {
	maps := map[Factor][]string{
		M: ids(motive), O: ids(opportunity), EE: ids(easeOfExploit), ID: ids(intrusionDetection),
		LC: ids(confidentiality), LI: ids(integrity), LAV: ids(availability), LAC: ids(accountability),
		FD: ids(financialDamage), RD: ids(reputationDamage), NC: ids(nonCompliance), PV: ids(privacyViolation),
	}
	d := base()
	d.Frameworks = []string{"PCI-DSS"}
	for _, f := range Order() {
		request := text(t)(Request(f, d, cvssBatch))
		answers := strings.Split(request, "\nANSWERS\n")[1]
		answers = answers[:strings.Index(answers, "\n\n")]
		var lines []string
		for _, line := range strings.Split(answers, "\n") {
			id, _, _ := strings.Cut(strings.TrimPrefix(line, "- "), ":")
			lines = append(lines, id)
		}
		var s struct {
			Properties struct {
				Answers struct {
					Items struct {
						Properties struct {
							Answer struct {
								Enum  []string
								Items struct{ Enum []string }
							}
						}
					}
				}
			}
		}
		if err := json.Unmarshal([]byte(data(t)(Schema(f, []string{"CVE-C"}))), &s); err != nil {
			t.Fatal(err)
		}
		enum := s.Properties.Answers.Items.Properties.Answer.Enum
		if f == ID {
			enum = s.Properties.Answers.Items.Properties.Answer.Items.Enum
		}
		if !slices.Equal(lines, maps[f]) || !slices.Equal(enum, maps[f]) {
			t.Errorf("%s: answer lines %v, schema enum %v, map %v", f, lines, enum, maps[f])
		}
	}
}

// A CVE's rows become one entry: what every row gives alike is written once,
// what they disagree on in each package, and a package listed twice once.
func TestEntryFromConflictingRows(t *testing.T) {
	twice := CVE{ID: "CVE-T", Rows: []Row{conflicting.Rows[0], conflicting.Rows[0]}}
	got := text(t)(entriesJSON([]CVE{conflicting, twice}))
	want := `[{"vulnId":"CVE-C","title":"Overflow in libfoo","packages":[` +
		`{"pkgId":"libfoo@1.0","name":"libfoo","installedVersion":"1.0","fixedVersion":"1.1","description":"A crafted header overflows a buffer.","severity":"HIGH"},` +
		`{"pkgId":"libfoo-dev@1.0","name":"libfoo-dev","installedVersion":"1.0","fixedVersion":"1.1","description":"A crafted header overflows a buffer; the maintainer disputes it.","severity":"MEDIUM"}]},` +
		`{"vulnId":"CVE-T","title":"Overflow in libfoo","description":"A crafted header overflows a buffer.","severity":"HIGH","packages":[` +
		`{"pkgId":"libfoo@1.0","name":"libfoo","installedVersion":"1.0","fixedVersion":"1.1"}]}]`
	if got != want {
		t.Errorf("entries:\n got %s\nwant %s", got, want)
	}
	if got := text(t)(entriesJSON([]CVE{{ID: "CVE-E", Rows: []Row{{}}}})); got != `[{"vulnId":"CVE-E","packages":[{}]}]` {
		t.Errorf("a row with no field: %s", got)
	}
	titles := CVE{ID: "CVE-U", Rows: []Row{{PkgName: "a", Title: "one"}, {PkgName: "b", Title: "two"}}}
	if got := text(t)(entriesJSON([]CVE{titles})); got != `[{"vulnId":"CVE-U","packages":[{"name":"a","title":"one"},{"name":"b","title":"two"}]}]` {
		t.Errorf("rows with two titles: %s", got)
	}
}

// The adjustment's entry lists every row's evidence: each vendor severity
// with the packages it came from, every distinct vector of every version
// and source, the flags, and the answers of the axes not floored.
func TestAdjustmentEntryListsEveryRowsEvidence(t *testing.T) {
	flags := []Flag{{MaintainerDisputed, "the maintainer disputes it", "libfoo-dev"}}
	given := Answers{O: "some_access_or_resources_required", LC: "extensive", LI: "minimal_slightly_corrupt", LAV: "extensive_primary_interrupted"}
	got := data(t)(json.Marshal(newAdjustmentEntry(conflicting, [3]bool{cvss.Availability: true}, flags, given)))
	for _, part := range []string{
		`"vendorSeverity":[{"source":"nvd","severity":"HIGH","packages":["libfoo","libfoo-dev"]},{"source":"redhat","severity":"MEDIUM","packages":["libfoo"]},{"source":"redhat","severity":"LOW","packages":["libfoo-dev"]}]`,
		`"cvss":[{"source":"nvd","version":"3.1","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},{"source":"redhat","version":"3.1","vector":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},{"source":"nvd","version":"3.1","vector":"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"},{"source":"nvd","version":"2.0","vector":"AV:N/AC:L/Au:N/C:P/I:N/A:N"}]`,
		`"flags":[{"flag":"maintainer_disputed","evidence":"the maintainer disputes it","package":"libfoo-dev"}]`,
		`"answers":{"opportunity":"some_access_or_resources_required","confidentiality":"extensive","integrity":"minimal_slightly_corrupt"}}`,
	} {
		if !strings.Contains(got, part) {
			t.Errorf("the adjustment's entry lacks %s:\n%s", part, got)
		}
	}
}

// The adjustment asks Opportunity, then each axis Applicability did not
// floor, in its request, its reply line and its schema alike.
func TestAdjustmentAsksTheAxesNotFloored(t *testing.T) {
	for mask := range 8 {
		floored := [3]bool{mask&1 != 0, mask&2 != 0, mask&4 != 0}
		want := []string{"opportunity"}
		for axis, name := range axisNames {
			if !floored[axis] {
				want = append(want, name)
			}
		}
		request := text(t)(AdjustmentRequest(base(), conflicting, floored, adjustFlags, adjustGiven))
		questions := strings.Split(strings.Split(request, "\nQUESTIONS\n")[1], "\n\n")[0]
		var asked []string
		for _, line := range strings.Split(questions, "\n") {
			name, _, _ := strings.Cut(line, ":")
			asked = append(asked, name)
		}
		var s struct{ Required []string }
		if err := json.Unmarshal([]byte(data(t)(AdjustmentSchema(floored))), &s); err != nil {
			t.Fatal(err)
		}
		reply := `Reply with {"reasoning": "...", "` + strings.Join(want, `": "...", "`) + `": "..."}.`
		if !slices.Equal(asked, want) || !slices.Equal(s.Required, append([]string{"reasoning"}, want...)) || !strings.HasSuffix(request, reply) {
			t.Errorf("floored %v: asks %v, requires %v, ends %q", floored, asked, s.Required, request[strings.LastIndex(request, "\n")+1:])
		}
	}
}

func TestSystemPromptLeavesOutWhatIsUnset(t *testing.T) {
	d := base()
	for _, listener := range []Setting{{}, {Value: "unknown", Meaning: "not stated"}} {
		d.Listener = listener
		got := text(t)(SystemPrompt(d))
		want := "DEPLOYMENT\nProject: svc\nExposure: internet (Publicly accessible). The attacker group to consider is anonymous Internet users.\n\nJudge"
		if !strings.Contains(got, want) {
			t.Errorf("listener %q:\n%s", listener.Value, got)
		}
	}
}

// A value holding a placeholder's name is sent as written.
func TestValuesAreSentAsWritten(t *testing.T) {
	d := base()
	d.Notes = "Reached by {group} through {entries}."
	d.Frameworks = []string{"{question}"}
	if got := text(t)(SystemPrompt(d)); !strings.Contains(got, "Notes: Reached by {group} through {entries}.\n") {
		t.Errorf("the notes changed:\n%s", got)
	}
	if got := text(t)(Request(NC, d, cvssBatch)); !strings.Contains(got, "This service must comply with {question}. If anonymous Internet users") {
		t.Errorf("the framework changed:\n%s", got)
	}
}

func TestRenderRefusesWhatItCannotSend(t *testing.T) {
	bad := base()
	bad.Exposure.Value = "public"
	for name, err := range map[string]error{
		"a factor with no question": second(Request("SL", base(), cvssBatch)),
		"NC with no framework":      second(Request(NC, base(), cvssBatch)),
		"an empty batch":            second(Request(M, base(), nil)),
		"a CVE twice":               second(Request(M, base(), []CVE{conflicting, conflicting})),
		"a CVE with no row":         second(Request(M, base(), []CVE{{ID: "CVE-X"}})),
		"a CVE with no id":          second(Request(M, base(), []CVE{{Rows: []Row{{}}}})),
		"an invalid deployment":     second(Request(M, bad, cvssBatch)),
		"a system prompt for it":    second(SystemPrompt(bad)),
		"a schema with no CVE":      second(Schema(M, nil)),
		"a schema with an id twice": second(Schema(M, []string{"CVE-C", "CVE-C"})),
		"a schema with an empty id": second(Schema(M, []string{""})),
		"a schema for no question":  second(Schema("S", []string{"CVE-C"})),
		"an adjustment unflagged":   second(AdjustmentRequest(base(), conflicting, [3]bool{}, nil, adjustGiven)),
		"an unknown flag":           second(AdjustmentRequest(base(), conflicting, [3]bool{}, []Flag{{Name: "suspicious"}}, adjustGiven)),
		"an adjustment of no CVE":   second(AdjustmentRequest(base(), CVE{}, [3]bool{}, adjustFlags, adjustGiven)),
		"an adjustment for it":      second(AdjustmentRequest(bad, conflicting, [3]bool{}, adjustFlags, adjustGiven)),
	} {
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func second[T any](_ T, err error) error { return err }
