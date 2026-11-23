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

package riskconfig

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"go.yaml.in/yaml/v3"

	"github.com/venslabs/vens/pkg/owasp"
)

const minimal = `schema_version: 2
project:
  name: svc
context:
  exposure: internet
  data_sensitivity: high
  business_criticality: high
`

// withContext returns the minimal config with lines added under context.
func withContext(lines ...string) string {
	var b strings.Builder
	b.WriteString(minimal)
	for _, l := range lines {
		b.WriteString("  " + l + "\n")
	}
	return b.String()
}

func mustParse(t *testing.T, src string) *Config {
	t.Helper()
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse:\n%s\nerror: %v", src, err)
	}
	return cfg
}

// parseFails checks that src fails with exactly the message want and the
// reference's error number code, 0 for an error it does not number.
func parseFails(t *testing.T, src string, code int, want string) {
	t.Helper()
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatalf("Parse:\n%s\nexpected an error, got nil", src)
	}
	if err.Error() != want {
		t.Errorf("Parse:\n%s\nerror %q\nwant  %q", src, err, want)
	}
	if got := errorCode(err); got != code {
		t.Errorf("error %q is E%d, want E%d", err, got, code)
	}
	if strings.Contains(err.Error(), "cannot unmarshal") || strings.Contains(err.Error(), "riskconfig.") {
		t.Errorf("error %q names yaml's Go types", err)
	}
}

func errorCode(err error) int {
	var le *loadError
	if errors.As(err, &le) {
		return le.code
	}
	return 0
}

func ptr(s string) *string { return &s }

func TestNewEnumsAcceptEveryValue(t *testing.T) {
	read := map[Field]func(ContextHints) *string{
		Listener:     func(h ContextHints) *string { return &h.Listener },
		DataSubjects: func(h ContextHints) *string { return h.DataSubjects },
		Traceability: func(h ContextHints) *string { return h.Traceability },
	}
	for f, get := range read {
		for _, v := range f.Values() {
			for _, written := range []string{v, strings.ToUpper(v), "  " + v + " "} {
				cfg := mustParse(t, withContext(string(f)+`: "`+written+`"`))
				if got := get(cfg.Context); got == nil || *got != v {
					t.Errorf("%s: %q read as %v, want %q", f, written, got, v)
				}
			}
		}
	}
}

func TestNewEnumsRefuseAnInvalidValue(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"listener: open", `context.listener must be one of [present absent unknown], got "open"`},
		{"data_subjects: dozens", `context.data_subjects must be one of [none one_individual hundreds thousands millions], got "dozens"`},
		{`data_subjects: ""`, `context.data_subjects must be one of [none one_individual hundreds thousands millions], got ""`},
		{"traceability: full", `context.traceability must be one of [none per_request per_individual], got "full"`},
		{`traceability: "  "`, `context.traceability must be one of [none per_request per_individual], got ""`},
		{"traceability: 5", `context.traceability must be one of [none per_request per_individual], got "5"`},
	} {
		parseFails(t, withContext(tc.line), 4, tc.want)
	}
}

func TestNewKeyWrittenWithNoValue(t *testing.T) {
	listener := "context.listener has no value: write one of [present absent unknown] or remove the key"
	for _, tc := range []struct{ line, want string }{
		{"listener:", listener},
		{"listener: null", listener},
		{`listener: ""`, listener},
		{`listener: "  "`, listener},
		{"data_subjects:", "context.data_subjects has no value: write one of [none one_individual hundreds thousands millions] or remove the key"},
		{"data_subjects: ~", "context.data_subjects has no value: write one of [none one_individual hundreds thousands millions] or remove the key"},
		{"traceability:", "context.traceability has no value: write one of [none per_request per_individual] or remove the key"},
	} {
		parseFails(t, withContext(tc.line), 4, tc.want)
	}
}

// A value is checked as it decodes, not as the node writes it: `!!binary IA==`
// is a single space, which no field may load as.
func TestValueBlankOnceDecoded(t *testing.T) {
	const blank = "!!binary IA=="
	for _, tc := range []struct {
		line string
		code int
		want string
	}{
		{"listener: " + blank, 4, "context.listener has no value: write one of [present absent unknown] or remove the key"},
		{"data_subjects: " + blank, 4, `context.data_subjects must be one of [none one_individual hundreds thousands millions], got ""`},
		{"traceability: " + blank, 4, `context.traceability must be one of [none per_request per_individual], got ""`},
		{"detection: {network: " + blank + ", host: logged, application: logged}", 5,
			"context.detection.network is required once context.detection is present (values: [not_logged logged logged_and_reviewed])"},
	} {
		parseFails(t, withContext(tc.line), tc.code, tc.want)
	}
	// The same decoding gives a listener that is present.
	if cfg := mustParse(t, withContext("listener: !!binary cHJlc2VudA==")); cfg.Context.Listener != "present" {
		t.Errorf("listener = %q, want present", cfg.Context.Listener)
	}
}

func TestNewScalarKeyWrittenAsASequenceOrAMapping(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"listener: [present]", "context.listener must be a single value, one of [present absent unknown]"},
		{"data_subjects: {a: b}", "context.data_subjects must be a single value, one of [none one_individual hundreds thousands millions]"},
		{"traceability: [none]", "context.traceability must be a single value, one of [none per_request per_individual]"},
	} {
		parseFails(t, withContext(tc.line), 4, tc.want)
	}
}

func TestNewKeysOmitted(t *testing.T) {
	ctx := mustParse(t, minimal).Context
	if ctx.Listener != "unknown" || ctx.DataSubjects != nil || ctx.Detection != nil || ctx.Traceability != nil {
		t.Errorf("omitted keys read listener %q, data_subjects %v, detection %v, traceability %v; want unknown and three nils",
			ctx.Listener, ctx.DataSubjects, ctx.Detection, ctx.Traceability)
	}
}

func TestListenerEmptyInAStructLiteralReadsUnknown(t *testing.T) {
	cfg := Config{
		SchemaVersion: SchemaVersion,
		Project:       ProjectConfig{Name: "svc"},
		Context:       ContextHints{Exposure: "internet", DataSensitivity: "high", BusinessCriticality: "high"},
	}
	got, err := cfg.validated()
	if err != nil {
		t.Fatal(err)
	}
	if got.Context.Listener != "unknown" {
		t.Errorf("listener = %q, want unknown", got.Context.Listener)
	}
	if cfg.Context.Listener != "" {
		t.Errorf("validated changed its receiver: listener %q", cfg.Context.Listener)
	}
}

func TestDetectionValid(t *testing.T) {
	cfg := mustParse(t, withContext(
		"detection:",
		"  network: logged",
		"  host: Not_Logged",
		`  application: " active_in_application "`,
	))
	want := DetectionCoverage{Network: "logged", Host: "not_logged", Application: "active_in_application"}
	if cfg.Context.Detection == nil || *cfg.Context.Detection != want {
		t.Errorf("detection = %+v, want %+v", cfg.Context.Detection, want)
	}
	for _, v := range DetectionApplication.Values() {
		mustParse(t, withContext("detection: {network: not_logged, host: not_logged, application: "+v+"}"))
	}
	for _, v := range DetectionNetwork.Values() {
		mustParse(t, withContext("detection: {network: "+v+", host: "+v+", application: not_logged}"))
	}
}

func TestDetectionMissingChannelsAreAllNamed(t *testing.T) {
	three := "[not_logged logged logged_and_reviewed]"
	four := "[not_logged logged logged_and_reviewed active_in_application]"
	for _, tc := range []struct{ line, want string }{
		{"detection: {network: logged, host: logged}",
			"context.detection.application is required once context.detection is present (values: " + four + ")"},
		{"detection: {application: logged}",
			"context.detection.network is required once context.detection is present (values: " + three + "); " +
				"context.detection.host is required once context.detection is present (values: " + three + ")"},
		{`detection: {network: "", host: logged, application: logged}`,
			"context.detection.network is required once context.detection is present (values: " + three + ")"},
	} {
		parseFails(t, withContext(tc.line), 5, tc.want)
	}
	partial := Config{
		Project: ProjectConfig{Name: "svc"},
		Context: ContextHints{Exposure: "internet", DataSensitivity: "high", BusinessCriticality: "high", Detection: &DetectionCoverage{}},
	}
	if _, err := partial.validated(); errorCode(err) != 5 || strings.Count(err.Error(), "is required") != 3 {
		t.Errorf("an empty DetectionCoverage literal: got %v, want E5 naming three channels", err)
	}
}

func TestDetectionWithoutChannels(t *testing.T) {
	noChannels := "context.detection has no channels: declare network, host and application, or remove the key"
	notMapping := "context.detection must be a mapping of network, host and application"
	for _, tc := range []struct{ line, want string }{
		{"detection:", noChannels},
		{"detection: null", noChannels},
		{"detection: ~", noChannels},
		{"detection: {}", noChannels},
		{"detection: logged", notMapping},
		{"detection: [network]", notMapping},
	} {
		parseFails(t, withContext(tc.line), 5, tc.want)
	}
}

func TestDetectionChannelValues(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"detection: {network: active_in_application, host: logged, application: logged}",
			"context.detection.network: active_in_application applies to application only"},
		{"detection: {network: logged, host: active_in_application, application: logged}",
			"context.detection.host: active_in_application applies to application only"},
		{"detection: {network: logged, host: logged, application: audited}",
			`context.detection.application must be one of [not_logged logged logged_and_reviewed active_in_application], got "audited"`},
		{"detection: {network: [logged], host: logged, application: logged}",
			"context.detection.network must be a single value, one of [not_logged logged logged_and_reviewed]"},
	} {
		parseFails(t, withContext(tc.line), 5, tc.want)
	}
}

// An alias is resolved before its node is checked: the alias node itself is
// neither the integer 2, nor a scalar, nor a mapping.
func TestAliasesAreResolved(t *testing.T) {
	cfg := mustParse(t, `project:
  name: &two 2
  description: &present present
schema_version: *two
context:
  exposure: internet
  data_sensitivity: high
  business_criticality: high
  listener: *present
`)
	if cfg.Context.Listener != "present" {
		t.Errorf("listener = %q, want present", cfg.Context.Listener)
	}

	// Under strict keys the only valid home for a second detection mapping is
	// a merge source, whose own context the explicit one overrides.
	cfg = mustParse(t, `<<:
  context:
    detection: &cov {network: logged, host: logged_and_reviewed, application: not_logged}
schema_version: 2
project:
  name: svc
context:
  exposure: internet
  data_sensitivity: high
  business_criticality: high
  detection: *cov
`)
	if d := cfg.Context.Detection; d == nil || d.Host != "logged_and_reviewed" {
		t.Errorf("detection = %+v, want the anchored mapping", d)
	}

	// Anchored under an unknown key, the file fails on that key (E3), which
	// is checked after detection's shape: an unresolved alias would fail E5
	// first.
	parseFails(t, `anchors:
  cov: &cov {network: logged, host: logged, application: logged}
`+withContext("detection: *cov"), 3, "config.yaml line 1: unknown key `anchors` at the top level")
}

func TestSchemaVersion(t *testing.T) {
	body := strings.TrimPrefix(minimal, "schema_version: 2\n")
	parseFails(t, body, 1, "config.yaml has no schema_version: it was written for vens v0.6 or earlier (schema 1). "+
		"This vens reads schema 2, which scores each OWASP factor on its own: audit_requirement and controls ids/siem/edr "+
		"no longer move any score, and listener, data_subjects, detection and traceability are new. "+
		"Read https://venslabs.github.io/vens/reference/config-schema/#migrating, then add `schema_version: 2` at the top of the file.")
	parseFails(t, "schema_version: 1\n"+body, 2, "schema_version 1 is not supported: this vens reads schema 2 only. "+
		"Read https://venslabs.github.io/vens/reference/config-schema/#migrating, then set `schema_version: 2`.")
	// 99999999999999999999 does not fit an int, so yaml.v3 resolves it as a
	// float: it is still a plain decimal integer above 2.
	for _, v := range []string{"3", "10", "99999999999999999999"} {
		parseFails(t, "schema_version: "+v+"\n"+body, 2,
			"schema_version "+v+" is not supported: this vens reads schema 2; the file needs a newer vens.")
	}
	for written, shown := range map[string]string{
		"2.0": "2.0", "2.5": "2.5", `"2"`: `"2"`, "'2'": "'2'", "0x2": "0x2", "+2": "+2", "0x3": "0x3", "+3": "+3",
		"0": "0", "-2": "-2", "02": "02", "": "no value", "null": "null", "!!str 2": "!!str 2", "[2]": "a sequence",
		"!!int 2": "!!int 2", `!!int "2"`: `!!int "2"`, "!!int 3": "!!int 3", "|\n  2": `a block scalar "2\n"`, ">-\n  2": `a block scalar "2"`,
		"!!binary Mg==": "!!binary Mg==", "!<tag:yaml.org,2002:int> 2": "!!int 2",
		// yaml.v3 drops a bare ! tag; the source still shows it.
		"! 2": "! 2", "&v ! 2": "&v ! 2", "! &v 2": "! &v 2", "!   2   # the format": "! 2", "!<!> 2": "!<!> 2",
	} {
		parseFails(t, "schema_version: "+written+"\n"+body, 2, "schema_version must be the integer 2, got "+shown)
	}
	mustParse(t, "schema_version: 2 # the format\n"+body)
	mustParse(t, body+"schema_version: 2\n")
	mustParse(t, "schema_version: &v 2\n"+body)
	mustParse(t, "schema_version:\n  2\n"+body)
}

// The marker's spelling is read from the source at the node's place, which
// must hold in flow style and whatever the line breaks and encoding marks.
func TestMarkerSpellingAtItsPlace(t *testing.T) {
	flow := "{project: {name: é}, context: {exposure: internet, data_sensitivity: high, business_criticality: high}, schema_version: %s}\n"
	mustParse(t, fmt.Sprintf(flow, "2"))
	mustParse(t, strings.TrimSuffix(fmt.Sprintf(flow, "2"), "\n")+" # the format\n")
	parseFails(t, fmt.Sprintf(flow, "! 2"), 2, "schema_version must be the integer 2, got ! 2")

	mustParse(t, "\uFEFF"+minimal)
	parseFails(t, "\uFEFF"+strings.Replace(minimal, "schema_version: 2", "schema_version: ! 2", 1), 2,
		"schema_version must be the integer 2, got ! 2")
	// Each of these is a line break to yaml.v3, so the marker is on line 2.
	for name, br := range map[string]string{"CRLF": "\r\n", "CR": "\r", "NEL": "\u0085", "LS": "\u2028", "PS": "\u2029"} {
		src := "# config" + br + strings.ReplaceAll(minimal, "\n", br)
		mustParse(t, src)
		if _, err := Parse([]byte(strings.Replace(src, "schema_version: 2", "schema_version: ! 2", 1))); errorCode(err) != 2 {
			t.Errorf("%s line breaks: ! 2 gave %v, want E2", name, err)
		}
	}
}

// The marker's properties are read as a sequence from the node's place, so a
// tag on the line after an anchor, or after a comment, is still seen.
func TestMarkerPropertiesOverLines(t *testing.T) {
	body := strings.TrimPrefix(minimal, "schema_version: 2\n")
	for written, shown := range map[string]string{
		"&v\n  ! 2":        "&v ! 2",
		"&v # c\n  ! 2":    "&v ! 2",
		"!\n  2":           "! 2",
		"! # c\n  &v 2":    "! &v 2",
		"&v\n  # c\n  ! 2": "&v ! 2",
	} {
		parseFails(t, "schema_version: "+written+"\n"+body, 2, "schema_version must be the integer 2, got "+shown)
	}
	for _, written := range []string{"&v\n  2", "&v # c\n  2", "\n  # c\n  2"} {
		mustParse(t, "schema_version: "+written+"\n"+body)
	}
}

// utf16File encodes s as UTF-16 in the given byte order, behind its
// byte-order mark, as yaml.v3 reads such a file.
func utf16File(s string, order binary.ByteOrder) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2+2*len(units))
	order.PutUint16(out, 0xFEFF)
	for i, u := range units {
		order.PutUint16(out[2+2*i:], u)
	}
	return out
}

func TestMarkerInUTF16Files(t *testing.T) {
	for name, order := range map[string]binary.ByteOrder{"UTF-16LE": binary.LittleEndian, "UTF-16BE": binary.BigEndian} {
		for written, want := range map[string]string{
			"! 2":    "schema_version must be the integer 2, got ! 2",
			"&v ! 2": "schema_version must be the integer 2, got &v ! 2",
			"2":      "",
		} {
			src := utf16File(strings.Replace(minimal, "schema_version: 2", "schema_version: "+written, 1), order)
			_, err := Parse(src)
			switch {
			case want == "" && err != nil:
				t.Errorf("%s, %s: %v", name, written, err)
			case want != "" && (err == nil || err.Error() != want):
				t.Errorf("%s, %s: error %v, want %q", name, written, err, want)
			}
		}
	}
}

// A file yaml.v3 has read always shows its marker at the node's place; a
// source that does not, here one other than the file parsed, is refused
// rather than taken for a plain 2.
func TestMarkerNotFoundFailsClosed(t *testing.T) {
	root, err := rootMapping([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"", "schema_version:\n", "schema_version: 3\n", "# the marker was here\n"} {
		err := checkSchemaVersion(root, []byte(src))
		if errorCode(err) != 2 || !strings.Contains(err.Error(), "vens cannot read it at line 1 of the file") {
			t.Errorf("source %q: got %v, want E2 saying the marker cannot be read", src, err)
		}
	}
}

// A merge key that brings a mapping into its own value fails with an error
// instead of recursing until the stack overflows.
func TestMergeIntoItself(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{"context", strings.Replace(withContext("<<: *c"), "context:\n", "context: &c\n", 1),
			"config.yaml line 8: anchor 'c' is merged into its own value"},
		{"controls", withContext("controls: &d {waf: true, <<: [*d]}"),
			"config.yaml line 8: anchor 'd' is merged into its own value"},
		{"root", "&r\n" + minimal + "<<: *r\n",
			"config.yaml line 9: anchor 'r' is merged into its own value"},
		{"project", strings.Replace(minimal, "project:\n  name: svc\n", "project: &p {name: svc, <<: *p}\n", 1),
			"config.yaml line 2: anchor 'p' is merged into its own value"},
	} {
		_, err := Parse([]byte(tc.src))
		if err == nil || err.Error() != tc.want {
			t.Errorf("%s:\n%s\nerror %v\nwant  %q", tc.name, tc.src, err, tc.want)
		}
	}
	// Merging the same mapping twice, or two mappings that both merge a third,
	// is no cycle.
	mustParse(t, withContext("controls: {<<: [&base {waf: true}, *base]}"))
	mustParse(t, strings.Replace(minimal, "context:\n", "context:\n  <<: [&a {notes: x}, &b {<<: *a}, {<<: [*a, *b]}]\n", 1))
}

func TestOneDocumentOnly(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{"a second document holding a key", minimal + "---\ncontext:\n  tracability: none\n",
			"config.yaml line 8: a second YAML document starts here; config.yaml must hold a single document"},
		{"an empty second document", minimal + "---\n",
			"config.yaml line 8: a second YAML document starts here; config.yaml must hold a single document"},
		{"an empty first document", "---\n---\n" + minimal,
			"config.yaml line 2: a second YAML document starts here; config.yaml must hold a single document"},
	} {
		_, err := Parse([]byte(tc.src))
		if err == nil || err.Error() != tc.want {
			t.Errorf("%s: error %v, want %q", tc.name, err, tc.want)
		}
	}
	mustParse(t, "---\n"+minimal)
	mustParse(t, minimal+"...\n")
}

func TestUnknownKeys(t *testing.T) {
	for _, tc := range []struct{ src, want string }{
		{"versions: 2\n" + minimal, "config.yaml line 1: unknown key `versions` at the top level"},
		{strings.Replace(minimal, "  name: svc\n", "  name: svc\n  owner: me\n", 1), "config.yaml line 4: unknown key `owner` under project"},
		{withContext("tracability: none"), "config.yaml line 8: unknown key `tracability` under context"},
		{withContext(`compliance_requirement: ["PCI-DSS"]`), "config.yaml line 8: unknown key `compliance_requirement` under context"},
		{withContext("controls:", "  waf: true", "  firewall: true"), "config.yaml line 10: unknown key `firewall` under context.controls"},
		{withContext("detection:", "  network: logged", "  host: logged", "  application: logged", "  cloud: logged"),
			"config.yaml line 12: unknown key `cloud` under context.detection"},
		{withContext("<<: {exposure: internet, exposed: true}"), "config.yaml line 8: unknown key `exposed` under context"},
		// An alias key is named by its anchor and placed where it is written.
		{strings.Replace(withContext("? *k", ": per_request"), "  name: svc\n", "  name: svc\n  description: &k tracability\n", 1),
			"config.yaml line 9: unknown key `tracability` under context"},
		// Only the scalar << is a merge key, whatever tag another key carries.
		{withContext("!!merge x: {exposure: internet}"), "config.yaml line 8: unknown key `x` under context"},
	} {
		parseFails(t, tc.src, 3, tc.want)
	}
	old := strings.TrimPrefix(withContext("tracability: none"), "schema_version: 2\n")
	if _, err := Parse([]byte(old)); errorCode(err) != 1 {
		t.Errorf("a config without schema_version and with an unknown key: got %v, want E1", err)
	}
	mustParse(t, withContext("<<: {notes: merged}"))
}

// A key written in the mapping wins over a merged one, and an earlier merge
// over a later one, in the checks as in the decode: the value the checks
// read is the one that loads.
func TestMergePrecedence(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"listener: present\n  <<: {listener: }", "present"},
		{"<<: [{listener: absent}, {listener: }]", "absent"},
	} {
		if got := mustParse(t, withContext(tc.name)).Context.Listener; got != tc.want {
			t.Errorf("%s: listener = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestEmptyOrNotAMapping(t *testing.T) {
	for _, src := range []string{"", "\n", "# only a comment\n", "---\n", "null\n", "~\n"} {
		parseFails(t, src, 0, "config.yaml is empty")
	}
	parseFails(t, "- project\n", 0, "config.yaml must be a mapping of schema_version, project and context, got a sequence")
	parseFails(t, "project\n", 0, "config.yaml must be a mapping of schema_version, project and context, got project")
}

// TestSchema1FieldsUnchanged loads a config that only adds the marker to a
// schema-1 file and checks each field holds what vens 9ac9ef4's parser read.
func TestSchema1FieldsUnchanged(t *testing.T) {
	cfg := mustParse(t, `schema_version: 2
project:
  name: " My Service "
  description: Payments API
context:
  exposure: " Internet "
  data_sensitivity: HIGH
  business_criticality: Critical
  availability_requirement: " High"
  compliance_requirements: [pci-dss, GDPR]
  audit_requirement: MEDIUM
  controls:
    waf: true
    ids: true
    zero_trust: true
  notes: |
    Two lines
    of notes.
`)
	want := Config{
		SchemaVersion: 2,
		Project:       ProjectConfig{Name: " My Service ", Description: "Payments API"},
		Context: ContextHints{
			Exposure:                "internet",
			DataSensitivity:         "high",
			BusinessCriticality:     "critical",
			AvailabilityRequirement: ptr("high"),
			ComplianceRequirements:  []string{"pci-dss", "GDPR"},
			AuditRequirement:        ptr("medium"),
			Listener:                "unknown",
			Controls:                SecurityControls{WAF: true, IDS: true, ZeroTrust: true},
			Notes:                   "Two lines\nof notes.\n",
		},
	}
	if !reflect.DeepEqual(*cfg, want) {
		t.Errorf("parsed\n%+v\nwant\n%+v", *cfg, want)
	}
}

func TestSchema1Errors(t *testing.T) {
	for _, tc := range []struct{ src, want string }{
		{strings.Replace(minimal, "  name: svc\n", "  description: x\n", 1), "project.name is required"},
		{strings.Replace(minimal, "  exposure: internet\n", "", 1), "context.exposure is required (valid values: [internal private internet])"},
		{strings.Replace(minimal, "  data_sensitivity: high\n", "", 1), "context.data_sensitivity is required (valid values: [low medium high critical])"},
		{strings.Replace(minimal, "  business_criticality: high\n", "", 1), "context.business_criticality is required (valid values: [low medium high critical])"},
		{strings.Replace(minimal, "exposure: internet", "exposure: public", 1), `context.exposure must be one of [internal private internet], got "public"`},
		{strings.Replace(minimal, "exposure: internet", `exposure: "  "`, 1), `context.exposure must be one of [internal private internet], got ""`},
		{withContext("availability_requirement: always"), `context.availability_requirement must be one of [low medium high critical], got "always"`},
		{withContext("audit_requirement: forensic"), `context.audit_requirement must be one of [low medium high], got "forensic"`},
		{withContext(`compliance_requirements: [GDPR, "PCI DSS"]`),
			`context.compliance_requirements contains unknown framework "PCI DSS" (valid: [PCI-DSS HIPAA GDPR SOX ISO27001 FedRAMP NIST CCPA SOC2 FISMA ITAR CMMC])`},
		// Schema 1 matched lowercased names: the long s of ſOX folds to s under
		// Unicode case folding, not under lowercasing.
		{withContext(`compliance_requirements: ["ſOX"]`),
			`context.compliance_requirements contains unknown framework "ſOX" (valid: [PCI-DSS HIPAA GDPR SOX ISO27001 FedRAMP NIST CCPA SOC2 FISMA ITAR CMMC])`},
	} {
		parseFails(t, tc.src, 0, tc.want)
	}
	if cfg := mustParse(t, withContext("compliance_requirements: [sox, Pci-Dss]")); !slices.Equal(cfg.Context.ComplianceRequirements, []string{"sox", "Pci-Dss"}) {
		t.Errorf("compliance = %q, want the names as written", cfg.Context.ComplianceRequirements)
	}
	// A v1 optional key written with no value still reads as unset.
	if cfg := mustParse(t, withContext("availability_requirement:", "audit_requirement:")); cfg.Context.AvailabilityRequirement != nil || cfg.Context.AuditRequirement != nil {
		t.Errorf("v1 keys with no value: availability %v, audit %v, want nil", cfg.Context.AvailabilityRequirement, cfg.Context.AuditRequirement)
	}
}

const declaredAll = `listener: absent
  data_subjects: thousands
  detection: {network: logged, host: not_logged, application: logged_and_reviewed}
  traceability: per_request`

func TestRoundTrip(t *testing.T) {
	for _, src := range []string{
		minimal,
		withContext(declaredAll, "availability_requirement: low", "compliance_requirements: [gdpr]",
			"audit_requirement: high", "controls: {waf: true, siem: true}", "notes: n"),
		withReachability("- cve: CVE-1", "  reachable: false", "  provenance: p", "- component: a", "  reachable: true", "  provenance: q"),
	} {
		cfg := mustParse(t, src)
		out, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		again := mustParse(t, string(out))
		if !reflect.DeepEqual(cfg, again) {
			t.Errorf("round trip of\n%s\ngave\n%+v\nwant\n%+v", out, again, cfg)
		}
	}
}

func TestWarnings(t *testing.T) {
	const (
		w1 = "context.audit_requirement no longer moves any score, and context.traceability is not declared: Loss of accountability uses its `none` column, 7 when the attacker must authenticate and cannot act as someone else or tamper with the records, 9 otherwise."
		w2 = "controls ids/siem/edr give no detection credit, and context.detection is not declared: every channel counts as not logged, so Intrusion detection is 9 on every finding."
		w3 = "context.traceability is not declared: Loss of accountability uses its `none` column, 7 or 9 on every finding."
		w4 = "context.detection is not declared: every channel counts as not logged, so Intrusion detection is 9 on every finding."
		w5 = "context.data_subjects is not declared: Privacy violation has no cap, so the model's band stands wherever Privacy violation is asked."
	)
	for _, tc := range []struct {
		name  string
		lines []string
		want  []string
	}{
		{"nothing declared", nil, []string{w3, w4, w5}},
		{"audit set", []string{"audit_requirement: high"}, []string{w1, w4, w5}},
		{"ids on", []string{"controls: {ids: true}"}, []string{w2, w3, w5}},
		{"siem on", []string{"controls: {siem: true}"}, []string{w2, w3, w5}},
		{"edr on", []string{"controls: {edr: true}"}, []string{w2, w3, w5}},
		{"other controls on", []string{"controls: {waf: true, antivirus: true}"}, []string{w3, w4, w5}},
		{"the quickstart's", []string{"audit_requirement: high", "controls: {waf: true, ids: true, siem: true}"}, []string{w1, w2, w5}},
		{"four declared", []string{declaredAll, "audit_requirement: high", "controls: {ids: true, edr: true}"}, nil},
		{"worst cases declared", []string{"data_subjects: millions", "traceability: none",
			"detection: {network: not_logged, host: not_logged, application: not_logged}"}, nil},
		{"traceability alone", []string{"traceability: per_individual", "audit_requirement: low"}, []string{w4, w5}},
		{"detection alone", []string{"detection: {network: logged, host: logged, application: logged}", "controls: {ids: true}"}, []string{w3, w5}},
		{"data_subjects alone", []string{"data_subjects: none"}, []string{w3, w4}},
	} {
		cfg := mustParse(t, withContext(tc.lines...))
		if got := cfg.Warnings(); !slices.Equal(got, tc.want) {
			t.Errorf("%s: warnings\n%q\nwant\n%q", tc.name, got, tc.want)
		}
		if got, want := len(cfg.Warnings()), len(cfg.Undeclared()); got != want {
			t.Errorf("%s: %d warnings for %d undeclared fields", tc.name, got, want)
		}
	}
}

func TestUndeclared(t *testing.T) {
	if got, want := mustParse(t, minimal).Undeclared(), []string{"context.data_subjects", "context.detection", "context.traceability"}; !slices.Equal(got, want) {
		t.Errorf("Undeclared() = %q, want %q", got, want)
	}
	if got := mustParse(t, withContext(declaredAll)).Undeclared(); got != nil {
		t.Errorf("Undeclared() = %q, want none", got)
	}
	var literal Config
	if got := literal.Undeclared(); len(got) != 3 {
		t.Errorf("a struct literal's Undeclared() = %q, want three paths without Parse", got)
	}
}

func TestEnable(t *testing.T) {
	for key := range yamlKeys(reflect.TypeFor[SecurityControls]()) {
		got, ok := SecurityControls{}.Enable(key)
		if !ok {
			t.Errorf("Enable(%q) found no control", key)
			continue
		}
		out, err := yaml.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if want := key + ": true\n"; string(out) != want {
			t.Errorf("Enable(%q) set\n%s\nwant\n%s", key, out, want)
		}
	}
	if _, ok := (SecurityControls{}).Enable("firewall"); ok {
		t.Error(`Enable("firewall") found a control`)
	}
}

// Enabled reads the control a config sets by its YAML key, and no other.
func TestEnabled(t *testing.T) {
	keys := yamlKeys(reflect.TypeFor[SecurityControls]())
	for key := range keys {
		var s SecurityControls
		if err := yaml.Unmarshal([]byte(key+": true"), &s); err != nil {
			t.Fatal(err)
		}
		for other := range keys {
			if got := s.Enabled(other); got != (other == key) {
				t.Errorf("with %s set, Enabled(%q) = %t", key, other, got)
			}
		}
	}
	for key := range keys {
		if (SecurityControls{}).Enabled(key) {
			t.Errorf("Enabled(%q) is true with nothing set", key)
		}
	}
	all := SecurityControls{WAF: true, DDoSProtection: true, IDS: true, SIEM: true, EDR: true, Antivirus: true, Segmentation: true, ZeroTrust: true}
	if all.Enabled("firewall") {
		t.Error(`Enabled("firewall") is true`)
	}
}

func TestFieldValuesInTheirOrder(t *testing.T) {
	for f, want := range map[Field][]string{
		Exposure:                {"internal", "private", "internet"},
		DataSensitivity:         {"low", "medium", "high", "critical"},
		BusinessCriticality:     {"low", "medium", "high", "critical"},
		AvailabilityRequirement: {"low", "medium", "high", "critical"},
		AuditRequirement:        {"low", "medium", "high"},
		Listener:                {"present", "absent", "unknown"},
		DataSubjects:            {"none", "one_individual", "hundreds", "thousands", "millions"},
		Detection:               {"not_logged", "logged", "logged_and_reviewed", "active_in_application"},
		DetectionNetwork:        {"not_logged", "logged", "logged_and_reviewed"},
		DetectionHost:           {"not_logged", "logged", "logged_and_reviewed"},
		DetectionApplication:    {"not_logged", "logged", "logged_and_reviewed", "active_in_application"},
		Traceability:            {"none", "per_request", "per_individual"},
	} {
		if got := f.Values(); !slices.Equal(got, want) {
			t.Errorf("%s.Values() = %q, want %q", f, got, want)
		}
	}
	if got := len(ComplianceFrameworks()); got != 12 {
		t.Errorf("%d compliance frameworks, want 12", got)
	}
	if got, want := keys(ControlScopes()), []string{"waf", "ddos_protection", "segmentation", "zero_trust", "antivirus"}; !slices.Equal(got, want) {
		t.Errorf("ControlScopes() keys = %q, want %q", got, want)
	}
}

func keys(controls []Control) []string {
	out := make([]string, len(controls))
	for i, c := range controls {
		out[i] = c.Key
	}
	return out
}

func TestBands(t *testing.T) {
	want := []Band{
		{"none", "0", owasp.PrivacyViolationOneIndividual},
		{"one_individual", "1", owasp.PrivacyViolationOneIndividual},
		{"hundreds", "2 to 999", owasp.PrivacyViolationHundredsOfPeople},
		{"thousands", "1,000 to 999,999", owasp.PrivacyViolationThousandsOfPeople},
		{"millions", "1,000,000 or more", owasp.PrivacyViolationMillionsOfPeople},
	}
	if got := DataSubjectsBands(); !slices.Equal(got, want) {
		t.Errorf("DataSubjectsBands() = %+v, want %+v", got, want)
	}
	if got, want := levels(DataSubjectsBands()), []int{3, 3, 5, 7, 9}; !slices.Equal(got, want) {
		t.Errorf("band levels = %v, want %v", got, want)
	}
	for _, b := range DataSubjectsBands() {
		if DataSubjects.Meaning(b.Name) != b.People {
			t.Errorf("data_subjects %q means %q, want its band's %q", b.Name, DataSubjects.Meaning(b.Name), b.People)
		}
	}
}

func levels(bands []Band) []int {
	out := make([]int, len(bands))
	for i, b := range bands {
		out[i] = int(b.Level)
	}
	return out
}

func TestAccessorsReturnCopies(t *testing.T) {
	DataSubjectsBands()[0].Name = "x"
	ControlScopes()[0].Scope = "x"
	ComplianceFrameworks()[0] = "x"
	Exposure.Choices()[0].Value = "x"
	Exposure.Values()[0] = "x"
	if DataSubjectsBands()[0].Name != "none" || ControlScopes()[0].Scope == "x" || ComplianceFrameworks()[0] != "PCI-DSS" ||
		Exposure.Values()[0] != "internal" {
		t.Error("an accessor returned the package's own slice")
	}
}

// withReachability returns the minimal config with lines added under a
// top-level reachability key.
func withReachability(lines ...string) string {
	var b strings.Builder
	b.WriteString(minimal)
	b.WriteString("reachability:\n")
	for _, l := range lines {
		b.WriteString("  " + l + "\n")
	}
	return b.String()
}

func TestReachabilityEntriesLoad(t *testing.T) {
	cfg := mustParse(t, withReachability(
		"- cve: ' CVE-2024-24790 '",
		"  reachable: false",
		"  provenance: \" govulncheck, no call path \"",
		"- component: libssl3",
		"  reachable: true",
		"  provenance: pentest",
	))
	want := []ReachabilityEntry{
		{CVE: "CVE-2024-24790", Reachable: false, Provenance: "govulncheck, no call path"},
		{Component: "libssl3", Reachable: true, Provenance: "pentest"},
	}
	if !reflect.DeepEqual(cfg.Reachability, want) {
		t.Errorf("reachability = %+v, want %+v", cfg.Reachability, want)
	}
	if got := []string{want[0].Selector(), want[1].Selector()}; !slices.Equal(got, []string{"cve: CVE-2024-24790", "component: libssl3"}) {
		t.Errorf("selectors %q", got)
	}
	if cfg := mustParse(t, minimal+"reachability: []\n"); cfg.Reachability != nil {
		t.Errorf("an empty list: %+v", cfg.Reachability)
	}
	if cfg := mustParse(t, minimal); cfg.Reachability != nil {
		t.Errorf("no key: %+v", cfg.Reachability)
	}
}

// Each entry gives exactly one selector, reachable written true or false, and
// a provenance that is not blank, all strings but reachable; a key other than
// the four is unknown. Every refusal names the entry.
func TestReachabilityEntriesRefused(t *testing.T) {
	for _, tc := range []struct {
		lines []string
		code  int
		want  string
	}{
		{[]string{"- reachable: false", "  provenance: p"}, 6, "reachability[0] gives no selector: write cve or component"},
		{[]string{"- cve: CVE-1", "  component: a", "  reachable: false", "  provenance: p"}, 6,
			"reachability[0] gives both cve and component: an entry has one selector"},
		{[]string{"- cve: CVE-1", "  reachable: false", "  provenance: p", "- cve: CVE-2", "  component: a", "  reachable: true", "  provenance: p"}, 6,
			"reachability[1] gives both cve and component: an entry has one selector"},
		{[]string{"- cve: CVE-1", "  provenance: p"}, 6, "reachability[0].reachable is required: write true or false"},
		{[]string{"- cve: CVE-1", "  reachable: no", "  provenance: p"}, 6, "reachability[0].reachable must be true or false, got no"},
		{[]string{"- cve: CVE-1", "  reachable: \"false\"", "  provenance: p"}, 6, `reachability[0].reachable must be true or false, got "false"`},
		{[]string{"- cve: CVE-1", "  reachable: false"}, 6, "reachability[0].provenance is required: say where the assertion comes from"},
		{[]string{"- cve: CVE-1", "  reachable: false", "  provenance: '  '"}, 6, "reachability[0].provenance has no value: write one or remove the key"},
		{[]string{"- cve: CVE-1", "  reachable: false", "  provenance:"}, 6, "reachability[0].provenance must be a string, got no value"},
		{[]string{"- cve: [CVE-1]", "  reachable: false", "  provenance: p"}, 6, "reachability[0].cve must be a string, got a sequence"},
		{[]string{"- cve: 2024", "  reachable: false", "  provenance: p"}, 6, "reachability[0].cve must be a string, got 2024"},
		{[]string{"- cve: ''", "  component: a", "  reachable: false", "  provenance: p"}, 6, "reachability[0].cve has no value: write one or remove the key"},
		{[]string{"- cve: CVE-1", "  reachable: false", "  provenance: p", "  scope: all"}, 3, "config.yaml line 12: unknown key `scope` under reachability[0]"},
		{[]string{"- CVE-1"}, 6, "reachability[0] must be a mapping of cve or component, reachable and provenance, got CVE-1"},
	} {
		parseFails(t, withReachability(tc.lines...), tc.code, tc.want)
	}
	parseFails(t, minimal+"reachability:\n", 6, "reachability has no value: write a list of entries or remove the key")
	parseFails(t, minimal+"reachability:\n  cve: CVE-1\n", 6, "reachability must be a list of entries, got a mapping")
	parseFails(t, withContext("reachability: []"), 3, "config.yaml line 8: unknown key `reachability` under context")
}

// A config built in Go, not read from a file, gets the same rules once
// trimmed.
func TestReachabilityEntriesValidatedInGo(t *testing.T) {
	base := mustParse(t, minimal)
	for _, tc := range []struct {
		entry ReachabilityEntry
		want  string
	}{
		{ReachabilityEntry{Provenance: "p"}, "reachability[0] gives no selector: write cve or component"},
		{ReachabilityEntry{CVE: " ", Component: "\t", Provenance: "p"}, "reachability[0] gives no selector: write cve or component"},
		{ReachabilityEntry{CVE: "CVE-1", Component: "a", Provenance: "p"}, "reachability[0] gives both cve and component: an entry has one selector"},
		{ReachabilityEntry{CVE: "CVE-1", Provenance: "  "}, "reachability[0].provenance is required: say where the assertion comes from"},
	} {
		c := *base
		c.Reachability = []ReachabilityEntry{tc.entry}
		if _, err := c.validated(); err == nil || err.Error() != tc.want || errorCode(err) != 6 {
			t.Errorf("%+v: %v (E%d), want %q", tc.entry, err, errorCode(err), tc.want)
		}
	}
}
