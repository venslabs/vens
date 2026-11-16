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
	"fmt"
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The docs checks D1 to D3: the config blocks the docs show load, and the
// reference documents the keys and the wording this package holds.

const reference = "docs/reference/config-schema.md"

// block is a config example found in the docs. expect is the load error
// number a `<!-- docs-check: E<n> -->` line right above it names, 0 when the
// block must load.
type block struct {
	source string // file:line
	lang   string
	text   string
	expect int
}

var (
	fenceOpen   = regexp.MustCompile("^( *)(`{3,}|~{3,})\\s*([^`\\s]*)")
	docsCheck   = regexp.MustCompile(`^<!-- docs-check: E([1-5]) -->$`)
	preElement  = regexp.MustCompile(`(?s)<pre[^>]*>(.*?)</pre>`)
	htmlTag     = regexp.MustCompile(`<[^>]+>`)
	topLevelKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*:(\s|$)`)
	projectKey  = regexp.MustCompile(`(?m)^\s*project:`)
	contextKey  = regexp.MustCompile(`(?m)^\s*context:`)
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's directory")
		}
		dir = parent
	}
}

// readText reads a committed file with LF line ends: a Windows checkout can
// turn them into CRLF, which would hide the blank lines between paragraphs.
func readText(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(raw), "\r\n", "\n")
}

func isConfig(text string) bool {
	return projectKey.MatchString(text) && contextKey.MatchString(text)
}

// isYAMLFence reports whether a fence's info string makes it YAML: yaml,
// yml, or none. A sketch fenced as text is not a config.
func isYAMLFence(lang string) bool {
	return lang == "" || lang == "yaml" || lang == "yml"
}

// fencedBlocks returns a Markdown file's fenced code blocks, each with its
// fence's indentation removed and the error a docs-check line above names.
func fencedBlocks(name, src string) []block {
	lines := strings.Split(src, "\n")
	var blocks []block
	for i := 0; i < len(lines); i++ {
		m := fenceOpen.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		indent, fence := len(m[1]), m[2]
		var body []string
		j := i + 1
		for ; j < len(lines); j++ {
			t := strings.TrimSpace(lines[j])
			if len(t) >= len(fence) && strings.Trim(t, fence[:1]) == "" {
				break
			}
			body = append(body, lines[j][min(indent, leadingSpaces(lines[j])):])
		}
		blocks = append(blocks, block{
			source: fmt.Sprintf("%s:%d", name, i+1),
			lang:   strings.ToLower(m[3]),
			text:   strings.Join(body, "\n") + "\n",
			expect: markedError(lines, i),
		})
		i = j
	}
	return blocks
}

func leadingSpaces(s string) int {
	return len(s) - len(strings.TrimLeft(s, " "))
}

func markedError(lines []string, i int) int {
	if i == 0 {
		return 0
	}
	if m := docsCheck.FindStringSubmatch(strings.TrimSpace(lines[i-1])); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// preBlocks returns the configs inside an HTML page's <pre> elements, tags
// stripped. A <pre> on the landing page is a terminal session, so a config
// is a run of YAML lines that starts at a top-level key; blank lines between
// its keys do not end it.
func preBlocks(name, src string) []block {
	var blocks []block
	lines := strings.Split(src, "\n")
	for _, loc := range preElement.FindAllStringSubmatchIndex(src, -1) {
		start := strings.Count(src[:loc[0]], "\n")
		text := html.UnescapeString(htmlTag.ReplaceAllString(src[loc[2]:loc[3]], ""))
		textLines := strings.Split(text, "\n")
		for _, run := range yamlRuns(textLines) {
			blocks = append(blocks, block{
				source: fmt.Sprintf("%s:%d", name, start+run.first+1),
				text:   strings.Join(textLines[run.first:run.end], "\n") + "\n",
				expect: markedError(lines, start+run.first),
			})
		}
	}
	return blocks
}

// yamlRun is a run of YAML lines, from first up to end.
type yamlRun struct{ first, end int }

// yamlRuns returns the runs of YAML lines, in order. A run starts at a
// top-level key and takes keys, indented lines, list items, comments and
// blank lines, up to the first line that is none of these, such as a shell
// command or its output.
func yamlRuns(lines []string) []yamlRun {
	var runs []yamlRun
	for i := 0; i < len(lines); i++ {
		if !topLevelKey.MatchString(lines[i]) {
			continue
		}
		end := i + 1
		for end < len(lines) && isYAMLLine(lines[end]) {
			end++
		}
		runs = append(runs, yamlRun{i, end})
		i = end - 1
	}
	return runs
}

func isYAMLLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(line, "- ") ||
		len(line) > len(strings.TrimLeft(line, " \t")) || topLevelKey.MatchString(line)
}

// docsConfigBlocks finds every config the docs show: fenced YAML blocks in
// README.md, docs/ and examples/, the YAML files under examples/, and the
// <pre> blocks of overrides/*.html.
func docsConfigBlocks(t *testing.T, root string) []block {
	t.Helper()
	var blocks []block
	add := func(path string) {
		src := readText(t, path)
		name, _ := filepath.Rel(root, path)
		var found []block
		switch filepath.Ext(path) {
		case ".md":
			for _, b := range fencedBlocks(name, src) {
				if isYAMLFence(b.lang) {
					found = append(found, b)
				}
			}
		case ".yaml", ".yml":
			found = []block{{source: name + ":1", text: src}}
		case ".html":
			found = preBlocks(name, src)
		}
		for _, b := range found {
			if isConfig(b.text) {
				blocks = append(blocks, b)
			}
		}
	}
	add(filepath.Join(root, "README.md"))
	for _, dir := range []string{"docs", "examples", "overrides"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && (dir != "overrides" || filepath.Ext(path) == ".html") {
				add(path)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return blocks
}

// checkBlock loads a block under schema 2: it must load, or fail with
// exactly the error its docs-check line names.
func checkBlock(b block) error {
	_, err := Parse([]byte(b.text))
	switch {
	case b.expect == 0 && err != nil:
		return fmt.Errorf("%s does not load under schema 2: %w", b.source, err)
	case b.expect != 0 && err == nil:
		return fmt.Errorf("%s is marked E%d but loads", b.source, b.expect)
	case b.expect != 0 && errorCode(err) != b.expect:
		return fmt.Errorf("%s is marked E%d but fails with E%d: %w", b.source, b.expect, errorCode(err), err)
	}
	return nil
}

// D1.
func TestDocsConfigBlocksLoad(t *testing.T) {
	blocks := docsConfigBlocks(t, repoRoot(t))
	from := map[string]bool{}
	for _, b := range blocks {
		if err := checkBlock(b); err != nil {
			t.Error(err)
		}
		file, _, _ := strings.Cut(b.source, ":")
		from[strings.SplitN(file, string(filepath.Separator), 2)[0]] = true
		from[filepath.Ext(file)] = true
	}
	// Each source and each kind of block yields at least one config, so a
	// walk or an extractor that finds nothing cannot pass for clean docs.
	for _, want := range []string{"README.md", "docs", "examples", "overrides", ".md", ".yaml", ".html"} {
		if !from[want] {
			t.Errorf("no config block found from %s", want)
		}
	}
}

func TestCheckBlockHonoursDocsCheckMarkers(t *testing.T) {
	old := "project:\n  name: x\ncontext:\n  exposure: internet\n  data_sensitivity: low\n  business_criticality: low\n"
	md := strings.Join([]string{
		"<!-- docs-check: E1 -->",
		"```yaml",
		old + "```",
		"<!-- docs-check: E3 -->",
		"```yaml",
		old + "```",
		"<!-- docs-check: E1 -->",
		"```yaml",
		"schema_version: 2\n" + old + "```",
		"!!! note",
		"    ```yaml",
		"    schema_version: 2",
		indent(old, "    ") + "    ```",
		"```text",
		old + "```",
	}, "\n")
	blocks := fencedBlocks("x.md", md)
	if len(blocks) != 5 {
		t.Fatalf("found %d blocks, want 5", len(blocks))
	}
	if err := checkBlock(blocks[0]); err != nil {
		t.Errorf("a block marked E1 that fails with E1: %v", err)
	}
	if err := checkBlock(blocks[1]); err == nil {
		t.Error("a block marked E3 that fails with E1 passed")
	}
	if err := checkBlock(blocks[2]); err == nil {
		t.Error("a block marked E1 that loads passed")
	}
	if err := checkBlock(blocks[3]); err != nil {
		t.Errorf("an indented block: %v", err)
	}
	if isYAMLFence(blocks[4].lang) {
		t.Error("a text fence counted as YAML")
	}

	pre := "<pre class=\"x\"><code><span># 1.</span>\ncat config.yaml\nschema_version: 2\n" + old +
		"\n<span># 2.</span>\nvens generate &amp;&amp; done</code></pre>"
	if got := preBlocks("x.html", pre); len(got) != 1 || checkBlock(got[0]) != nil {
		t.Errorf("the config in a <pre> session: %+v", got)
	}
}

// A config in a <pre> session may separate its top-level keys with blank
// lines; each example is read whole, so a broken one is caught.
func TestPreBlocksReadWholeConfigs(t *testing.T) {
	page := strings.Join([]string{
		`<p>Two examples.</p>`,
		`<pre class="vens-code"><code><span class="c"># 1. a valid config</span>`,
		`<span class="k">cat</span> config.yaml`,
		`schema_version: 2`,
		``,
		`project:`,
		`  name: my-api`,
		``,
		`context:`,
		`  exposure: internet`,
		`  data_sensitivity: high`,
		`  business_criticality: high`,
		``,
		`<span class="c"># 2. a broken one</span>`,
		`<span class="k">cat</span> broken.yaml`,
		`schema_version: 2`,
		``,
		`project:`,
		`  name: broken`,
		``,
		`context:`,
		`  exposure: everywhere`,
		`  data_sensitivity: high`,
		`  business_criticality: high`,
		`<span class="k">vens</span> generate --config-file config.yaml report.json out.json</code></pre>`,
	}, "\n")
	blocks := preBlocks("page.html", page)
	if len(blocks) != 2 {
		t.Fatalf("found %d configs, want 2: %+v", len(blocks), blocks)
	}
	if blocks[0].source != "page.html:4" || blocks[1].source != "page.html:16" {
		t.Errorf("sources %s and %s, want page.html:4 and page.html:16", blocks[0].source, blocks[1].source)
	}
	if err := checkBlock(blocks[0]); err != nil {
		t.Errorf("the valid config: %v", err)
	}
	if err := checkBlock(blocks[1]); err == nil || !strings.Contains(err.Error(), `got "everywhere"`) {
		t.Errorf("the broken config: got %v, want its invalid exposure", err)
	}
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n") + "\n"
}

// section is the text under one heading of the reference, up to the next.
type section struct {
	key    string // the heading's first code span, when it is a YAML path
	prose  []string
	tables [][][]string
}

var (
	heading = regexp.MustCompile("^#{1,6} (.*)$")
	keyPath = regexp.MustCompile(`^[a-z_]+(\.[a-z_]+)*$`)
	codeRun = regexp.MustCompile("`([^`]*)`")
)

// readReference splits the reference into sections, skipping fenced code,
// whose comment lines would read as headings.
func readReference(t *testing.T) []section {
	t.Helper()
	sections := []section{{}}
	inFence, inTable := false, false
	for _, line := range strings.Split(readText(t, filepath.Join(repoRoot(t), reference)), "\n") {
		cur := &sections[len(sections)-1]
		isRow := !inFence && strings.HasPrefix(line, "|")
		switch {
		case fenceOpen.MatchString(line):
			inFence = !inFence
		case inFence:
		case heading.MatchString(line):
			s := section{}
			if m := codeRun.FindStringSubmatch(heading.FindStringSubmatch(line)[1]); m != nil && keyPath.MatchString(m[1]) {
				s.key = m[1]
			}
			sections = append(sections, s)
		case isRow:
			if !inTable {
				cur.tables = append(cur.tables, nil)
			}
			if !separatorRow.MatchString(line) {
				cur.tables[len(cur.tables)-1] = append(cur.tables[len(cur.tables)-1], cells(line))
			}
		default:
			cur.prose = append(cur.prose, line)
		}
		inTable = isRow
	}
	return sections
}

var separatorRow = regexp.MustCompile(`^\|[\s:|-]+\|?\s*$`)

func cells(row string) []string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(row), "|"), "|")
	for i, p := range parts {
		parts[i] = plain(p)
	}
	return parts
}

// plain drops Markdown's code marks and collapses whitespace.
func plain(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "`", "")), " ")
}

func sectionFor(t *testing.T, sections []section, key string) section {
	t.Helper()
	for _, s := range sections {
		if s.key == key {
			return s
		}
	}
	t.Fatalf("%s has no section headed `%s`", reference, key)
	return section{}
}

// table returns the rows of s's first table whose header starts with first.
func (s section) table(first string) [][]string {
	for _, tb := range s.tables {
		if len(tb) > 0 && tb[0][0] == first {
			return tb[1:]
		}
	}
	return nil
}

// TestReferenceMeaningsEqualTheTable checks the reference's value tables, and
// what each field states, against the wording this package holds. Only
// audit_requirement's values are checked: no question shows its meanings.
func TestReferenceMeaningsEqualTheTable(t *testing.T) {
	sections := readReference(t)
	for _, f := range []Field{Exposure, DataSensitivity, BusinessCriticality, AvailabilityRequirement, AuditRequirement,
		Listener, DataSubjects, Detection, Traceability} {
		s := sectionFor(t, sections, f.Path())
		meanings := slices.ContainsFunc(f.Choices(), func(c Choice) bool { return c.Meaning != "" })
		var documented []string
		for _, row := range s.table("Value") {
			documented = append(documented, row[0])
			if meanings && (len(row) < 2 || row[1] != f.Meaning(row[0])) {
				t.Errorf("%s: %s %q is documented as %q, the table says %q", reference, f.Path(), row[0], row[1:], f.Meaning(row[0]))
			}
		}
		if !slices.Equal(documented, f.Values()) {
			t.Errorf("%s: %s documents %q, the table holds %q", reference, f.Path(), documented, f.Values())
		}
		if about := f.About(); about != "" && !strings.Contains(plain(strings.Join(s.prose, " ")), about) {
			t.Errorf("%s: the %s section does not say %q", reference, f.Path(), about)
		}
	}
	checkBandLevels(t, sectionFor(t, sections, DataSubjects.Path()).table("Value"))
	checkChannelMeanings(t, sectionFor(t, sections, Detection.Path()).table("Field"))
	checkControlScopes(t, sectionFor(t, sections, "context.controls").table("Field"))
}

func checkBandLevels(t *testing.T, rows [][]string) {
	t.Helper()
	for i, b := range DataSubjectsBands() {
		if i >= len(rows) || len(rows[i]) < 3 || rows[i][2] != strconv.Itoa(int(b.Level)) {
			t.Errorf("%s: data_subjects %q should cap Privacy violation at %d", reference, b.Name, b.Level)
		}
	}
}

func checkChannelMeanings(t *testing.T, rows [][]string) {
	t.Helper()
	want := map[string]string{
		"network":     DetectionNetwork.About(),
		"host":        DetectionHost.About(),
		"application": DetectionApplication.About(),
	}
	for _, row := range rows {
		if len(row) < 2 || row[1] != want[row[0]] {
			t.Errorf("%s: detection channel %q is documented as %q, the table says %q", reference, row[0], row[1:], want[row[0]])
		}
		delete(want, row[0])
	}
	for channel := range want {
		t.Errorf("%s: detection channel %q is not documented", reference, channel)
	}
}

func checkControlScopes(t *testing.T, rows [][]string) {
	t.Helper()
	for _, c := range ControlScopes() {
		i := slices.IndexFunc(rows, func(row []string) bool { return row[0] == c.Key })
		if i < 0 || len(rows[i]) < 3 || rows[i][1] != c.Description || rows[i][2] != c.Scope {
			t.Errorf("%s: control %q should read %q, scope %q", reference, c.Key, c.Description, c.Scope)
		}
	}
}

// D3.
func TestReferenceDocumentsEveryKey(t *testing.T) {
	documented := map[string]bool{}
	for _, s := range readReference(t) {
		if s.key != "" {
			documented[s.key] = true
		}
		for _, row := range s.table("Field") {
			key := row[0]
			if !strings.Contains(key, ".") && s.key != "" {
				key = s.key + "." + key
			}
			documented[key] = true
		}
	}
	keys := map[string]bool{}
	collectKeys(reflect.TypeFor[Config](), "", keys)
	for k := range keys {
		if !documented[k] {
			t.Errorf("%s does not document %s", reference, k)
		}
	}
	for k := range documented {
		if !keys[k] {
			t.Errorf("%s documents %s, which config.yaml does not have", reference, k)
		}
	}
}

func collectKeys(t reflect.Type, prefix string, out map[string]bool) {
	for name, ft := range yamlKeys(t) {
		path := strings.TrimPrefix(prefix+"."+name, ".")
		out[path] = true
		if ft.Kind() == reflect.Struct {
			collectKeys(ft, path, out)
		}
	}
}
