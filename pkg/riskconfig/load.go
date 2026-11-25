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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"

	"go.yaml.in/yaml/v3"
)

// migrating is the address the schema-version errors give for the migration
// notes.
const migrating = "https://venslabs.github.io/vens/reference/config-schema/#migrating"

// reconfirm is what the schema-1 errors say of business_criticality: a file
// that only gains the marker keeps a value whose meaning has changed.
const reconfirm = "business_criticality keeps its values with a new meaning, " +
	"the worst Financial damage and Reputation damage an exploit could cost: reconfirm yours"

// loadError is a load error with its number, the one a docs block's
// `<!-- docs-check: E<n> -->` marker names: 1 no schema_version, 2 another
// version, 3 an unknown key, 4 a listener, data_subjects or traceability that
// cannot load, 5 a detection that cannot.
type loadError struct {
	code int
	msg  string
}

func (e *loadError) Error() string { return e.msg }

var (
	errEmpty           = errors.New("config.yaml is empty")
	errNoSchemaVersion = &loadError{1, "config.yaml has no schema_version: it was written for vens v0.6 or earlier (schema 1). " +
		"This vens reads schema 2, which scores each OWASP factor on its own: audit_requirement and controls ids/siem/edr " +
		"no longer move any score, listener, data_subjects, detection and traceability are new, and " + reconfirm + ". " +
		"Read " + migrating + ", then add `schema_version: 2` at the top of the file."}
	errSchemaVersion1 = &loadError{2, "schema_version 1 is not supported: this vens reads schema 2 only, in which " + reconfirm + ". " +
		"Read " + migrating + ", then set `schema_version: 2`."}
	errNoChannels  = &loadError{5, "context.detection has no channels: declare network, host and application, or remove the key"}
	errNotChannels = &loadError{5, "context.detection must be a mapping of network, host and application"}

	newerVersion = regexp.MustCompile(`^[1-9][0-9]*$`)

	// lineBreaks are the line breaks yaml.v3 counts when it numbers lines.
	lineBreaks = strings.NewReplacer("\r\n", "\n", "\r", "\n", "\u0085", "\n", "\u2028", "\n", "\u2029", "\n")
)

// rootMapping returns the top-level mapping of the file's one document,
// aliases resolved. A second document is refused: decoding reads the first
// only, so whatever a second one holds would be ignored without a word.
func rootMapping(b []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errEmpty
		}
		return nil, err
	}
	var next yaml.Node
	switch err := dec.Decode(&next); {
	case err == nil:
		return nil, fmt.Errorf("config.yaml line %d: a second YAML document starts here; config.yaml must hold a single document", next.Line)
	case !errors.Is(err, io.EOF):
		return nil, err
	}
	root := resolve(doc.Content[0])
	switch {
	case isNull(root):
		return nil, errEmpty
	case root.Kind != yaml.MappingNode:
		return nil, fmt.Errorf("config.yaml must be a mapping of schema_version, project and context, got %s", asWritten(root))
	}
	return root, nil
}

// checkSchemaVersion reads the marker before anything else, so that a file
// written for another schema gets E1 or E2 and never an error of this one.
func checkSchemaVersion(root *yaml.Node, src []byte) error {
	v, ok, err := lookup(root, "schema_version")
	switch {
	case err != nil:
		return err
	case !ok:
		return errNoSchemaVersion
	}
	// The marker is read as written: yaml.v3 decodes 2.0, 2.5, 0x2, +2 and
	// !!int "2" into an int as 2, and resolves a plain integer too large for
	// one as a float.
	plain := v.Kind == yaml.ScalarNode && v.Style == 0
	switch {
	case plain && v.Value == "2":
		// yaml.v3 drops a bare ! tag, so only the source tells `! 2` from 2.
		written, tagged, found := writtenMarker(src, v)
		switch {
		case !found:
			return &loadError{2, fmt.Sprintf("schema_version must be the integer 2, written plain; vens cannot read it at line %d of the file", v.Line)}
		case tagged:
			return &loadError{2, "schema_version must be the integer 2, got " + written}
		}
		return nil
	case plain && v.Value == "1":
		return errSchemaVersion1
	case plain && newerVersion.MatchString(v.Value):
		return &loadError{2, fmt.Sprintf("schema_version %s is not supported: this vens reads schema 2; the file needs a newer vens.", v.Value)}
	}
	return &loadError{2, "schema_version must be the integer 2, got " + asWritten(v)}
}

// writtenMarker reads the marker as the file writes it from the node's place:
// its properties, anchor and tag in any order and over line breaks and
// comments, then its value. found is false when that place does not hold a
// value of 2, which a file yaml.v3 has read does not cause; the caller then
// refuses the file rather than guess.
func writtenMarker(src []byte, n *yaml.Node) (written string, tagged, found bool) {
	text := []rune(lineBreaks.Replace(parsedText(src)))
	i, found := position(text, n.Line, n.Column)
	if !found {
		return "", false, false
	}
	var parts []string
	for {
		i = skipBlank(text, i)
		if i == len(text) || (text[i] != '&' && text[i] != '!') {
			break
		}
		end := tokenEnd(text, i)
		parts = append(parts, string(text[i:end]))
		tagged = tagged || text[i] == '!'
		i = end
	}
	if string(text[i:tokenEnd(text, i)]) != "2" {
		return "", false, false
	}
	return strings.Join(append(parts, "2"), " "), tagged, true
}

// parsedText returns the text yaml.v3 parses from src: UTF-16 decoded by its
// byte-order mark, a UTF-8 one dropped.
func parsedText(src []byte) string {
	switch {
	case bytes.HasPrefix(src, []byte{0xFF, 0xFE}):
		return utf16Text(src[2:], binary.LittleEndian)
	case bytes.HasPrefix(src, []byte{0xFE, 0xFF}):
		return utf16Text(src[2:], binary.BigEndian)
	}
	return strings.TrimPrefix(string(src), "\uFEFF")
}

func utf16Text(b []byte, order binary.ByteOrder) string {
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = order.Uint16(b[2*i:])
	}
	return string(utf16.Decode(units))
}

// position returns the offset in text of a 1-based line and column, which
// yaml.v3 counts in characters, not bytes.
func position(text []rune, line, col int) (int, bool) {
	if line < 1 || col < 1 {
		return 0, false
	}
	start := 0
	for range line - 1 {
		next := slices.Index(text[start:], '\n')
		if next < 0 {
			return 0, false
		}
		start += next + 1
	}
	length := slices.Index(text[start:], '\n')
	if length < 0 {
		length = len(text) - start
	}
	if col > length {
		return 0, false
	}
	return start + col - 1, true
}

// skipBlank skips spaces, line breaks and comments from i.
func skipBlank(text []rune, i int) int {
	for i < len(text) {
		switch text[i] {
		case ' ', '\t', '\n':
			i++
		case '#':
			for i < len(text) && text[i] != '\n' {
				i++
			}
		default:
			return i
		}
	}
	return i
}

// tokenEnd returns where the token at i ends: at a space, a line break or a
// flow indicator.
func tokenEnd(text []rune, i int) int {
	for i < len(text) && !strings.ContainsRune(" \t\n,[]{}", text[i]) {
		i++
	}
	return i
}

// checkSchema2Keys checks the shape of the four schema-2 keys before the
// decode: yaml.v3 reads a key written with no value as an omitted one, and
// names Go types where a value has the wrong kind.
func checkSchema2Keys(root *yaml.Node) error {
	ctx, ok, err := lookup(root, "context")
	if err != nil || !ok || ctx.Kind != yaml.MappingNode {
		return err
	}
	for _, f := range []Field{Listener, DataSubjects} {
		if err := checkSingleValue(ctx, f); err != nil {
			return err
		}
	}
	if err := checkDetection(ctx); err != nil {
		return err
	}
	return checkSingleValue(ctx, Traceability)
}

func checkSingleValue(ctx *yaml.Node, f Field) error {
	v, ok, err := lookup(ctx, string(f))
	switch {
	case err != nil || !ok:
		return err
	case v.Kind == yaml.SequenceNode || v.Kind == yaml.MappingNode:
		return &loadError{4, fmt.Sprintf("%s must be a single value, one of %v", f.Path(), f.Values())}
	case isNull(v), f == Listener && decodesBlank(v):
		return &loadError{4, fmt.Sprintf("%s has no value: write one of %v or remove the key", f.Path(), f.Values())}
	}
	return nil
}

// decodesBlank reports whether scalar v decodes to a string that trims to
// empty. The decoded string, not the node's text, is what validation reads:
// `!!binary IA==` is a space.
func decodesBlank(v *yaml.Node) bool {
	var s string
	return v.Decode(&s) == nil && strings.TrimSpace(s) == ""
}

func checkDetection(ctx *yaml.Node) error {
	d, ok, err := lookup(ctx, "detection")
	switch {
	case err != nil || !ok:
		return err
	case isNull(d), d.Kind == yaml.MappingNode && len(d.Content) == 0:
		return errNoChannels
	case d.Kind != yaml.MappingNode:
		return errNotChannels
	}
	for _, f := range []Field{DetectionNetwork, DetectionHost, DetectionApplication} {
		_, channel, _ := strings.Cut(string(f), ".")
		v, ok, err := lookup(d, channel)
		if err != nil {
			return err
		}
		if ok && (v.Kind == yaml.SequenceNode || v.Kind == yaml.MappingNode) {
			return &loadError{5, fmt.Sprintf("%s must be a single value, one of %v", f.Path(), f.Values())}
		}
	}
	return nil
}

// checkKnownKeys refuses the first key that no field of t decodes, naming
// its line and YAML path. It descends only into struct fields, so its depth
// is the structs' and an alias cannot make it recurse for ever.
func checkKnownKeys(m *yaml.Node, t reflect.Type, path string) error {
	pairs, err := entries(m)
	if err != nil {
		return err
	}
	keys := yamlKeys(t)
	for _, p := range pairs {
		ft, ok := keys[p.key.Value]
		if !ok {
			where := "at the top level"
			if path != "" {
				where = "under " + path
			}
			return &loadError{3, fmt.Sprintf("config.yaml line %d: unknown key `%s` %s", p.at.Line, p.key.Value, where)}
		}
		if ft.Kind() == reflect.Struct && p.value.Kind == yaml.MappingNode {
			if err := checkKnownKeys(p.value, ft, strings.TrimPrefix(path+"."+p.key.Value, ".")); err != nil {
				return err
			}
		}
	}
	return nil
}

// yamlKeys returns each YAML key a struct type decodes and the type behind
// it, pointers followed.
func yamlKeys(t reflect.Type) map[string]reflect.Type {
	keys := map[string]reflect.Type{}
	for f := range t.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if !f.IsExported() || name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		keys[name] = ft
	}
	return keys
}

// lookup returns the value of key in mapping m, aliases resolved, the way
// yaml.v3 decodes it: a key written in m wins over one a merge key brings in.
func lookup(m *yaml.Node, key string) (*yaml.Node, bool, error) {
	pairs, err := entries(m)
	if err != nil {
		return nil, false, err
	}
	for _, p := range pairs {
		if p.key.Value == key {
			return p.value, true, nil
		}
	}
	return nil, false, nil
}

// pair is a key of a mapping and its value, aliases resolved. at is the key
// as written, whose line an error names: an alias key's name is its
// anchor's, its place is its own.
type pair struct {
	key, at, value *yaml.Node
}

// entries returns the keys and values of mapping m: its own first, then
// those each merge key brings in, in order, so that the first pair of a key
// is the one yaml.v3 decodes. Each merged mapping is read once, so repeated
// merges stay linear, and a mapping merged into its own value fails, as
// yaml.v3 fails on it, instead of recursing for ever.
func entries(m *yaml.Node) ([]pair, error) {
	var pairs []pair
	read := map[*yaml.Node]bool{m: true}
	merging := map[*yaml.Node]bool{m: true}
	var walk func(*yaml.Node) error
	walk = func(m *yaml.Node) error {
		var sources []*yaml.Node
		for i := 0; i+1 < len(m.Content); i += 2 {
			k, v := m.Content[i], m.Content[i+1]
			if isMergeKey(k) {
				sources = append(sources, mergeSources(v)...)
				continue
			}
			pairs = append(pairs, pair{resolve(k), k, resolve(v)})
		}
		for _, src := range sources {
			target := resolve(src)
			switch {
			case merging[target]:
				return fmt.Errorf("config.yaml line %d: anchor '%s' is merged into its own value", src.Line, src.Value)
			case read[target] || target.Kind != yaml.MappingNode:
				continue
			}
			read[target], merging[target] = true, true
			if err := walk(target); err != nil {
				return err
			}
			delete(merging, target)
		}
		return nil
	}
	return pairs, walk(m)
}

// isMergeKey reports whether k is a merge key as yaml.v3 reads one: the
// scalar << with the merge tag. A !!merge tag on another key is no merge.
func isMergeKey(k *yaml.Node) bool {
	return k.Kind == yaml.ScalarNode && k.Value == "<<" && k.ShortTag() == "!!merge"
}

// mergeSources returns what a merge key's value names: the value itself, or
// each item of a sequence. yaml.v3 refuses anything but mappings there when
// it decodes.
func mergeSources(v *yaml.Node) []*yaml.Node {
	if v.Kind == yaml.SequenceNode {
		return v.Content
	}
	return []*yaml.Node{v}
}

func resolve(n *yaml.Node) *yaml.Node {
	for n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	return n
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null"
}

// asWritten renders a node for an error message the way the file writes it.
func asWritten(n *yaml.Node) string {
	switch n.Kind {
	case yaml.SequenceNode:
		return "a sequence"
	case yaml.MappingNode:
		return "a mapping"
	}
	value := n.Value
	switch {
	case n.Style&yaml.DoubleQuotedStyle != 0:
		value = strconv.Quote(value)
	case n.Style&yaml.SingleQuotedStyle != 0:
		value = "'" + value + "'"
	case n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0:
		value = "a block scalar " + strconv.Quote(value)
	case value == "":
		return "no value"
	}
	if n.Style&yaml.TaggedStyle != 0 {
		value = n.ShortTag() + " " + value
	}
	return value
}
