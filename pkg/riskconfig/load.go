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
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// migrating is the reference's migration section, which E1 and E2 point to.
const migrating = "https://venslabs.github.io/vens/reference/config-schema/#migrating"

// loadError is a load error the reference documents by number: E1 no
// schema_version, E2 another version, E3 an unknown key, E4 a listener,
// data_subjects or traceability that cannot load, E5 a detection that cannot.
type loadError struct {
	code int
	msg  string
}

func (e *loadError) Error() string { return e.msg }

var (
	errEmpty           = errors.New("config.yaml is empty")
	errNoSchemaVersion = &loadError{1, "config.yaml has no schema_version: it was written for vens v0.6 or earlier (schema 1). " +
		"This vens reads schema 2, which scores each OWASP factor on its own: audit_requirement and controls ids/siem/edr " +
		"no longer move any score, and listener, data_subjects, detection and traceability are new. " +
		"Read " + migrating + ", then add `schema_version: 2` at the top of the file."}
	errSchemaVersion1 = &loadError{2, "schema_version 1 is not supported: this vens reads schema 2 only. " +
		"Read " + migrating + ", then set `schema_version: 2`."}
	errNoChannels  = &loadError{5, "context.detection has no channels: declare network, host and application, or remove the key"}
	errNotChannels = &loadError{5, "context.detection must be a mapping of network, host and application"}

	newerVersion = regexp.MustCompile(`^[1-9][0-9]*$`)
)

// rootMapping returns the document's top-level mapping, aliases resolved.
func rootMapping(b []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, errEmpty
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
func checkSchemaVersion(root *yaml.Node) error {
	v, ok := lookup(root, "schema_version")
	if !ok {
		return errNoSchemaVersion
	}
	// yaml.v3 decodes 2.0, 2.5, 0x2 and +2 into an int as 2, so the node is
	// checked, not the decoded value.
	isInt := v.Kind == yaml.ScalarNode && v.ShortTag() == "!!int"
	switch {
	case isInt && v.Value == "2":
		return nil
	case isInt && v.Value == "1":
		return errSchemaVersion1
	case isInt && newerVersion.MatchString(v.Value):
		return &loadError{2, fmt.Sprintf("schema_version %s is not supported: this vens reads schema 2; the file needs a newer vens.", v.Value)}
	}
	return &loadError{2, "schema_version must be the integer 2, got " + asWritten(v)}
}

// checkSchema2Keys checks the shape of the four schema-2 keys before the
// decode: yaml.v3 reads a key written with no value as an omitted one, and
// names Go types where a value has the wrong kind.
func checkSchema2Keys(root *yaml.Node) error {
	ctx, ok := lookup(root, "context")
	if !ok || ctx.Kind != yaml.MappingNode {
		return nil
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
	v, ok := lookup(ctx, string(f))
	switch {
	case !ok:
		return nil
	case v.Kind == yaml.SequenceNode || v.Kind == yaml.MappingNode:
		return &loadError{4, fmt.Sprintf("%s must be a single value, one of %v", f.Path(), f.Values())}
	case isNull(v), f == Listener && strings.TrimSpace(v.Value) == "":
		return &loadError{4, fmt.Sprintf("%s has no value: write one of %v or remove the key", f.Path(), f.Values())}
	}
	return nil
}

func checkDetection(ctx *yaml.Node) error {
	d, ok := lookup(ctx, "detection")
	switch {
	case !ok:
		return nil
	case isNull(d), d.Kind == yaml.MappingNode && len(d.Content) == 0:
		return errNoChannels
	case d.Kind != yaml.MappingNode:
		return errNotChannels
	}
	for _, f := range []Field{DetectionNetwork, DetectionHost, DetectionApplication} {
		_, channel, _ := strings.Cut(string(f), ".")
		if v, ok := lookup(d, channel); ok && (v.Kind == yaml.SequenceNode || v.Kind == yaml.MappingNode) {
			return &loadError{5, fmt.Sprintf("%s must be a single value, one of %v", f.Path(), f.Values())}
		}
	}
	return nil
}

// checkKnownKeys refuses the first key, in file order, that no field of t
// decodes, naming its line and YAML path.
func checkKnownKeys(m *yaml.Node, t reflect.Type, path string) error {
	keys := yamlKeys(t)
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], resolve(m.Content[i+1])
		if k.ShortTag() == "!!merge" {
			for _, src := range mergeSources(v) {
				if err := checkKnownKeys(src, t, path); err != nil {
					return err
				}
			}
			continue
		}
		ft, ok := keys[k.Value]
		if !ok {
			where := "at the top level"
			if path != "" {
				where = "under " + path
			}
			return &loadError{3, fmt.Sprintf("config.yaml line %d: unknown key `%s` %s", k.Line, k.Value, where)}
		}
		if ft.Kind() == reflect.Struct && v.Kind == yaml.MappingNode {
			if err := checkKnownKeys(v, ft, strings.TrimPrefix(path+"."+k.Value, ".")); err != nil {
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

// lookup returns the value of key in mapping m, aliases resolved. A key
// written in m wins over one a merge key brings in, as when yaml.v3 decodes.
func lookup(m *yaml.Node, key string) (*yaml.Node, bool) {
	var merged []*yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], resolve(m.Content[i+1])
		switch {
		case k.ShortTag() == "!!merge":
			merged = append(merged, mergeSources(v)...)
		case k.Value == key:
			return v, true
		}
	}
	for _, src := range merged {
		if v, ok := lookup(src, key); ok {
			return v, true
		}
	}
	return nil, false
}

// mergeSources returns the mappings a merge key's value brings in: one
// mapping, or a sequence of them.
func mergeSources(v *yaml.Node) []*yaml.Node {
	if v.Kind == yaml.MappingNode {
		return []*yaml.Node{v}
	}
	var sources []*yaml.Node
	if v.Kind == yaml.SequenceNode {
		for _, item := range v.Content {
			if item = resolve(item); item.Kind == yaml.MappingNode {
				sources = append(sources, item)
			}
		}
	}
	return sources
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
	case value == "":
		return "no value"
	}
	if n.Style&yaml.TaggedStyle != 0 {
		value = n.ShortTag() + " " + value
	}
	return value
}
