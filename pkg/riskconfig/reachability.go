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
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ReachabilityEntry declares, for one CVE or one component, whether the
// vulnerable code is reachable in this deployment, and where that comes
// from. vens carries the declaration into the VEX; it does not judge it, and
// it moves no score.
type ReachabilityEntry struct {
	// CVE and Component are the entry's selector, exactly one of them set: a
	// vulnerability id, or a package name as the scanner names it, both
	// matched without regard to case.
	CVE       string `yaml:"cve,omitempty"`
	Component string `yaml:"component,omitempty"`
	// Reachable is what the entry asserts. false publishes the CVE as
	// not_affected, code_not_reachable, when the entry covers every package
	// the scan lists for it; true vetoes any such entry for the same CVE.
	Reachable bool `yaml:"reachable"`
	// Provenance says where the assertion comes from, such as a tool run or a
	// review: the VEX's detail cites it.
	Provenance string `yaml:"provenance"`
}

// Selector returns the entry's selector as the reference writes it,
// "cve: <id>" or "component: <name>".
func (e ReachabilityEntry) Selector() string {
	if e.CVE != "" {
		return "cve: " + e.CVE
	}
	return "component: " + e.Component
}

// reachabilityKeys are the keys an entry may give.
var reachabilityKeys = []string{"cve", "component", "reachable", "provenance"}

// reachabilityError numbers the errors of a reachability declaration.
func reachabilityError(format string, args ...any) error {
	return &loadError{6, fmt.Sprintf(format, args...)}
}

// checkReachability checks the shape of reachability before the decode: a
// list of entries, each a mapping of the four keys alone, with exactly one
// selector, reachable written true or false, and a provenance that is not
// blank. Every value is read as written, so that no entry is guessed at.
func checkReachability(root *yaml.Node) error {
	list, ok, err := lookup(root, "reachability")
	switch {
	case err != nil || !ok:
		return err
	case isNull(list):
		return reachabilityError("reachability has no value: write a list of entries or remove the key")
	case list.Kind != yaml.SequenceNode:
		return reachabilityError("reachability must be a list of entries, got %s", asWritten(list))
	}
	for i, item := range list.Content {
		if err := checkReachabilityEntry(resolve(item), fmt.Sprintf("reachability[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

func checkReachabilityEntry(e *yaml.Node, path string) error {
	if e.Kind != yaml.MappingNode {
		return reachabilityError("%s must be a mapping of cve or component, reachable and provenance, got %s", path, asWritten(e))
	}
	pairs, err := entries(e)
	if err != nil {
		return err
	}
	values := map[string]*yaml.Node{}
	for _, p := range pairs {
		if !slices.Contains(reachabilityKeys, p.key.Value) {
			return &loadError{3, fmt.Sprintf("config.yaml line %d: unknown key `%s` under %s", p.at.Line, p.key.Value, path)}
		}
		if _, seen := values[p.key.Value]; !seen {
			values[p.key.Value] = p.value
		}
	}
	var selectors []string
	for _, key := range []string{"cve", "component"} {
		v, ok := values[key]
		if !ok {
			continue
		}
		if err := checkText(v, path+"."+key); err != nil {
			return err
		}
		selectors = append(selectors, key)
	}
	switch len(selectors) {
	case 0:
		return reachabilityError("%s gives no selector: write cve or component", path)
	case 2:
		return reachabilityError("%s gives both cve and component: an entry has one selector", path)
	}
	switch v, ok := values["reachable"]; {
	case !ok:
		return reachabilityError("%s.reachable is required: write true or false", path)
	case v.Kind != yaml.ScalarNode || v.ShortTag() != "!!bool":
		return reachabilityError("%s.reachable must be true or false, got %s", path, asWritten(v))
	}
	v, ok := values["provenance"]
	if !ok {
		return reachabilityError("%s.provenance is required: say where the assertion comes from", path)
	}
	return checkText(v, path+".provenance")
}

// checkText refuses a value that is not a string, or one that is blank.
func checkText(v *yaml.Node, path string) error {
	if v.Kind != yaml.ScalarNode || v.ShortTag() != "!!str" {
		return reachabilityError("%s must be a string, got %s", path, asWritten(v))
	}
	if decodesBlank(v) {
		return reachabilityError("%s has no value: write one or remove the key", path)
	}
	return nil
}

// normalized returns the entry with its values trimmed.
func (e ReachabilityEntry) normalized() ReachabilityEntry {
	return ReachabilityEntry{
		CVE:        strings.TrimSpace(e.CVE),
		Component:  strings.TrimSpace(e.Component),
		Reachable:  e.Reachable,
		Provenance: strings.TrimSpace(e.Provenance),
	}
}

// check applies, once trimmed, the rules Parse reads in the file: one
// selector and a provenance.
func (e ReachabilityEntry) check(path string) error {
	switch {
	case e.CVE == "" && e.Component == "":
		return reachabilityError("%s gives no selector: write cve or component", path)
	case e.CVE != "" && e.Component != "":
		return reachabilityError("%s gives both cve and component: an entry has one selector", path)
	case e.Provenance == "":
		return reachabilityError("%s.provenance is required: say where the assertion comes from", path)
	}
	return nil
}
