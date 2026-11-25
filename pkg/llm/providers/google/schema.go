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

package google

import (
	"bytes"
	"encoding/json"
)

// orderedSchema decodes a JSON Schema for ResponseJsonSchema and gives each
// object schema with properties a propertyOrdering list naming them in the
// order the schema's bytes write them. The SDK turns the request into Go maps
// before sending it, which sorts every object's keys, so the order reaches
// Gemini through propertyOrdering, the one non-standard keyword
// ResponseJsonSchema accepts. Only properties and items are walked, the
// keywords vens' schemas nest objects with; any other value is decoded as is.
func orderedSchema(raw json.RawMessage) (any, error) {
	// Rejects exactly what a plain decode rejects, trailing data included.
	if err := json.Unmarshal(raw, new(any)); err != nil {
		return nil, err
	}
	return orderSchema(raw)
}

func orderSchema(raw json.RawMessage) (any, error) {
	obj, ok, err := readObject(raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return decode(raw)
	}
	out := make(map[string]any, len(obj.names))
	for _, name := range obj.names {
		var v any
		switch name {
		case "properties":
			v, err = orderEach(obj.values[name])
		case "items":
			v, err = orderSchema(obj.values[name])
		default:
			v, err = decode(obj.values[name])
		}
		if err != nil {
			return nil, err
		}
		out[name] = v
	}
	props, has := obj.values["properties"]
	if _, set := out["propertyOrdering"]; set || !has {
		return out, nil
	}
	p, ok, err := readObject(props)
	if err != nil {
		return nil, err
	}
	if ok && len(p.names) > 0 {
		out["propertyOrdering"] = p.names
	}
	return out, nil
}

// orderEach orders each schema of a properties object.
func orderEach(raw json.RawMessage) (any, error) {
	obj, ok, err := readObject(raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return decode(raw)
	}
	out := make(map[string]any, len(obj.names))
	for _, name := range obj.names {
		v, err := orderSchema(obj.values[name])
		if err != nil {
			return nil, err
		}
		out[name] = v
	}
	return out, nil
}

func decode(raw json.RawMessage) (any, error) {
	var v any
	err := json.Unmarshal(raw, &v)
	return v, err
}

// object holds a JSON object's member values and their names in the order
// the object's bytes write them.
type object struct {
	names  []string
	values map[string]json.RawMessage
}

// readObject reads the JSON object in raw; ok is false when raw holds another
// kind of value. A repeated name keeps its first place and its last value, as
// a plain decode keeps the last.
func readObject(raw json.RawMessage) (object, bool, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return object{}, false, err
	}
	obj := object{values: map[string]json.RawMessage{}}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return object{}, false, err
		}
		name, _ := tok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return object{}, false, err
		}
		if _, seen := obj.values[name]; !seen {
			obj.names = append(obj.names, name)
		}
		obj.values[name] = value
	}
	return obj, true, nil
}
