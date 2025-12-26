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

package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	trivytypes "github.com/fahedouch/vens/pkg/api/types"
)

// StreamCycloneDXLibraries performs a single-pass streaming parse of a CycloneDX
// SBOM JSON file to:
//  1. Read the parent PURL (metadata.component.purl) once, and
//  2. Stream the components array, forwarding only entries with type == "library".
//
// It never loads the whole SBOM in memory. When decoding metadata, once the
// component has been decoded, the rest of the metadata section is skipped to
// minimize work. This keeps both time and space complexity low.
func StreamCycloneDXLibraries(path string, cb func(trivytypes.SBOMComponent) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	dec := json.NewDecoder(f)

	// Expect root object
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("invalid CycloneDX JSON: expected object start")
	}

	parentPURL := ""

	// Iterate root keys; handle metadata (for parent PURL) and components array
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := t.(string)
		if !ok {
			return fmt.Errorf("invalid key token")
		}

		switch key {
		case "metadata":
			// Enter metadata object
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			if d, ok := tok.(json.Delim); !ok || d != '{' {
				return fmt.Errorf("invalid metadata object")
			}
			// Walk metadata keys, but stop early after component is decoded.
			consumedEnd := false
			for dec.More() {
				tk, err := dec.Token()
				if err != nil {
					return err
				}
				mkey, ok := tk.(string)
				if !ok {
					return fmt.Errorf("invalid metadata key")
				}
				if mkey == "component" {
					var tmp struct {
						PURL string `json:"purl"`
					}
					if err := dec.Decode(&tmp); err != nil {
						return err
					}
					parentPURL = tmp.PURL
					// Skip the remaining metadata fields (if any)
					for dec.More() {
						if err := skipAny(dec); err != nil {
							break
						}
					}
					// Consume '}' for metadata and break out of the metadata loop
					if _, err := dec.Token(); err != nil {
						return err
					}
					consumedEnd = true
					break
				}
				// Skip any other metadata fields without decoding
				if err := skipAny(dec); err != nil {
					return err
				}
			}
			// If we didn’t already consume '}', do it now
			if !consumedEnd {
				if _, err := dec.Token(); err != nil {
					return err
				}
			}

		case "components":
			// Enter components array
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			if d, ok := tok.(json.Delim); !ok || d != '[' {
				return fmt.Errorf("invalid components array")
			}
			for dec.More() {
				var c trivytypes.SBOMComponent
				if err := dec.Decode(&c); err != nil {
					return err
				}
				// Only `library` type for now. See: https://cyclonedx.org/docs/1.7/json/#components_items_type
				if strings.ToLower(c.Type) != "library" {
					continue
				}
				c.ParentPURL = parentPURL
				if err := cb(c); err != nil {
					return err
				}
			}
			// Consume closing ']'
			if _, err := dec.Token(); err != nil {
				return err
			}

		default:
			// Skip any other root fields
			if err := skipAny(dec); err != nil {
				return err
			}
		}
	}
	// Consume '}' of the root object
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}

// ReadParentPURL reads `metadata.component.purl` from a CycloneDX SBOM without
// loading the entire file. It uses a streaming JSON decoder to keep memory and
// CPU overhead minimal.
func ReadParentPURL(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck

	dec := json.NewDecoder(f)
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return "", fmt.Errorf("invalid CycloneDX JSON: expected object start")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return "", err
		}
		key, ok := t.(string)
		if !ok {
			return "", fmt.Errorf("invalid key token")
		}
		if key != "metadata" {
			if err := skipAny(dec); err != nil {
				return "", err
			}
			continue
		}
		// Enter the metadata object
		tok, err := dec.Token()
		if err != nil {
			return "", err
		}
		if d, ok := tok.(json.Delim); !ok || d != '{' {
			return "", fmt.Errorf("invalid metadata object")
		}
		for dec.More() {
			tk, err := dec.Token()
			if err != nil {
				return "", err
			}
			mkey, ok := tk.(string)
			if !ok {
				return "", fmt.Errorf("invalid metadata key")
			}
			if mkey == "component" {
				var tmp struct {
					PURL string `json:"purl"`
				}
				if err := dec.Decode(&tmp); err != nil {
					return "", err
				}
				// Consume any remaining metadata keys quickly
				for dec.More() {
					if err := skipAny(dec); err != nil {
						return tmp.PURL, nil
					}
				}
				// Consume '}' for metadata
				_, _ = dec.Token()
				// Consume the rest of the root object
				for dec.More() {
					if err := skipAny(dec); err != nil {
						break
					}
				}
				// Consume '}' of the root object
				_, _ = dec.Token()
				return tmp.PURL, nil
			}
			if err := skipAny(dec); err != nil {
				return "", err
			}
		}
		// Consume '}' for metadata
		if _, err := dec.Token(); err != nil {
			return "", err
		}
	}
	// Consume '}' of the root object
	_, _ = dec.Token()
	return "", nil
}

// StreamComponents streams each entry of the `components` array and invokes the
// provided callback with a minimally decoded SBOMComponent. It never loads the
// full SBOM into memory.
func StreamComponents(path string, cb func(trivytypes.SBOMComponent) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	dec := json.NewDecoder(f)
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return fmt.Errorf("invalid CycloneDX JSON: expected object start")
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := t.(string)
		if !ok {
			return fmt.Errorf("invalid key token")
		}
		if key != "components" {
			if err := skipAny(dec); err != nil {
				return err
			}
			continue
		}
		// Enter the components array
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); !ok || d != '[' {
			return fmt.Errorf("invalid components array")
		}
		for dec.More() {
			var c trivytypes.SBOMComponent
			if err := dec.Decode(&c); err != nil {
				return err
			}
			if err := cb(c); err != nil {
				return err
			}
		}
		// Consume closing ']'
		if _, err := dec.Token(); err != nil {
			return err
		}
	}
	// Consume '}' of the root object
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}

// skipAny consumes the next JSON value in full (scalar, object, or array).
// It advances the decoder past the current value while keeping allocations and
// CPU overhead very low. This is essential to keep streaming fast on large SBOMs.
func skipAny(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim {
		return nil
	}
	// Track nested delimiters using a simple depth counter.
	depth := 1
	var open, close rune
	switch d {
	case '{':
		open, close = '{', '}'
	case '[':
		open, close = '[', ']'
	default:
		return nil
	}
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if dd, ok := t.(json.Delim); ok {
			switch rune(dd) {
			case open:
				depth++
			case close:
				depth--
			}
		}
	}
	return nil
}
