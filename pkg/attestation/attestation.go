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

// Package attestation builds the CycloneDX Attestations (CDXA) sibling file for
// a vens VEX: prompt hash, input hash, model, seed, raw LLM response.
package attestation

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

// Opts configures a Builder. Set once per run.
type Opts struct {
	VensVersion string
	Provider    string
	Model       string
	Seed        int
	InputHash   string
	VEXUUID     string
	VEXVersion  int
	Now         func() time.Time
}

// Builder collects per-batch evidence and emits a CDX 1.7 BOM with
// declarations.evidence[].
type Builder struct {
	opts    Opts
	batches []batchEvidence
}

type batchEvidence struct {
	promptHash  string
	rawResponse []byte
	at          time.Time
}

// HashInput returns the hex-encoded SHA-256 of b.
func HashInput(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SiblingPath returns the attestation path next to a VEX output path:
// foo.cdx.json, foo.json and foo all yield foo.attestation.cdx.json.
func SiblingPath(vexPath string) string {
	base := strings.TrimSuffix(vexPath, ".json")
	base = strings.TrimSuffix(base, ".cdx")
	return base + ".attestation.cdx.json"
}

// NewBuilder returns a Builder.
func NewBuilder(opts Opts) *Builder {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Builder{opts: opts}
}

// AddBatch records evidence for a single LLM batch. systemPrompt and humanPrompt
// are hashed together (SHA-256 of system + "\n\n" + human); rawResponse is the
// raw bytes returned by the LLM.
func (b *Builder) AddBatch(systemPrompt, humanPrompt string, rawResponse []byte) {
	sum := sha256.Sum256([]byte(systemPrompt + "\n\n" + humanPrompt))
	b.batches = append(b.batches, batchEvidence{
		promptHash:  hex.EncodeToString(sum[:]),
		rawResponse: append([]byte(nil), rawResponse...),
		at:          b.opts.Now().UTC(),
	})
}

// BatchCount returns the number of batches recorded.
func (b *Builder) BatchCount() int { return len(b.batches) }

// Write serializes the attestation as a CycloneDX 1.7 JSON BOM.
// Returns an error if no batches were recorded.
func (b *Builder) Write(w io.Writer) error {
	if len(b.batches) == 0 {
		return fmt.Errorf("attestation: no batches recorded")
	}

	bom := cyclonedx.NewBOM()
	bom.SerialNumber = "urn:uuid:" + uuid.NewString()
	bom.Version = 1
	bom.Metadata = &cyclonedx.Metadata{
		Timestamp: b.opts.Now().UTC().Format(time.RFC3339),
	}
	if b.opts.VensVersion != "" {
		bom.Metadata.Tools = &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					Type:    cyclonedx.ComponentTypeApplication,
					Name:    "vens",
					Version: b.opts.VensVersion,
				},
			},
		}
	}
	if b.opts.VEXUUID != "" {
		v := b.opts.VEXVersion
		if v == 0 {
			v = 1
		}
		// The attestation is a file; it points at the VEX BOM it describes via a
		// BOM-Link external reference (not via bom-ref, which is a local id).
		bom.Metadata.Component = &cyclonedx.Component{
			Type:   cyclonedx.ComponentTypeFile,
			BOMRef: "vens-vex",
			Name:   "vens-vex",
			ExternalReferences: &[]cyclonedx.ExternalReference{
				{
					Type: cyclonedx.ERTypeBOM,
					URL:  fmt.Sprintf("urn:cdx:%s/%d", b.opts.VEXUUID, v),
				},
			},
		}
	}

	// "provider/model", or just whichever part is set (no dangling slash).
	model := b.opts.Model
	switch {
	case b.opts.Provider != "" && model != "":
		model = b.opts.Provider + "/" + model
	case model == "":
		model = b.opts.Provider
	}
	evidence := make([]cyclonedx.DeclarationEvidence, 0, len(b.batches))
	for i, e := range b.batches {
		data := []cyclonedx.EvidenceData{
			textData("prompt_hash", e.promptHash),
			textData("input_hash", b.opts.InputHash),
			textData("model", model),
			textData("seed", fmt.Sprintf("%d", b.opts.Seed)),
			base64Data("raw_response", e.rawResponse, "application/json"),
		}
		evidence = append(evidence, cyclonedx.DeclarationEvidence{
			BOMRef:      fmt.Sprintf("evidence-batch-%d", i+1),
			Description: fmt.Sprintf("LLM scoring batch %d", i+1),
			Created:     e.at.Format(time.RFC3339),
			Data:        &data,
		})
	}
	bom.Declarations = &cyclonedx.Declarations{Evidence: &evidence}

	enc := cyclonedx.NewBOMEncoder(w, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.EncodeVersion(bom, cyclonedx.SpecVersion1_7); err != nil {
		return fmt.Errorf("attestation: encode: %w", err)
	}
	return nil
}

func textData(name, value string) cyclonedx.EvidenceData {
	return cyclonedx.EvidenceData{
		Name: name,
		Contents: &cyclonedx.EvidenceDataContents{
			Attachment: &cyclonedx.AttachedText{
				Content:     value,
				ContentType: "text/plain",
			},
		},
	}
}

func base64Data(name string, value []byte, contentType string) cyclonedx.EvidenceData {
	return cyclonedx.EvidenceData{
		Name: name,
		Contents: &cyclonedx.EvidenceDataContents{
			Attachment: &cyclonedx.AttachedText{
				Content:     base64.StdEncoding.EncodeToString(value),
				ContentType: contentType,
				Encoding:    "base64",
			},
		},
	}
}
