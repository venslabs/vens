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
// a vens VEX: per-CVE claims backed by per-batch LLM evidence.
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
	Temperature float64
	InputHash   string
	ConfigHash  string
	VEXUUID     string
	VEXVersion  int
	Now         func() time.Time
}

// ClaimInput is one scored CVE/component assessment to attest.
type ClaimInput struct {
	VulnID      string
	CompRef     string
	CompName    string
	CompVersion string
	PURL        string
	Score       float64
	Severity    string
	Reasoning   string
}

// Builder collects per-batch evidence and per-CVE claims, then emits a CDX 1.7
// BOM with declarations (targets, claims, evidence, assessor, attestation).
type Builder struct {
	opts       Opts
	batches    []batchEvidence
	claims     []claimEntry
	targets    []cyclonedx.Component
	seenTarget map[string]bool
}

type batchEvidence struct {
	promptHash  string
	rawResponse []byte
	at          time.Time
}

type claimEntry struct {
	in          ClaimInput
	evidenceRef string
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
	return &Builder{opts: opts, seenTarget: map[string]bool{}}
}

// AddBatch records evidence for a single LLM batch and returns its bom-ref, so
// claims from the same batch can point at it. systemPrompt and humanPrompt are
// hashed together (SHA-256 of system + "\n\n" + human); rawResponse is the raw
// bytes returned by the LLM.
func (b *Builder) AddBatch(systemPrompt, humanPrompt string, rawResponse []byte) string {
	sum := sha256.Sum256([]byte(systemPrompt + "\n\n" + humanPrompt))
	b.batches = append(b.batches, batchEvidence{
		promptHash:  hex.EncodeToString(sum[:]),
		rawResponse: append([]byte(nil), rawResponse...),
		at:          b.opts.Now().UTC(),
	})
	return fmt.Sprintf("evidence-batch-%d", len(b.batches))
}

// AddClaim records one assessment (a scored CVE on a component) backed by the
// given evidence. The component is added to the target list once.
func (b *Builder) AddClaim(evidenceRef string, c ClaimInput) {
	if c.CompRef == "" {
		return // a claim must resolve to a target component
	}
	b.claims = append(b.claims, claimEntry{in: c, evidenceRef: evidenceRef})
	if b.seenTarget[c.CompRef] {
		return
	}
	b.seenTarget[c.CompRef] = true
	comp := cyclonedx.Component{
		BOMRef:  c.CompRef,
		Type:    cyclonedx.ComponentTypeLibrary,
		Name:    c.CompName,
		Version: c.CompVersion,
	}
	if strings.HasPrefix(c.PURL, "pkg:") {
		comp.PackageURL = c.PURL
	}
	b.targets = append(b.targets, comp)
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

	decl := &cyclonedx.Declarations{Evidence: b.evidence()}
	if len(b.claims) > 0 {
		b.addClaims(decl)
	}
	bom.Declarations = decl

	enc := cyclonedx.NewBOMEncoder(w, cyclonedx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.EncodeVersion(bom, cyclonedx.SpecVersion1_7); err != nil {
		return fmt.Errorf("attestation: encode: %w", err)
	}
	return nil
}

// evidence builds one declarations.evidence entry per LLM batch.
func (b *Builder) evidence() *[]cyclonedx.DeclarationEvidence {
	out := make([]cyclonedx.DeclarationEvidence, 0, len(b.batches))
	for i, e := range b.batches {
		data := []cyclonedx.EvidenceData{
			textData("generation_method", "llm"),
			textData("provider", b.opts.Provider),
			textData("model", b.opts.Model),
			textData("seed", fmt.Sprintf("%d", b.opts.Seed)),
			textData("temperature", fmt.Sprintf("%g", b.opts.Temperature)),
			textData("prompt_hash", e.promptHash),
			textData("input_hash", b.opts.InputHash),
		}
		if b.opts.ConfigHash != "" {
			data = append(data, textData("config_hash", b.opts.ConfigHash))
		}
		raw := base64Data("raw_response", e.rawResponse, "application/json")
		raw.SensitiveData = &[]string{"raw LLM output, may echo SBOM-derived context"}
		data = append(data, raw)

		out = append(out, cyclonedx.DeclarationEvidence{
			BOMRef:      fmt.Sprintf("evidence-batch-%d", i+1),
			Description: fmt.Sprintf("LLM scoring batch %d", i+1),
			Created:     e.at.Format(time.RFC3339),
			Data:        &data,
		})
	}
	return &out
}

// addClaims fills assessor, targets, claims and the attestation that maps them.
func (b *Builder) addClaims(decl *cyclonedx.Declarations) {
	const assessorRef cyclonedx.BOMReference = "assessor-vens"

	decl.Assessors = &[]cyclonedx.Assessor{{
		BOMRef:       assessorRef,
		Organization: &cyclonedx.OrganizationalEntity{Name: "vens automated assessment"},
	}}
	if len(b.targets) > 0 {
		targets := b.targets
		decl.Targets = &cyclonedx.Targets{Components: &targets}
	}

	claims := make([]cyclonedx.Claim, 0, len(b.claims))
	refs := make([]cyclonedx.BOMReference, 0, len(b.claims))
	for i, c := range b.claims {
		ref := fmt.Sprintf("claim-%d", i+1)
		claims = append(claims, cyclonedx.Claim{
			BOMRef:    ref,
			Target:    cyclonedx.BOMReference(c.in.CompRef),
			Predicate: fmt.Sprintf("%s on %s %s assessed at OWASP risk %.2f (%s)", c.in.VulnID, c.in.CompName, c.in.CompVersion, c.in.Score, c.in.Severity),
			Reasoning: c.in.Reasoning,
			Evidence:  &[]cyclonedx.BOMReference{cyclonedx.BOMReference(c.evidenceRef)},
		})
		refs = append(refs, cyclonedx.BOMReference(ref))
	}
	decl.Claims = &claims
	decl.Attestations = &[]cyclonedx.Attestation{{
		Summary:  "OWASP risk scores generated by vens via an LLM, one claim per CVE/component.",
		Assessor: assessorRef,
		Map:      &[]cyclonedx.AttestationMap{{Claims: &refs}},
	}}
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
