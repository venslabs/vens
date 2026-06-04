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

package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixedNow(t time.Time) func() time.Time { return func() time.Time { return t } }

func newTestBuilder(t *testing.T, mod func(*Opts)) *Builder {
	t.Helper()
	o := Opts{
		VensVersion: "v0.0.0-test",
		Provider:    "openai",
		Model:       "gpt-4o",
		Seed:        42,
		InputHash:   HashInput([]byte(`{"hello":"world"}`)),
		VEXUUID:     "11111111-2222-3333-4444-555555555555",
		VEXVersion:  1,
		Now:         fixedNow(time.Date(2026, 5, 25, 10, 0, 0, 0, time.UTC)),
	}
	if mod != nil {
		mod(&o)
	}
	return NewBuilder(o)
}

// evidenceFields decodes an attestation BOM and returns the first batch's
// evidence as a name->content map.
func evidenceFields(t *testing.T, data []byte) map[string]string {
	t.Helper()
	var got struct {
		Declarations struct {
			Evidence []struct {
				Data []struct {
					Name     string `json:"name"`
					Contents struct {
						Attachment struct {
							Content string `json:"content"`
						} `json:"attachment"`
					} `json:"contents"`
				} `json:"data"`
			} `json:"evidence"`
		} `json:"declarations"`
	}
	require.NoError(t, json.Unmarshal(data, &got))
	require.NotEmpty(t, got.Declarations.Evidence)
	fields := map[string]string{}
	for _, d := range got.Declarations.Evidence[0].Data {
		fields[d.Name] = d.Contents.Attachment.Content
	}
	return fields
}

func TestHashInput_Deterministic(t *testing.T) {
	want := sha256.Sum256([]byte("payload"))
	assert.Equal(t, hex.EncodeToString(want[:]), HashInput([]byte("payload")))
}

func TestBuilder_AddBatch_HashesSystemPlusHuman(t *testing.T) {
	b := newTestBuilder(t, nil)
	b.AddBatch("sys", "hum", []byte(`{"ok":true}`))
	require.Equal(t, 1, b.BatchCount())
	want := sha256.Sum256([]byte("sys\n\nhum"))
	assert.Equal(t, hex.EncodeToString(want[:]), b.batches[0].promptHash)
}

func TestBuilder_Write_NoBatches_Errors(t *testing.T) {
	b := newTestBuilder(t, nil)
	require.Error(t, b.Write(&bytes.Buffer{}))
}

func TestBuilder_Write_StructureAndFields(t *testing.T) {
	b := newTestBuilder(t, nil)
	raw := []byte(`{"results":[{"vulnId":"CVE-X"}]}`)
	b.AddBatch("sys", "hum", raw)

	var buf bytes.Buffer
	require.NoError(t, b.Write(&buf))

	var got struct {
		BomFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Version      int    `json:"version"`
		Metadata     struct {
			Timestamp string `json:"timestamp"`
			Tools     struct {
				Components []struct {
					Type    string `json:"type"`
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"components"`
			} `json:"tools"`
			Component struct {
				Type               string `json:"type"`
				BomRef             string `json:"bom-ref"`
				Name               string `json:"name"`
				ExternalReferences []struct {
					Type string `json:"type"`
					URL  string `json:"url"`
				} `json:"externalReferences"`
			} `json:"component"`
		} `json:"metadata"`
		Declarations struct {
			Evidence []struct {
				BomRef      string `json:"bom-ref"`
				Description string `json:"description"`
				Created     string `json:"created"`
				Data        []struct {
					Name     string `json:"name"`
					Contents struct {
						Attachment struct {
							Content     string `json:"content"`
							ContentType string `json:"contentType"`
							Encoding    string `json:"encoding"`
						} `json:"attachment"`
					} `json:"contents"`
				} `json:"data"`
			} `json:"evidence"`
		} `json:"declarations"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got), "output:\n%s", buf.String())

	assert.Equal(t, "CycloneDX", got.BomFormat)
	assert.Equal(t, "1.7", got.SpecVersion)
	assert.True(t, strings.HasPrefix(got.SerialNumber, "urn:uuid:"), "serialNumber=%q", got.SerialNumber)
	assert.Equal(t, 1, got.Version)
	assert.Equal(t, "2026-05-25T10:00:00Z", got.Metadata.Timestamp)
	assert.Equal(t, "file", got.Metadata.Component.Type)
	assert.Equal(t, "vens-vex", got.Metadata.Component.BomRef)
	require.Len(t, got.Metadata.Component.ExternalReferences, 1)
	assert.Equal(t, "bom", got.Metadata.Component.ExternalReferences[0].Type)
	assert.Equal(t, "urn:cdx:11111111-2222-3333-4444-555555555555/1", got.Metadata.Component.ExternalReferences[0].URL)
	require.Len(t, got.Metadata.Tools.Components, 1)
	assert.Equal(t, "vens", got.Metadata.Tools.Components[0].Name)
	assert.Equal(t, "v0.0.0-test", got.Metadata.Tools.Components[0].Version)

	require.Len(t, got.Declarations.Evidence, 1)
	ev := got.Declarations.Evidence[0]
	assert.Equal(t, "evidence-batch-1", ev.BomRef)
	assert.Equal(t, "2026-05-25T10:00:00Z", ev.Created)

	fields := map[string]string{}
	encodings := map[string]string{}
	for _, d := range ev.Data {
		fields[d.Name] = d.Contents.Attachment.Content
		encodings[d.Name] = d.Contents.Attachment.Encoding
	}

	wantPrompt := sha256.Sum256([]byte("sys\n\nhum"))
	assert.Equal(t, hex.EncodeToString(wantPrompt[:]), fields["prompt_hash"])
	assert.Equal(t, HashInput([]byte(`{"hello":"world"}`)), fields["input_hash"])
	assert.Equal(t, "openai/gpt-4o", fields["model"])
	assert.Equal(t, "42", fields["seed"])

	gotResp, err := base64.StdEncoding.DecodeString(fields["raw_response"])
	require.NoError(t, err, "raw_response not base64")
	assert.Equal(t, raw, gotResp)
	assert.Equal(t, "base64", encodings["raw_response"])
}

func TestBuilder_Write_NoVEXUUID_NoComponent(t *testing.T) {
	b := newTestBuilder(t, func(o *Opts) { o.VEXUUID = "" })
	b.AddBatch("s", "h", []byte("{}"))
	var buf bytes.Buffer
	require.NoError(t, b.Write(&buf))
	var got struct {
		Metadata struct {
			Component *struct{} `json:"component,omitempty"`
		} `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
	assert.Nil(t, got.Metadata.Component, "metadata.component should be omitted when VEXUUID empty")
}

func TestBuilder_Write_ProviderEmpty_ModelStandsAlone(t *testing.T) {
	b := newTestBuilder(t, func(o *Opts) { o.Provider = "" })
	b.AddBatch("s", "h", []byte("{}"))
	var buf bytes.Buffer
	require.NoError(t, b.Write(&buf))
	assert.Equal(t, "gpt-4o", evidenceFields(t, buf.Bytes())["model"])
}

func TestBuilder_Write_ModelEmpty_ProviderStandsAlone(t *testing.T) {
	b := newTestBuilder(t, func(o *Opts) { o.Model = "" })
	b.AddBatch("s", "h", []byte("{}"))
	var buf bytes.Buffer
	require.NoError(t, b.Write(&buf))
	// An unset model must not produce a dangling "provider/".
	assert.Equal(t, "openai", evidenceFields(t, buf.Bytes())["model"])
}

func TestBuilder_Write_MultipleBatches(t *testing.T) {
	b := newTestBuilder(t, nil)
	b.AddBatch("s1", "h1", []byte("{}"))
	b.AddBatch("s2", "h2", []byte("{}"))
	b.AddBatch("s3", "h3", []byte("{}"))
	var buf bytes.Buffer
	require.NoError(t, b.Write(&buf))
	s := buf.String()
	for _, want := range []string{"evidence-batch-1", "evidence-batch-2", "evidence-batch-3"} {
		assert.Contains(t, s, want)
	}
}

func TestSiblingPath(t *testing.T) {
	tests := map[string]string{
		"out.cdx.json":      "out.attestation.cdx.json",
		"out.json":          "out.attestation.cdx.json",
		"out":               "out.attestation.cdx.json",
		"dir/scan.cdx.json": "dir/scan.attestation.cdx.json",
	}
	for in, want := range tests {
		assert.Equal(t, want, SiblingPath(in))
	}
}
