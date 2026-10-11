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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/gowebpki/jcs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func writePKCS8PEM(t *testing.T, dir string, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	path := filepath.Join(dir, "attest.key")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), 0o600))
	return path
}

func TestLoadSigningKey_PKCS8P256(t *testing.T) {
	key := testP256Key(t)
	path := writePKCS8PEM(t, t.TempDir(), key)
	got, err := LoadSigningKey(path)
	require.NoError(t, err)
	assert.True(t, got.PublicKey.Equal(&key.PublicKey))
}

func TestLoadSigningKey_RejectsNonPKCS8(t *testing.T) {
	key := testP256Key(t)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "sec1.key")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}), 0o600))
	_, err = LoadSigningKey(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PKCS#8")
}

func TestSignDocument_RoundTripAndTamper(t *testing.T) {
	key := testP256Key(t)
	b := newTestBuilder(t, func(o *Opts) {
		o.Signer = &Signer{Key: key, KeyID: "vens-test-key"}
	})
	ref := b.AddBatch("sys", "hum", []byte(`{"ok":true}`))
	b.AddClaim(ref, ClaimInput{
		VulnID: "CVE-2024-1234", CompRef: "pkg:deb/debian/openssl@3.0.11",
		CompName: "openssl", CompVersion: "3.0.11", PURL: "pkg:deb/debian/openssl@3.0.11",
		Score: 56, Severity: "high", Reasoning: "RCE",
	})

	var buf bytes.Buffer
	require.NoError(t, b.Write(&buf))
	published := buf.Bytes()

	var got struct {
		Signature struct {
			Signers []struct {
				Algorithm string `json:"algorithm"`
				KeyID     string `json:"keyId"`
				Value     string `json:"value"`
				PublicKey struct {
					KTY string `json:"kty"`
					CRV string `json:"crv"`
				} `json:"publicKey"`
			} `json:"signers"`
		} `json:"signature"`
	}
	require.NoError(t, json.Unmarshal(published, &got), "output:\n%s", published)
	require.Len(t, got.Signature.Signers, 1, "must emit signers wrapper, not empty signature")
	assert.Equal(t, "ES256", got.Signature.Signers[0].Algorithm)
	assert.Equal(t, "vens-test-key", got.Signature.Signers[0].KeyID)
	assert.Equal(t, "EC", got.Signature.Signers[0].PublicKey.KTY)
	assert.Equal(t, "P-256", got.Signature.Signers[0].PublicKey.CRV)
	assert.NotEmpty(t, got.Signature.Signers[0].Value)
	assert.Contains(t, string(published), `"signers"`)
	assert.NotContains(t, string(published), `"signature": {}`)

	require.NoError(t, VerifyDocument(published, &key.PublicKey))

	tampered := bytes.Replace(published, []byte("RCE"), []byte("TAMPERED"), 1)
	require.NotEqual(t, published, tampered)
	require.Error(t, VerifyDocument(tampered, &key.PublicKey))
}

func TestSignDocument_DigestIsDeleteValueOnly(t *testing.T) {
	// Guard against the early (wrong) "strip whole signature" probe rule:
	// a signature produced with the JSF rule must NOT verify under that rule.
	key := testP256Key(t)
	doc := []byte(`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "declarations": {"evidence": []}
}`)
	signed, err := SignDocument(doc, &Signer{Key: key, KeyID: "k"})
	require.NoError(t, err)
	require.NoError(t, VerifyDocument(signed, &key.PublicKey))

	require.Error(t, verifyWithStripSignatureRule(signed, &key.PublicKey),
		"strip-whole-signature must not verify a JSF-conformant signature")
}

func verifyWithStripSignatureRule(doc []byte, pub *ecdsa.PublicKey) error {
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		return err
	}
	sigObj, _ := m["signature"].(map[string]any)
	signers, _ := sigObj["signers"].([]any)
	signer0, _ := signers[0].(map[string]any)
	value, _ := signer0["value"].(string)
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != 64 {
		return err
	}
	delete(m, "signature")
	rawView, err := json.Marshal(m)
	if err != nil {
		return err
	}
	canon, err := jcs.Transform(rawView)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canon)
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return assert.AnError
	}
	return nil
}

func TestDefaultKeyID_Stable(t *testing.T) {
	key := testP256Key(t)
	a := DefaultKeyID(&key.PublicKey)
	b := DefaultKeyID(&key.PublicKey)
	assert.Equal(t, a, b)
	assert.Len(t, a, 64)
}
