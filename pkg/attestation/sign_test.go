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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func writePEM(t *testing.T, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: der,
	}), 0o600))
	return path
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func writePKCS8PEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return writePEM(t, "attest.key", "PRIVATE KEY", der)
}

// jwkPublicKey rebuilds an ECDSA P-256 public key from a JWK's x and y.
func jwkPublicKey(t *testing.T, x, y string) *ecdsa.PublicKey {
	t.Helper()
	xb, err := base64.RawURLEncoding.DecodeString(x)
	require.NoError(t, err)
	yb, err := base64.RawURLEncoding.DecodeString(y)
	require.NoError(t, err)
	raw := append([]byte{0x04}, append(xb, yb...)...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	require.NoError(t, err)
	return pub
}

// verifySigner checks signer idx of doc against pub with the JSF section 8
// digest rule. It is a test helper: vens only signs today.
func verifySigner(t *testing.T, doc []byte, idx int, pub *ecdsa.PublicKey) bool {
	t.Helper()
	var m struct {
		Signature struct {
			Signers []struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"signers"`
		} `json:"signature"`
	}
	require.NoError(t, json.Unmarshal(doc, &m))
	require.Greater(t, len(m.Signature.Signers), idx)
	require.Equal(t, "ES256", m.Signature.Signers[idx].Algorithm)
	raw, err := base64.RawURLEncoding.DecodeString(m.Signature.Signers[idx].Value)
	require.NoError(t, err)
	require.Len(t, raw, 64, "ES256 value must be r||s, 64 bytes")

	canon, err := jsfCanonical(doc, idx)
	require.NoError(t, err)
	digest := sha256.Sum256(canon)
	return ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:]))
}

func TestLoadSigningKey_PKCS8P256(t *testing.T) {
	key := testP256Key(t)
	got, err := LoadSigningKey(writePKCS8PEM(t, key))
	require.NoError(t, err)
	assert.True(t, got.PublicKey.Equal(&key.PublicKey))
}

func TestLoadSigningKey_Rejections(t *testing.T) {
	p256 := testP256Key(t)
	sec1, err := x509.MarshalECPrivateKey(p256)
	require.NoError(t, err)

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tests := []struct {
		name string
		path string
		want string
	}{
		{"sec1 EC key", writePEM(t, "sec1.key", "EC PRIVATE KEY", sec1), "openssl pkcs8 -topk8 -nocrypt"},
		{"encrypted key", writePEM(t, "enc.key", "ENCRYPTED PRIVATE KEY", []byte("x")), "passphrase-protected"},
		{"P-384 key", writePKCS8PEM(t, p384), "P-256"},
		{"RSA key", writePKCS8PEM(t, rsaKey), "must be ECDSA"},
		{"not PEM", writeFile(t, "junk.key", "garbage"), "no PEM block"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := LoadSigningKey(tt.path)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestLoadSigningKey_ErrorDoesNotEchoValue(t *testing.T) {
	// Passing the key material instead of a path must not print it.
	secret := "-----BEGIN PRIVATE KEY-----\nTOPSECRETMATERIAL\n-----END PRIVATE KEY-----"
	_, err := LoadSigningKey(secret)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "TOPSECRETMATERIAL")
	assert.NotContains(t, err.Error(), "BEGIN")
	assert.Contains(t, err.Error(), "pass a file path, not the key itself")
}

func signedAttestation(t *testing.T, key *ecdsa.PrivateKey, keyID string) []byte {
	t.Helper()
	b := newTestBuilder(t, func(o *Opts) {
		o.Signer = &Signer{Key: key, KeyID: keyID}
	})
	ref := b.AddBatch("sys", "hum", []byte(`{"ok":true}`))
	b.AddClaim(ref, ClaimInput{
		VulnID: "CVE-2024-1234", CompRef: "pkg:deb/debian/openssl@3.0.11?arch=amd64&distro=debian-12.4",
		CompName: "openssl", CompVersion: "3.0.11", PURL: "pkg:deb/debian/openssl@3.0.11?arch=amd64&distro=debian-12.4",
		Score: 56, Severity: "high", Reasoning: "RCE <script> & friends",
	})
	var buf bytes.Buffer
	require.NoError(t, b.Write(&buf))
	return buf.Bytes()
}

func TestSignedAttestation_RoundTripAndTamper(t *testing.T) {
	key := testP256Key(t)
	published := signedAttestation(t, key, "vens-test-key")

	var got struct {
		Signature struct {
			Signers []struct {
				Algorithm string `json:"algorithm"`
				KeyID     string `json:"keyId"`
				Value     string `json:"value"`
				PublicKey struct {
					KTY string `json:"kty"`
					CRV string `json:"crv"`
					X   string `json:"x"`
					Y   string `json:"y"`
				} `json:"publicKey"`
			} `json:"signers"`
		} `json:"signature"`
	}
	require.NoError(t, json.Unmarshal(published, &got), "output:\n%s", published)
	require.Len(t, got.Signature.Signers, 1, "must emit signers wrapper, not empty signature")
	signer := got.Signature.Signers[0]
	assert.Equal(t, "ES256", signer.Algorithm)
	assert.Equal(t, "vens-test-key", signer.KeyID)
	assert.Equal(t, "EC", signer.PublicKey.KTY)
	assert.Equal(t, "P-256", signer.PublicKey.CRV)
	assert.NotEmpty(t, signer.Value)

	// The embedded JWK must be the signing key: swapping x and y must not pass.
	embedded := jwkPublicKey(t, signer.PublicKey.X, signer.PublicKey.Y)
	assert.True(t, embedded.Equal(&key.PublicKey), "embedded publicKey is not the signing key")

	assert.True(t, verifySigner(t, published, 0, &key.PublicKey))

	tampered := bytes.Replace(published, []byte("RCE"), []byte("TAMPERED"), 1)
	require.NotEqual(t, published, tampered)
	assert.False(t, verifySigner(t, tampered, 0, &key.PublicKey))

	// A different key (what an attacker re-signing would use) must not verify.
	assert.False(t, verifySigner(t, published, 0, &testP256Key(t).PublicKey))
}

func TestSignedAttestation_KeepsUnsignedMemberOrder(t *testing.T) {
	published := string(signedAttestation(t, testP256Key(t), "k"))
	bomFormat := strings.Index(published, `"bomFormat"`)
	specVersion := strings.Index(published, `"specVersion"`)
	declarations := strings.Index(published, `"declarations"`)
	signature := strings.Index(published, `"signature"`)
	require.True(t, bomFormat >= 0 && specVersion > bomFormat && declarations > specVersion && signature > declarations,
		"signed sidecar should keep CycloneDX member order, got:\n%s", published)
}

func TestSignedAttestation_StillVerifiesAfterCountersign(t *testing.T) {
	key := testP256Key(t)
	published := signedAttestation(t, key, "k")

	var m map[string]any
	require.NoError(t, json.Unmarshal(published, &m))
	sig := m["signature"].(map[string]any)
	sig["signers"] = append(sig["signers"].([]any), map[string]any{
		"algorithm": "ES256", "keyId": "reviewer", "value": "AAAA",
	})
	countersigned, err := json.Marshal(m)
	require.NoError(t, err)

	assert.True(t, verifySigner(t, countersigned, 0, &key.PublicKey),
		"JSF section 8: signer 0 keeps verifying once another signer is added")
}

func TestSignedAttestation_DefaultKeyIDIsSPKIFingerprint(t *testing.T) {
	key := testP256Key(t)
	// Independent of x509.MarshalPKIXPublicKey: fixed SPKI header for
	// id-ecPublicKey / prime256v1, then the uncompressed point.
	header, err := hex.DecodeString("3059301306072a8648ce3d020106082a8648ce3d030107034200")
	require.NoError(t, err)
	point, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	sum := sha256.Sum256(append(header, point...))

	assert.Equal(t, hex.EncodeToString(sum[:]), DefaultKeyID(&key.PublicKey))

	published := signedAttestation(t, key, "")
	assert.Contains(t, string(published), `"keyId": "`+hex.EncodeToString(sum[:])+`"`)
}

func TestPackRS_PadsToFixedWidth(t *testing.T) {
	got := packRS(big.NewInt(1), big.NewInt(2))
	require.Len(t, got, 64)
	want := make([]byte, 64)
	want[31], want[63] = 1, 2
	assert.Equal(t, want, got)
}

func TestJSFCanonical_KnownAnswer(t *testing.T) {
	// Keys out of order, a non-ASCII key, and characters that encoding/json
	// escapes (& and <). The expected RFC 8785 form is written by hand: keys
	// sorted by UTF-16 code unit, no insignificant whitespace, no \u0026, and
	// the signer's value dropped but the rest of the signature object kept.
	doc := `{
  "z": "a&b<c",
  "a": {"y": 1, "x": [true, null]},
  "\u00e9": "\u20ac",
  "signature": {"signers": [{"value": "AAAA", "algorithm": "ES256"}]}
}`
	want := `{"a":{"x":[true,null],"y":1},"signature":{"signers":[{"algorithm":"ES256"}]},"z":"a&b<c","é":"€"}`

	got, err := jsfCanonical([]byte(doc), 0)
	require.NoError(t, err)
	assert.Equal(t, want, string(got))
}

func TestVerifySigner_JSFSpecMultiSignatureVector(t *testing.T) {
	// JSF spec Appendix A, p256#es256,r2048#rs256@mult-jwk.json. The ES256
	// signer is signer 0; the RS256 signer is only there so the document is a
	// real multi-signature one (its digest view must not leak into signer 0's).
	doc := []byte(`{
  "now": "2019-02-10T11:23:06Z",
  "name": "Joe",
  "id": 2200063,
  "signature": {
    "signers": [{
      "algorithm": "ES256",
      "publicKey": {
        "kty": "EC",
        "crv": "P-256",
        "x": "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU",
        "y": "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg"
      },
      "value": "Nmkfbz5AfQbLW7m3uZrc12yrXoP-skILw58Z9KRPFW0OYyrnuagJTVvKAfpaZ6SznQ69IGM_J8bBnsuois6JAg"
    },{
      "algorithm": "RS256",
      "publicKey": {
        "kty": "RSA",
        "n": "ptKZyFPStvmOlb0WihOBhlHUr6wFDHC-tW7hJAudfTQ5mHZQpB8PoMz07udZA-dG8dhUIPkmXlp1TgREeYTHdhxhuf0y_GhbpZv5JPYHx3watO-HWO2qYkjRMEcrWhPMdaVkS_Xe_liaMcow4jYoWaFm8VobeYsyVD2bWWdyl4joTEETm1Z47RnnfR15kVhVudVrDzEFmM4nXV_6dmIg184RJE4httwBFxR8qZCQCwTiJmsoyJxfUR0Gs4ePKc5sB0NTkmFZc5klQSitd67RJn2ldhbqE7EpDl4XlIt-UyLJm1guCBltia8Agke7dXuhpB7hQ6LJwY4EjzthkJ8IPw",
        "e": "AQAB"
      },
      "value": "JqJPRtttK-_whpZthVGZne1MONlMh5co7s8IWsI1-HAlqyYQTqmIIaIVBUc00MKxGZkle99d7GuF2GGKb_7aJtdsA5ZNUYHzYReaX0xg6TKcM9ppWqeFQx_DXR6GlGv3NNhNqBy2uCT_vnwErlWlNe_KQd3KJeQDrqHVQHmvCrUnx2ShXQp6MhLkZ6mrAN_J2I9z-i6NWFRG91aXfnupKvmrUZ8834ASbo5i2uEXbT8VeG9Ihuwi9iP7hhLmGd3ocUTsdtB4jTU2js7Q-F24_99SbIXW50Tfrp_TZWIjF9CqW8278OE4kGsf9Qub4VkR0b7MXYFRsE0fxTw4rdPV7A"
    }]
  }
}`)
	pub := jwkPublicKey(t, "6BKxpty8cI-exDzCkh-goU6dXq3MbcY0cd1LaAxiNrU", "mCbcvUzm44j3Lt2b5BPyQloQ91tf2D2V-gzeUxWaUdg")
	assert.True(t, verifySigner(t, doc, 0, pub))

	tampered := bytes.Replace(doc, []byte("Joe"), []byte("Eve"), 1)
	assert.False(t, verifySigner(t, tampered, 0, pub))
}
