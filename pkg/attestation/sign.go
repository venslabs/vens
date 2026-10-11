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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	"github.com/gowebpki/jcs"
)

// Signer holds the private key and optional key id used to JSF-sign a CDXA BOM.
// Only ECDSA P-256 / ES256 is supported in this release.
type Signer struct {
	Key   *ecdsa.PrivateKey
	KeyID string
}

// LoadSigningKey reads a PKCS#8 PEM private key and requires ECDSA P-256.
func LoadSigningKey(path string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("signing key: no PEM block found")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("signing key: want PKCS#8 PEM (BEGIN PRIVATE KEY), got %q", block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing key: parse PKCS#8: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key: must be ECDSA, got %T", parsed)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("signing key: must be EC P-256 (prime256v1), got %s", key.Curve.Params().Name)
	}
	return key, nil
}

// DefaultKeyID returns the hex-encoded SHA-256 of the public key's SPKI DER.
func DefaultKeyID(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// SignDocument attaches a BOM-level JSF signature ({"signers":[...]}) to a
// CycloneDX JSON document. The digest is SHA-256 of the RFC 8785 (JCS)
// canonical form of the document with the signer's `value` member deleted
// only — the signature object remains in the signed bytes (JSF §6 / §8).
func SignDocument(doc []byte, s *Signer) ([]byte, error) {
	if s == nil || s.Key == nil {
		return nil, fmt.Errorf("attestation: nil signing key")
	}
	if s.Key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("attestation: signing key must be EC P-256")
	}

	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		return nil, fmt.Errorf("attestation: decode for signing: %w", err)
	}

	keyID := s.KeyID
	if keyID == "" {
		keyID = DefaultKeyID(&s.Key.PublicKey)
	}

	jwk, err := publicKeyJWK(&s.Key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("attestation: encode public key: %w", err)
	}
	signerCore := map[string]any{
		"algorithm": "ES256",
		"keyId":     keyID,
		"publicKey": jwk,
	}
	m["signature"] = map[string]any{
		"signers": []any{signerCore},
	}

	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("attestation: marshal signing view: %w", err)
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("attestation: JCS canonicalize: %w", err)
	}
	digest := sha256.Sum256(canon)

	r, ss, err := ecdsa.Sign(rand.Reader, s.Key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("attestation: ECDSA sign: %w", err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), ss.FillBytes(make([]byte, 32))...)
	signerCore["value"] = base64.RawURLEncoding.EncodeToString(sig)

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("attestation: marshal signed document: %w", err)
	}
	out = append(out, '\n')
	return out, nil
}

// VerifyDocument checks the first BOM-level JSF signer against pub using the
// JSF digest rule (delete signer `value` only, then JCS + SHA-256 + ES256).
// It is intended for tests and as the reference for the documented verify recipe.
func VerifyDocument(doc []byte, pub *ecdsa.PublicKey) error {
	if pub == nil {
		return fmt.Errorf("attestation: nil public key")
	}
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		return fmt.Errorf("attestation: decode for verify: %w", err)
	}
	sigObj, ok := m["signature"].(map[string]any)
	if !ok {
		return fmt.Errorf("attestation: missing signature")
	}
	signers, ok := sigObj["signers"].([]any)
	if !ok || len(signers) == 0 {
		return fmt.Errorf("attestation: signature.signers missing")
	}
	signer0, ok := signers[0].(map[string]any)
	if !ok {
		return fmt.Errorf("attestation: signature.signers[0] invalid")
	}
	value, _ := signer0["value"].(string)
	if value == "" {
		return fmt.Errorf("attestation: signature value missing")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != 64 {
		return fmt.Errorf("attestation: signature value must be 64-byte ES256 (base64url)")
	}

	// Multi-signer JSF view: only the target signer remains, without `value`.
	viewSigner := cloneMap(signer0)
	delete(viewSigner, "value")
	view := cloneMap(m)
	view["signature"] = map[string]any{
		"signers": []any{viewSigner},
	}

	rawView, err := json.Marshal(view)
	if err != nil {
		return fmt.Errorf("attestation: marshal verify view: %w", err)
	}
	canon, err := jcs.Transform(rawView)
	if err != nil {
		return fmt.Errorf("attestation: JCS canonicalize: %w", err)
	}
	digest := sha256.Sum256(canon)
	r := new(big.Int).SetBytes(raw[:32])
	s := new(big.Int).SetBytes(raw[32:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return fmt.Errorf("attestation: signature did not verify")
	}
	return nil
}

func publicKeyJWK(pub *ecdsa.PublicKey) (map[string]any, error) {
	// Uncompressed SEC1 point: 0x04 || X || Y (65 bytes for P-256).
	raw, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	if len(raw) != 65 {
		return nil, fmt.Errorf("unexpected P-256 point length %d", len(raw))
	}
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(raw[1:33]),
		"y":   base64.RawURLEncoding.EncodeToString(raw[33:65]),
	}, nil
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
