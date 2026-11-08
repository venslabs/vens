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
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gowebpki/jcs"
)

// Signer holds the private key and optional key id used to JSF-sign a CDXA BOM.
// Only ECDSA P-256 / ES256 is supported in this release.
type Signer struct {
	Key   *ecdsa.PrivateKey
	KeyID string
}

// LoadSigningKey reads an unencrypted PKCS#8 PEM private key from path and
// requires ECDSA P-256. Errors never echo the file contents or the path value,
// so passing the key itself instead of a path cannot leak it into a log.
func LoadSigningKey(path string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, fmt.Errorf("read --attest-signing-key file: %w (pass a file path, not the key itself)", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("signing key: no PEM block found")
	}
	switch block.Type {
	case "PRIVATE KEY":
	case "ENCRYPTED PRIVATE KEY":
		return nil, fmt.Errorf("signing key: passphrase-protected keys are not supported; decrypt it first (openssl pkey -in enc.key -out attest.key)")
	case "EC PRIVATE KEY":
		return nil, fmt.Errorf("signing key: want PKCS#8 PEM (BEGIN PRIVATE KEY), got a SEC1 EC key; convert it with: openssl pkcs8 -topk8 -nocrypt -in ec.key -out attest.key")
	default:
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

// encodeBOM serializes bom the same way for both the unsigned and signed paths.
type encodeBOM func(*cyclonedx.BOM) ([]byte, error)

// signBOM attaches a BOM-level JSF signature ({"signers":[...]}) to bom and
// returns the encoded document. The BOM is encoded with the regular CycloneDX
// encoder, so a signed sidecar keeps the same member order as an unsigned one.
//
// The digest follows JSF section 8: keep only the signer being signed in
// signature.signers, drop its `value`, then JCS (RFC 8785) + SHA-256. It is
// computed from the encoded JSON, not from the struct, because
// cyclonedx.JSFSigner.Value has no omitempty.
func signBOM(bom *cyclonedx.BOM, s *Signer, encode encodeBOM) ([]byte, error) {
	if s == nil || s.Key == nil {
		return nil, fmt.Errorf("attestation: nil signing key")
	}
	if s.Key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("attestation: signing key must be EC P-256")
	}
	keyID := s.KeyID
	if keyID == "" {
		keyID = DefaultKeyID(&s.Key.PublicKey)
	}
	jwk, err := publicKeyJWK(&s.Key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("attestation: encode public key: %w", err)
	}
	signers := []cyclonedx.JSFSigner{{
		Algorithm: "ES256",
		KeyID:     keyID,
		PublicKey: jwk,
	}}
	bom.Signature = &cyclonedx.JSFSignature{Signers: &signers}

	unsigned, err := encode(bom)
	if err != nil {
		return nil, fmt.Errorf("attestation: encode: %w", err)
	}
	canon, err := jsfCanonical(unsigned, 0)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canon)
	r, ss, err := ecdsa.Sign(rand.Reader, s.Key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("attestation: ECDSA sign: %w", err)
	}
	signers[0].Value = base64.RawURLEncoding.EncodeToString(packRS(r, ss))

	out, err := encode(bom)
	if err != nil {
		return nil, fmt.Errorf("attestation: encode signed document: %w", err)
	}
	return out, nil
}

// jsfCanonical returns the JCS bytes that signer idx of doc signs: the document
// with signature.signers reduced to that one signer, minus its `value`.
func jsfCanonical(doc []byte, idx int) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		return nil, fmt.Errorf("attestation: decode signing view: %w", err)
	}
	sigObj, ok := m["signature"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("attestation: missing signature")
	}
	signers, ok := sigObj["signers"].([]any)
	if !ok || idx < 0 || idx >= len(signers) {
		return nil, fmt.Errorf("attestation: signature.signers[%d] missing", idx)
	}
	signer, ok := signers[idx].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("attestation: signature.signers[%d] invalid", idx)
	}
	view := make(map[string]any, len(signer))
	for k, v := range signer {
		if k != "value" {
			view[k] = v
		}
	}
	// Mutating m is fine: it is our own decoded copy.
	sigObj["signers"] = []any{view}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("attestation: marshal signing view: %w", err)
	}
	canon, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("attestation: JCS canonicalize: %w", err)
	}
	return canon, nil
}

// packRS packs an ECDSA signature as the fixed-width r||s form JSF/JWS use for
// ES256: each integer left-padded with zeros to 32 bytes.
func packRS(r, s *big.Int) []byte {
	out := make([]byte, 0, 64)
	out = append(out, r.FillBytes(make([]byte, 32))...)
	return append(out, s.FillBytes(make([]byte, 32))...)
}

func publicKeyJWK(pub *ecdsa.PublicKey) (cyclonedx.JSFPublicKey, error) {
	// Uncompressed SEC1 point: 0x04 || X || Y (65 bytes for P-256).
	raw, err := pub.Bytes()
	if err != nil {
		return cyclonedx.JSFPublicKey{}, err
	}
	if len(raw) != 65 {
		return cyclonedx.JSFPublicKey{}, fmt.Errorf("unexpected P-256 point length %d", len(raw))
	}
	return cyclonedx.JSFPublicKey{
		KTY: "EC",
		CRV: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(raw[1:33]),
		Y:   base64.RawURLEncoding.EncodeToString(raw[33:65]),
	}, nil
}
