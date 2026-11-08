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

package main

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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gowebpki/jcs"
	"github.com/rogpeppe/go-internal/testscript"
)

func sourceDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("could not determine source directory")
	}
	return filepath.Dir(file)
}

func TestMain(m *testing.M) {
	vensBinary := os.Getenv("VENS_TEST_BINARY")
	if vensBinary == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			panic(err)
		}
		testBinDir := filepath.Join(cacheDir, "vens-test-bin")
		if err := os.MkdirAll(testBinDir, 0755); err != nil {
			panic(err)
		}

		vensBinaryName := "vens"
		if runtime.GOOS == "windows" {
			vensBinaryName = "vens.exe"
		}
		vensBinary = filepath.Join(testBinDir, vensBinaryName)
		srcDir := sourceDir()

		cmd := exec.Command("go", "build", "-o", vensBinary, ".")
		cmd.Dir = srcDir
		if out, err := cmd.CombinedOutput(); err != nil {
			panic(fmt.Sprintf("building vens: %s: %v", out, err))
		}
		if err := os.Setenv("VENS_TEST_BINARY", vensBinary); err != nil {
			panic(err)
		}
	}

	testscript.Main(m, map[string]func(){
		"vens": func() {
			cmd := exec.Command(vensBinary, os.Args[1:]...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					os.Exit(exitErr.ExitCode())
				}
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
	})
}

func TestScript(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir:                 filepath.Join(sourceDir(), "testdata", "script"),
		RequireExplicitExec: true,
		RequireUniqueNames:  true,
		Setup:               setupTestEnv,
		Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
			"json-contains": jsonContainsCmd,
			"json-eq":       jsonEqCmd,
			"envsubst":      envsubstCmd,
			"gen-ec-key":    genECKeyCmd,
			"jsf-verify":    jsfVerifyCmd,
		},
	})
}

func setupTestEnv(env *testscript.Env) error {
	env.Setenv("VENS_TEST_BINARY", os.Getenv("VENS_TEST_BINARY"))

	homeDir := filepath.Join(env.WorkDir, "home")
	if err := os.MkdirAll(homeDir, 0755); err != nil {
		return err
	}
	env.Setenv("HOME", homeDir)
	env.Setenv("USERPROFILE", homeDir)

	cacheDir := filepath.Join(env.WorkDir, "cache")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return err
	}
	env.Setenv("XDG_CACHE_HOME", cacheDir)

	configDir := filepath.Join(env.WorkDir, "config")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return err
	}
	env.Setenv("XDG_CONFIG_HOME", configDir)

	env.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	env.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")

	return nil
}

func jsonContainsCmd(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) != 2 {
		ts.Fatalf("usage: json-contains file expected-string")
	}
	file := ts.MkAbs(args[0])
	expected := args[1]

	data, err := os.ReadFile(file)
	if err != nil {
		ts.Fatalf("reading %s: %v", file, err)
	}

	contains := strings.Contains(string(data), expected)

	if neg {
		if contains {
			ts.Fatalf("%s contains %q but should not", file, expected)
		}
	} else {
		if !contains {
			ts.Fatalf("%s does not contain %q\n\nFile content:\n%s", file, expected, truncate(string(data), 2000))
		}
	}
}

func jsonEqCmd(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) != 2 {
		ts.Fatalf("usage: json-eq actual.json expected.json")
	}

	actualFile := ts.MkAbs(args[0])
	expectedFile := ts.MkAbs(args[1])

	actualData, err := os.ReadFile(actualFile)
	if err != nil {
		ts.Fatalf("reading %s: %v", actualFile, err)
	}

	expectedData, err := os.ReadFile(expectedFile)
	if err != nil {
		ts.Fatalf("reading %s: %v", expectedFile, err)
	}

	expectedStr := os.Expand(string(expectedData), func(key string) string {
		return ts.Getenv(key)
	})

	var actual, expected interface{}
	if err := json.Unmarshal(actualData, &actual); err != nil {
		ts.Fatalf("parsing %s as JSON: %v", actualFile, err)
	}
	if err := json.Unmarshal([]byte(expectedStr), &expected); err != nil {
		ts.Fatalf("parsing %s as JSON: %v", expectedFile, err)
	}

	actualNorm, _ := json.MarshalIndent(actual, "", "  ")
	expectedNorm, _ := json.MarshalIndent(expected, "", "  ")

	equal := string(actualNorm) == string(expectedNorm)

	if neg {
		if equal {
			ts.Fatalf("JSON files are equal but should differ")
		}
	} else {
		if !equal {
			ts.Fatalf("JSON mismatch:\n\n--- actual (%s) ---\n%s\n\n--- expected (%s) ---\n%s",
				actualFile, string(actualNorm), expectedFile, string(expectedNorm))
		}
	}
}

func envsubstCmd(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 1 {
		ts.Fatalf("usage: envsubst file")
	}

	file := ts.MkAbs(args[0])
	data, err := os.ReadFile(file)
	if err != nil {
		ts.Fatalf("reading %s: %v", file, err)
	}

	expanded := os.Expand(string(data), func(key string) string {
		return ts.Getenv(key)
	})

	if err := os.WriteFile(file, []byte(expanded), 0644); err != nil {
		ts.Fatalf("writing %s: %v", file, err)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n... (truncated)"
}

// genECKeyCmd writes a fresh P-256 key as an unencrypted PKCS#8 PEM private key
// and a PKIX PEM public key, so no private key has to live in the repo.
func genECKeyCmd(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 2 {
		ts.Fatalf("usage: gen-ec-key private.pem public.pem")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		ts.Fatalf("generating key: %v", err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		ts.Fatalf("marshal private key: %v", err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		ts.Fatalf("marshal public key: %v", err)
	}
	write := func(name, blockType string, der []byte, mode os.FileMode) {
		data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
		if err := os.WriteFile(ts.MkAbs(name), data, mode); err != nil {
			ts.Fatalf("writing %s: %v", name, err)
		}
	}
	write(args[0], "PRIVATE KEY", priv, 0o600)
	write(args[1], "PUBLIC KEY", pub, 0o644)
}

// jsfVerifyCmd verifies the first JSF signer of a document against a PEM public
// key (the pinned key, not the one embedded in the file) with an
// implementation independent of pkg/attestation. It also checks that the
// embedded publicKey is that same key and that the default keyId is the
// SHA-256 of the public key's SPKI DER.
//
//	jsf-verify file pub.pem [keyid|default]
func jsfVerifyCmd(ts *testscript.TestScript, neg bool, args []string) {
	err := jsfVerify(ts, args)
	if neg {
		if err == nil {
			ts.Fatalf("jsf-verify succeeded but should have failed")
		}
		return
	}
	if err != nil {
		ts.Fatalf("jsf-verify: %v", err)
	}
}

func jsfVerify(ts *testscript.TestScript, args []string) error {
	if len(args) < 2 || len(args) > 3 {
		return fmt.Errorf("usage: jsf-verify file pub.pem [keyid|default]")
	}
	data, err := os.ReadFile(ts.MkAbs(args[0]))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(mustRead(ts, args[1]))
	if block == nil {
		return fmt.Errorf("%s: no PEM block", args[1])
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%s: not an ECDSA public key", args[1])
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	sigObj, _ := doc["signature"].(map[string]any)
	signers, _ := sigObj["signers"].([]any)
	if len(signers) == 0 {
		return fmt.Errorf("no signature.signers")
	}
	signer, _ := signers[0].(map[string]any)
	if signer["algorithm"] != "ES256" {
		return fmt.Errorf("algorithm = %v, want ES256", signer["algorithm"])
	}
	value, _ := signer["value"].(string)
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != 64 {
		return fmt.Errorf("signature value is not 64 bytes of base64url")
	}

	// Embedded publicKey must be the pinned key.
	jwk, _ := signer["publicKey"].(map[string]any)
	x, _ := jwk["x"].(string)
	y, _ := jwk["y"].(string)
	xb, errX := base64.RawURLEncoding.DecodeString(x)
	yb, errY := base64.RawURLEncoding.DecodeString(y)
	if errX != nil || errY != nil {
		return fmt.Errorf("embedded publicKey x/y are not base64url")
	}
	pinnedRaw, err := pub.Bytes()
	if err != nil {
		return err
	}
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" ||
		string(xb) != string(pinnedRaw[1:33]) || string(yb) != string(pinnedRaw[33:65]) {
		return fmt.Errorf("embedded publicKey is not the pinned public key")
	}

	if len(args) == 3 {
		want := args[2]
		if want == "default" {
			sum := sha256.Sum256(block.Bytes)
			want = hex.EncodeToString(sum[:])
		}
		if signer["keyId"] != want {
			return fmt.Errorf("keyId = %v, want %s", signer["keyId"], want)
		}
	}

	// JSF section 8: keep only this signer, drop its value, JCS, SHA-256.
	view := map[string]any{}
	for k, v := range signer {
		if k != "value" {
			view[k] = v
		}
	}
	sigObj["signers"] = []any{view}
	reencoded, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	canon, err := jcs.Transform(reencoded)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canon)
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
		return fmt.Errorf("signature did not verify against %s", args[1])
	}
	return nil
}

func mustRead(ts *testscript.TestScript, name string) []byte {
	b, err := os.ReadFile(ts.MkAbs(name))
	if err != nil {
		ts.Fatalf("reading %s: %v", name, err)
	}
	return b
}
