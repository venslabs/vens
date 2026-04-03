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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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

		vensBinary = filepath.Join(testBinDir, "vens")
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
