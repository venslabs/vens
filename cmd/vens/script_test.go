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
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
	"github.com/venslabs/vens/cmd/vens/commands/generate"
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
			"vex-vectors":   vexVectorsCmd,
			"below-scale":   belowScaleCmd,
		},
	})
}

func setupTestEnv(env *testscript.Env) error {
	env.Setenv("VENS_TEST_BINARY", os.Getenv("VENS_TEST_BINARY"))
	env.Setenv("QUICKSTART", filepath.Join(sourceDir(), "..", "..", "examples", "quickstart"))

	// VENS_TEMP_GLOB matches the temp files the outputs are written to:
	// os.CreateTemp puts its random part in place of the pattern's last "*",
	// or at the end of a pattern without one.
	tempGlob := generate.TempPattern
	if !strings.Contains(tempGlob, "*") {
		tempGlob += "*"
	}
	env.Setenv("VENS_TEMP_GLOB", tempGlob)

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

// The OWASP calculator's vector pattern (OwaspRiskRating.java:34).
var owaspVector = regexp.MustCompile(`^SL:\d/M:\d/O:\d/S:\d/ED:\d/EE:\d/A:\d/ID:\d/LC:\d/LI:\d/LAV:\d/LAC:\d/FD:\d/RD:\d/NC:\d/PV:\d$`)

// vexVectorsCmd checks a VEX's every vulnerability: one OWASP rating, its
// vector on the calculator's pattern with each level one the rules can give,
// every one of which the calculator's JAR scored, and its severity and score
// recomputed from the vector alone by OWASP's matrix on the larger impact.
func vexVectorsCmd(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) != 2 {
		ts.Fatalf("usage: vex-vectors vex.json count")
	}
	count, err := strconv.Atoi(args[1])
	if err != nil {
		ts.Fatalf("count %q: %v", args[1], err)
	}
	err = checkVEXVectors([]byte(ts.ReadFile(args[0])), count, reachableLevelSets(ts))
	switch {
	case neg && err == nil:
		ts.Fatalf("%s: every vector checks out", args[0])
	case !neg && err != nil:
		ts.Fatalf("%s: %v", args[0], err)
	}
}

func checkVEXVectors(data []byte, count int, sets [16][]int) error {
	var vex struct {
		Vulnerabilities []struct {
			ID      string `json:"id"`
			Ratings []struct {
				Method   string  `json:"method"`
				Vector   string  `json:"vector"`
				Severity string  `json:"severity"`
				Score    float64 `json:"score"`
			} `json:"ratings"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &vex); err != nil {
		return err
	}
	if len(vex.Vulnerabilities) != count {
		return fmt.Errorf("%d vulnerabilities, want %d", len(vex.Vulnerabilities), count)
	}
	for _, v := range vex.Vulnerabilities {
		if len(v.Ratings) != 1 || v.Ratings[0].Method != "OWASP" {
			return fmt.Errorf("%s: ratings %+v, want one OWASP rating", v.ID, v.Ratings)
		}
		r := v.Ratings[0]
		if !owaspVector.MatchString(r.Vector) {
			return fmt.Errorf("%s: %q is off the calculator's pattern", v.ID, r.Vector)
		}
		var sums [3]float64
		for i, part := range strings.Split(r.Vector, "/") {
			level := int(part[len(part)-1] - '0')
			if !slices.Contains(sets[i], level) {
				return fmt.Errorf("%s: %s in %s is off the levels the rules give, %v", v.ID, part, r.Vector, sets[i])
			}
			switch {
			case i < 8:
				sums[0] += float64(level)
			case i < 12:
				sums[1] += float64(level)
			default:
				sums[2] += float64(level)
			}
		}
		severity, score := owaspRate(sums[0]/8, max(sums[1], sums[2])/4)
		if r.Severity != severity || r.Score != score {
			return fmt.Errorf("%s: %s rated %s %v, its vector rates %s %v", v.ID, r.Vector, r.Severity, r.Score, severity, score)
		}
	}
	return nil
}

// belowScaleCmd reads the answers.json of the one run under a --debug-dir
// and checks every not_reachable and no_impact answer of the technical
// impact questions: read as answered, from the answer, at the level given
// per factor; not_reachable answered at least once on each of the four, and
// no_impact on each but Loss of accountability, which does not list it.
func belowScaleCmd(ts *testscript.TestScript, neg bool, args []string) {
	if neg || len(args) != 5 {
		ts.Fatalf("usage: below-scale debug-dir LC=level LI=level LAV=level LAC=level")
	}
	want := map[string]int{}
	for _, arg := range args[1:] {
		factor, digit, _ := strings.Cut(arg, "=")
		level, err := strconv.Atoi(digit)
		ts.Check(err)
		want[factor] = level
	}
	runs, err := filepath.Glob(filepath.Join(ts.MkAbs(args[0]), "run-*", "answers.json"))
	ts.Check(err)
	if len(runs) != 1 {
		ts.Fatalf("%s holds %d answers.json, want one", args[0], len(runs))
	}
	data, err := os.ReadFile(runs[0])
	ts.Check(err)
	ts.Check(checkBelowScale(data, want))
}

func checkBelowScale(data []byte, want map[string]int) error {
	var answers struct {
		Vulnerabilities []struct {
			VulnID  string `json:"vulnId"`
			Factors []struct {
				Factor  string `json:"factor"`
				Answer  any    `json:"answer"`
				Reading string `json:"reading"`
				Level   int    `json:"level"`
				Source  string `json:"source"`
			} `json:"factors"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &answers); err != nil {
		return err
	}
	seen := map[string]int{}
	for _, v := range answers.Vulnerabilities {
		for _, f := range v.Factors {
			if f.Answer != "not_reachable" && f.Answer != "no_impact" {
				continue
			}
			level, impact := want[f.Factor]
			if !impact {
				return fmt.Errorf("%s: %s answered %v, which only the technical impact questions list", v.VulnID, f.Factor, f.Answer)
			}
			if f.Reading != "answered" || f.Source != "answer" || f.Level != level {
				return fmt.Errorf("%s: %s %v read %s from %s at %d, want answered from the answer at %d", v.VulnID, f.Factor, f.Answer, f.Reading, f.Source, f.Level, level)
			}
			seen[f.Factor+" "+f.Answer.(string)]++
		}
	}
	for factor := range want {
		for _, id := range []string{"not_reachable", "no_impact"} {
			if factor == "LAC" && id == "no_impact" {
				continue
			}
			if seen[factor+" "+id] == 0 {
				return fmt.Errorf("no %s answered %s: the run exercises nothing", factor, id)
			}
		}
	}
	return nil
}

// owaspRate is OWASP's overall severity, its Note never reachable from the
// levels the rules give, and vens's score, likelihood x impact.
func owaspRate(likelihood, impact float64) (string, float64) {
	band := func(x float64) int {
		switch {
		case x < 3:
			return 0
		case x < 6:
			return 1
		}
		return 2
	}
	matrix := [3][3]string{{"info", "low", "medium"}, {"low", "medium", "high"}, {"medium", "high", "critical"}}
	return matrix[band(likelihood)][band(impact)], likelihood * impact
}

// reachableLevelSets reads, in vector order, the levels the rules can give
// each factor, which pkg/owasp's mirror test pins: the calculator's JAR
// scored every vector of their product.
func reachableLevelSets(ts *testscript.TestScript) [16][]int {
	path := filepath.Join(sourceDir(), "..", "..", "pkg", "owasp", "mirror_test.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	ts.Check(err)
	var line string
	ast.Inspect(file, func(n ast.Node) bool {
		if vs, ok := n.(*ast.ValueSpec); ok && len(vs.Names) == 1 && vs.Names[0].Name == "reachableLevelSets" {
			if lit, ok := vs.Values[0].(*ast.BasicLit); ok {
				line, err = strconv.Unquote(lit.Value)
				ts.Check(err)
			}
		}
		return line == ""
	})
	var sets [16][]int
	fields := strings.Fields(line)
	if len(fields) != len(sets) {
		ts.Fatalf("%s: reachableLevelSets holds %d sets, want 16", path, len(fields))
	}
	for i, field := range fields {
		for _, digit := range strings.Split(field, ",") {
			level, err := strconv.Atoi(digit)
			ts.Check(err)
			sets[i] = append(sets[i], level)
		}
	}
	return sets
}
