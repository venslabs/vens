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

package owasp

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The reference calculator, mirrored for the tests from
// stevespringett/owasp-risk-rating-calculator at
// bc8a1273911b416b349288e1046377bcaaa6fe44 (Apache-2.0), the sources of its
// 1.0.1 release: the tag, bd22f95, differs from it by pom.xml only. sha256 of
// the six files under src/main/java/us/springett/owasp/riskrating/:
//
//	a423d08ed11cb841cd8b1eb880f3f00486feca682c928c459fb21d0804983eef  OwaspRiskRating.java
//	df1fdecca510f0d8852522fcf56bafc69bd0499faef0f1641d767811e41cc893  Score.java
//	7b6a2310a2707cdf74e0b53515c5b24d4b4d87f983ae37ba9cac1a4b842b3b95  ThreatAgentFactor.java
//	5847a295bd395254931c62b925209a4816e7e06884ea1fbe9c061309dd5a295a  VulnerabilityFactor.java
//	ecc54e820c797247bbecbc1e907fa813bfae0de5f2bfaa9b460d7418b57285c8  TechnicalImpactFactor.java
//	eb285a22f6c6cba99c9cb54374e9f4b4b6ac7438e2b86d5e3cd5a7dcfc8a4e39  BusinessImpactFactor.java

// OwaspRiskRating.java:34, anchored because fromVector() matches the whole
// string (:83-84).
var mirrorPattern = regexp.MustCompile(`^SL:\d/M:\d/O:\d/S:\d/ED:\d/EE:\d/A:\d/ID:\d/LC:\d/LI:\d/LAV:\d/LAC:\d/FD:\d/RD:\d/NC:\d/PV:\d$`)

type mirrorLevel struct {
	name  string
	level int
}

// The 16 enums in vector order, each constant in declaration order.
var mirrorEnums = [16]struct {
	abbr, enum string
	levels     []mirrorLevel
}{
	{"SL", "SkillLevel", []mirrorLevel{ // ThreatAgentFactor.java:34-39
		{"NO_TECHNICAL_SKILLS", 1}, {"SOME_TECHNICAL_SKILLS", 3}, {"ADVANCED_COMPUTER_USER", 5},
		{"NETWORK_AND_PROGRAMMING_SKILLS", 6}, {"SECURITY_PENETRATION_SKILLS", 9},
	}},
	{"M", "Motive", []mirrorLevel{ // :67-70
		{"LOW_OR_NO_REWARD", 1}, {"POSSIBLE_REWARD", 4}, {"HIGH_REWARD", 9},
	}},
	{"O", "Opportunity", []mirrorLevel{ // :98-102
		{"FULL_ACCESS_OR_EXPENSIVE_RESOURCES_REQUIRED", 0}, {"SPECIAL_ACCESS_OR_RESOURCES_REQUIRED", 4},
		{"SOME_ACCESS_OR_RESOURCES_REQUIRED", 7}, {"NO_ACCESS_OR_RESOURCES_REQUIRED", 9},
	}},
	{"S", "Size", []mirrorLevel{ // :130-136
		{"DEVELOPERS", 2}, {"SYSTEM_ADMINISTRATORS", 2}, {"INTRANET_USERS", 4}, {"PARTNERS", 5},
		{"AUTHENTICATED_USERS", 6}, {"ANONYMOUS_INTERNET_USERS", 9},
	}},
	{"ED", "EaseOfDiscovery", []mirrorLevel{ // VulnerabilityFactor.java:34-38
		{"PRACTICALLY_IMPOSSIBLE", 1}, {"DIFFICULT", 3}, {"EASY", 7}, {"AUTOMATED_TOOLS_AVAILABLE", 9},
	}},
	{"EE", "EaseOfExploit", []mirrorLevel{ // :66-70
		{"THEORETICAL", 1}, {"DIFFICULT", 3}, {"EASY", 5}, {"AUTOMATED_TOOLS_AVAILABLE", 9},
	}},
	{"A", "Awareness", []mirrorLevel{ // :98-102
		{"UNKNOWN", 1}, {"HIDDEN", 4}, {"OBVIOUS", 6}, {"PUBLIC_KNOWLEDGE", 9},
	}},
	{"ID", "IntrusionDetection", []mirrorLevel{ // :130-134
		{"ACTIVE_DETECTION_IN_APPLICATION", 1}, {"LOGGED_AND_REVIEWED", 3}, {"LOGGED_WITHOUT_REVIEW", 8},
		{"NOT_LOGGED", 9},
	}},
	{"LC", "LossOfConfidentiality", []mirrorLevel{ // TechnicalImpactFactor.java:35-40
		{"MINIMAL_NON_SENSITIVE_DATA_DISCLOSED", 2}, {"MINIMAL_CRITICAL_DATA_DISCLOSED", 6},
		{"EXTENSIVE_NON_SENSITIVE_DATA_DISCLOSED", 6}, {"EXTENSIVE_CRITICAL_DATA_DISCLOSED", 7},
		{"ALL_DATA_DISCLOSED", 9},
	}},
	{"LI", "LossOfIntegrity", []mirrorLevel{ // :68-73
		{"MINIMAL_SLIGHTLY_CORRUPT_DATA", 1}, {"MINIMAL_SERIOUSLY_CORRUPT_DATA", 3},
		{"EXTENSIVE_SLIGHTLY_CORRUPT_DATA", 5}, {"EXTENSIVE_SERIOUSLY_CORRUPT_DATA", 7},
		{"ALL_DATA_TOTALLY_CORRUPT", 9},
	}},
	{"LAV", "LossOfAvailability", []mirrorLevel{ // :101-106
		{"MINIMAL_SECONDARY_SERVICES_INTERRUPTED", 1}, {"MINIMAL_PRIMARY_SERVICES_INTERRUPTED", 5},
		{"EXTENSIVE_SECONDARY_SERVICES_INTERRUPTED", 5}, {"EXTENSIVE_PRIMARY_SERVICES_INTERRUPTED", 7},
		{"ALL_SERVICES_COMPLETELY_LOST", 9},
	}},
	{"LAC", "LossOfAccountability", []mirrorLevel{ // :134-137
		{"FULLY_TRACEABLE", 1}, {"POSSIBLY_TRACEABLE", 7}, {"COMPLETELY_ANONYMOUS", 9},
	}},
	{"FD", "FinancialDamage", []mirrorLevel{ // BusinessImpactFactor.java:44-48
		{"LESS_THAN_THE_COST_TO_FIX_THE_VULNERABILITY", 1}, {"MINOR_EFFECT_ON_ANNUAL_PROFIT", 3},
		{"SIGNIFICANT_EFFECT_ON_ANNUAL_PROFIT", 7}, {"BANKRUPTCY", 9},
	}},
	{"RD", "ReputationDamage", []mirrorLevel{ // :76-80
		{"MINIMAL_DAMAGE", 1}, {"LOSS_OF_MAJOR_ACCOUNTS", 4}, {"LOSS_OF_GOODWILL", 5}, {"BRAND_DAMAGE", 9},
	}},
	{"NC", "NonCompliance", []mirrorLevel{ // :108-111
		{"MINOR_VIOLATION", 2}, {"CLEAR_VIOLATION", 5}, {"HIGH_PROFILE_VIOLATION", 7},
	}},
	{"PV", "PrivacyViolation", []mirrorLevel{ // :139-143
		{"ONE_INDIVIDUAL", 3}, {"HUNDREDS_OF_PEOPLE", 5}, {"THOUSANDS_OF_PEOPLE", 7}, {"MILLIONS_OF_PEOPLE", 9},
	}},
}

// fromDouble(): a level is the factor's only when one of its constants carries it.
func mirrorAccepts(factor, level int) bool {
	return slices.ContainsFunc(mirrorEnums[factor].levels, func(l mirrorLevel) bool { return l.level == level })
}

// fromVector() then calculateScore()'s null check (OwaspRiskRating.java:60-68,
// :79-107): the whole string matches and every digit is on its factor's enum.
func mirrorParse(vector string) ([16]int, bool) {
	var levels [16]int
	if !mirrorPattern.MatchString(vector) {
		return levels, false
	}
	for i, token := range strings.Split(vector, "/") {
		level, err := strconv.Atoi(strings.Split(token, ":")[1])
		if err != nil || !mirrorAccepts(i, level) {
			return levels, false
		}
		levels[i] = level
	}
	return levels, true
}

// calculateScore(): the sums of the likelihood, technical and business levels
// /8, /4 and /4 (OwaspRiskRating.java:69-75).
func mirrorScores(levels [16]int) (likelihood, technical, business float64) {
	for i, level := range levels {
		switch {
		case i < 8:
			likelihood += float64(level)
		case i < 12:
			technical += float64(level)
		default:
			business += float64(level)
		}
	}
	return likelihood / 8, technical / 4, business / 4
}

// Score.rank() (Score.java:63-71).
func mirrorBand(x float64) int {
	if x < 3 {
		return 0
	} else if x < 6 {
		return 1
	}
	return 2
}

// OWASP's Step 4 overall risk severity, likelihood band by impact band.
var owaspMatrix = [3][3]string{
	{"Note", "Low", "Medium"},
	{"Low", "Medium", "High"},
	{"Medium", "High", "Critical"},
}

// The published severity and score recomputed from a written vector alone.
func mirrorRate(vector string) (severity string, score float64, ok bool) {
	levels, ok := mirrorParse(vector)
	if !ok {
		return "", 0, false
	}
	likelihood, technical, business := mirrorScores(levels)
	impact := max(technical, business)
	severity = strings.ToLower(owaspMatrix[mirrorBand(likelihood)][mirrorBand(impact)])
	if severity == "note" {
		severity = "info"
	}
	return severity, likelihood * impact, true
}

func mirrorVector(levels [16]int) string {
	parts := make([]string, len(levels))
	for i, level := range levels {
		parts[i] = fmt.Sprintf("%s:%d", mirrorEnums[i].abbr, level)
	}
	return strings.Join(parts, "/")
}

func lowestLevels() [16]int {
	var levels [16]int
	for i, f := range mirrorEnums {
		levels[i] = slices.MinFunc(f.levels, func(a, b mirrorLevel) int { return a.level - b.level }).level
	}
	return levels
}

func vectorOf(l [16]int) Vector {
	return Vector{
		SL: SkillLevel(l[0]), M: Motive(l[1]), O: Opportunity(l[2]), S: Size(l[3]),
		ED: EaseOfDiscovery(l[4]), EE: EaseOfExploit(l[5]), A: Awareness(l[6]), ID: IntrusionDetection(l[7]),
		LC: LossOfConfidentiality(l[8]), LI: LossOfIntegrity(l[9]), LAV: LossOfAvailability(l[10]), LAC: LossOfAccountability(l[11]),
		FD: FinancialDamage(l[12]), RD: ReputationDamage(l[13]), NC: NonCompliance(l[14]), PV: PrivacyViolation(l[15]),
	}
}

// The digits the calculator's 1.0.1 release JAR accepted, factor by factor,
// the other factors at their lowest level, when run for #310 step 3.
var jarAcceptedDigits = [16]string{
	"13569", "149", "0479", "24569", "1379", "1359", "1469", "1389",
	"2679", "13579", "1579", "179", "1379", "1459", "257", "3579",
}

func TestMirrorAcceptsExactlyTheEnumeratedDigits(t *testing.T) {
	for i, f := range mirrorEnums {
		var enumerated, accepted strings.Builder
		for d := 0; d <= 9; d++ {
			if mirrorAccepts(i, d) {
				enumerated.WriteString(strconv.Itoa(d))
			}
			levels := lowestLevels()
			levels[i] = d
			if _, ok := mirrorParse(mirrorVector(levels)); ok {
				accepted.WriteString(strconv.Itoa(d))
			}
		}
		if accepted.String() != enumerated.String() {
			t.Errorf("%s: the mirror accepts %q, its enum holds %q", f.abbr, accepted.String(), enumerated.String())
		}
		if enumerated.String() != jarAcceptedDigits[i] {
			t.Errorf("%s: the copied enum holds %q, the calculator's JAR accepted %q", f.abbr, enumerated.String(), jarAcceptedDigits[i])
		}
	}
}

func TestMirrorRefusesWhatThePatternRefuses(t *testing.T) {
	lowest := mirrorVector(lowestLevels())
	if _, ok := mirrorParse(lowest); !ok {
		t.Fatalf("mirrorParse(%q) refused the lowest levels", lowest)
	}
	for _, vector := range []string{
		"",
		lowest + "\n",
		" " + lowest,
		lowest + "/",
		strings.Replace(lowest, "SL:1", "SL:10", 1),
		strings.Replace(lowest, "SL:1", "SL:-1", 1),
		strings.Replace(lowest, "SL:1", "sl:1", 1),
		strings.Replace(lowest, "/M:1/", "/M:1 /", 1),
		strings.Replace(lowest, "/M:1/O:0", "/O:0/M:1", 1),
		strings.TrimSuffix(lowest, "/PV:3"),
	} {
		if _, ok := mirrorParse(vector); ok {
			t.Errorf("mirrorParse(%q) accepted a string off the pattern", vector)
		}
	}
}

func TestCheckAcceptsExactlyTheCalculatorsLevels(t *testing.T) {
	for i, f := range mirrorEnums {
		for d := -1; d <= 10; d++ {
			levels := lowestLevels()
			levels[i] = d
			err := vectorOf(levels).Check()
			if (err == nil) != mirrorAccepts(i, d) {
				t.Errorf("%s:%d: Check() = %v, the calculator accepts it: %t", f.abbr, d, err, mirrorAccepts(i, d))
			}
		}
	}
}

// One type per factor, its constants the enum's, name for name: the constant
// SkillLevelNoTechnicalSkills for SkillLevel.NO_TECHNICAL_SKILLS(1).
func TestLevelConstantsAreTheCalculatorsEnums(t *testing.T) {
	got, _ := goLevelDecls(t)
	for _, f := range mirrorEnums {
		want := map[string]int{}
		for _, l := range f.levels {
			want[f.enum+camelCase(l.name)] = l.level
		}
		if !maps.Equal(got[f.enum], want) {
			t.Errorf("type %s: constants %v, the calculator's enum %v", f.enum, got[f.enum], want)
		}
		delete(got, f.enum)
	}
	if len(got) > 0 {
		t.Errorf("typed constants of no calculator enum: %v", got)
	}
}

// Check compares values, so a constant sharing its level with another (Size 2,
// LC 6, LAV 5) could drop out of its table unseen: each table lists its type's
// constants, each once.
func TestLevelTablesListEachConstantOnce(t *testing.T) {
	consts, tables := goLevelDecls(t)
	for _, f := range mirrorEnums {
		want := slices.Sorted(maps.Keys(consts[f.enum]))
		got := slices.Sorted(slices.Values(tables[f.enum]))
		if !slices.Equal(got, want) {
			t.Errorf("the table of %s lists %v, its constants are %v", f.enum, got, want)
		}
	}
}

// goLevelDecls reads the package's typed integer constants, keyed by type then
// name, and what each []Type literal lists, keyed by type.
func goLevelDecls(t *testing.T) (consts map[string]map[string]int, tables map[string][]string) {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	consts, tables = map[string]map[string]int{}, map[string][]string{}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
				continue
			}
			for _, spec := range gen.Specs {
				if gen.Tok == token.CONST {
					addConst(t, fset, consts, spec.(*ast.ValueSpec))
				} else {
					addTable(tables, spec.(*ast.ValueSpec))
				}
			}
		}
	}
	return consts, tables
}

func addConst(t *testing.T, fset *token.FileSet, consts map[string]map[string]int, vs *ast.ValueSpec) {
	t.Helper()
	typ, ok := vs.Type.(*ast.Ident)
	if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
		t.Fatalf("%s: declare each level as `Name Type = digit`", fset.Position(vs.Pos()))
	}
	lit, ok := vs.Values[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		t.Fatalf("%s: a level is an integer literal", fset.Position(vs.Pos()))
	}
	level, err := strconv.Atoi(lit.Value)
	if err != nil {
		t.Fatal(err)
	}
	if consts[typ.Name] == nil {
		consts[typ.Name] = map[string]int{}
	}
	consts[typ.Name][vs.Names[0].Name] = level
}

func addTable(tables map[string][]string, vs *ast.ValueSpec) {
	for _, value := range vs.Values {
		lit, ok := value.(*ast.CompositeLit)
		if !ok {
			continue
		}
		slice, ok := lit.Type.(*ast.ArrayType)
		if !ok || slice.Len != nil {
			continue
		}
		if typ, ok := slice.Elt.(*ast.Ident); ok {
			for _, elt := range lit.Elts {
				tables[typ.Name] = append(tables[typ.Name], types.ExprString(elt))
			}
		}
	}
}

func camelCase(screaming string) string {
	var b strings.Builder
	for _, word := range strings.Split(strings.ToLower(screaming), "_") {
		b.WriteString(strings.ToUpper(word[:1]) + word[1:])
	}
	return b.String()
}

// The levels #310 step 3's rules can give each factor, in vector order. The
// calculator's 1.0.1 release JAR parsed and scored every vector of their
// product, 26,542,080, and refused none.
const calculatorLevelSets = "9 1,4,9 0,4,7,9 4,6,9 9 1,3,5,9 9 1,3,8,9 2,6,7,9 1,3,5,7,9 1,5,7,9 1,7,9 1,3,7,9 1,4,5,9 2,5,7 3,5,7,9"

func levelSets(t *testing.T) [16][]int {
	t.Helper()
	var sets [16][]int
	fields := strings.Fields(calculatorLevelSets)
	if len(fields) != len(sets) {
		t.Fatalf("calculatorLevelSets holds %d sets, want %d", len(fields), len(sets))
	}
	for i, field := range fields {
		for _, digit := range strings.Split(field, ",") {
			level, err := strconv.Atoi(digit)
			if err != nil {
				t.Fatal(err)
			}
			sets[i] = append(sets[i], level)
		}
	}
	return sets
}

func TestCalculatorLevelSetsAreLegal(t *testing.T) {
	product := 1
	for i, set := range levelSets(t) {
		product *= len(set)
		for _, level := range set {
			if !mirrorAccepts(i, level) {
				t.Errorf("level set %s:%d is off the calculator's enum", mirrorEnums[i].abbr, level)
			}
			levels := lowestLevels()
			levels[i] = level
			if err := vectorOf(levels).Check(); err != nil {
				t.Errorf("level set %s:%d: %v", mirrorEnums[i].abbr, level, err)
			}
		}
	}
	if product != 26_542_080 {
		t.Errorf("the level sets' product holds %d vectors, the JAR scored 26,542,080", product)
	}
}
