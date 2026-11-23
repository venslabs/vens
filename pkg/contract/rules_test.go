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

package contract

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/owasp"
)

// base is a valid deployment declaring nothing optional.
func base() Deployment {
	return Deployment{
		Name:                "svc",
		Exposure:            Setting{"internet", "Publicly accessible"},
		BusinessCriticality: Setting{"high", "Customer-facing, important operations"},
		DataSensitivity:     Setting{"low", "Public data"},
	}
}

func ptr(s string) *string { return &s }

var vectorOrder = [16]string{"SL", "M", "O", "S", "ED", "EE", "A", "ID", "LC", "LI", "LAV", "LAC", "FD", "RD", "NC", "PV"}

func levels(v owasp.Vector) map[string]int {
	return map[string]int{
		"SL": int(v.SL), "M": int(v.M), "O": int(v.O), "S": int(v.S), "ED": int(v.ED), "EE": int(v.EE),
		"A": int(v.A), "ID": int(v.ID), "LC": int(v.LC), "LI": int(v.LI), "LAV": int(v.LAV),
		"LAC": int(v.LAC), "FD": int(v.FD), "RD": int(v.RD), "NC": int(v.NC), "PV": int(v.PV),
	}
}

// describedCVE is a CVE a row describes, with a usable CVSS v3 vector: the
// case every rule but the likelihood and the technical impact fallbacks
// reads.
var describedCVE = impactCVE("L", "L", "L")

// impactCVE is a CVE a row describes, with one CVSS v3.1 vector giving C, I
// and A these values, or with no vector when they are empty.
func impactCVE(c, i, a string) CVE {
	row := Row{PkgName: "libexample", Description: "A described vulnerability."}
	if c != "" {
		row.CVSS = []cvss.Vector{v31("nvd", "AV:N/AC:L/PR:N/UI:N/S:U/C:"+c+"/I:"+i+"/A:"+a)}
	}
	return CVE{ID: "CVE-T", Rows: []Row{row}}
}

func compute(t *testing.T, d Deployment, a Answers, adjusted *Adjusted) Levels {
	t.Helper()
	return computeFor(t, d, describedCVE, a, adjusted)
}

func computeFor(t *testing.T, d Deployment, c CVE, a Answers, adjusted *Adjusted) Levels {
	t.Helper()
	l, err := Compute(d, c, a, adjusted)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if err := l.Vector.Check(); err != nil {
		t.Fatalf("Compute wrote a vector the calculator refuses: %v", err)
	}
	return l
}

func ids[V any](c contract[V]) []string {
	var out []string
	for _, a := range c.answers {
		out = append(out, a.id)
	}
	return out
}

var (
	sensitivities       = []string{"low", "medium", "high", "critical"}
	detectionLevelNames = []string{"not_logged", "logged", "logged_and_reviewed", activeInApplication}
	// impactValues are the values an axis's worst usable v3 vector gives,
	// "" for no usable vector.
	impactValues = []string{"N", "L", "H", ""}
)

// detections returns every state of detection: undeclared, then each
// channel at each level it can be declared at.
func detections() []*Detection {
	out := []*Detection{nil}
	for _, n := range detectionLevelNames[:3] {
		for _, h := range detectionLevelNames[:3] {
			for _, a := range detectionLevelNames {
				out = append(out, &Detection{Network: n, Host: h, Application: a})
			}
		}
	}
	return out
}

// channelSets returns Intrusion detection's answer sets: empty, cannot_tell
// alone, an id off the list, a channel twice, and every non-empty subset of
// the four ids.
func channelSets() [][]string {
	out := [][]string{{}, {cannotTell}, {"bogus"}, {"network", "network"}}
	all := ids(intrusionDetection)
	for mask := 1; mask < 1<<len(all); mask++ {
		var set []string
		for i, id := range all {
			if mask&(1<<i) != 0 {
				set = append(set, id)
			}
		}
		out = append(out, set)
	}
	return out
}

// walk calls each rule over its whole input domain and returns, per factor,
// the levels reached and the number of inputs walked.
func walk(t *testing.T) (reached map[string]map[int]bool, inputs map[string]int) {
	reached, inputs = map[string]map[int]bool{}, map[string]int{}
	sets := owaspLevelSets(t)
	add := func(factor string, d Deployment, c CVE, a Answers, adjusted *Adjusted) {
		l := computeFor(t, d, c, a, adjusted)
		rating, err := l.Vector.Rate()
		if err != nil {
			t.Fatalf("the calculator refuses %+v: %v", l.Vector, err)
		}
		checkRating(t, rating, levels(l.Vector), sets)
		inputs[factor]++
		if reached[factor] == nil {
			reached[factor] = map[int]bool{}
		}
		reached[factor][levels(l.Vector)[factor]] = true
	}
	for _, f := range []string{"SL", "ED", "A"} {
		add(f, base(), describedCVE, Answers{}, nil)
	}
	for _, e := range []string{"internal", "private", "internet"} {
		d := base()
		d.Exposure.Value = e
		add("S", d, describedCVE, Answers{}, nil)
	}
	for _, id := range ids(motive) {
		add("M", base(), describedCVE, Answers{M: id}, nil)
	}
	for _, id := range ids(easeOfExploit) {
		add("EE", base(), describedCVE, Answers{EE: id}, nil)
	}
	for _, id := range ids(financialDamage) {
		add("FD", base(), describedCVE, Answers{FD: id}, nil)
	}
	for _, id := range ids(reputationDamage) {
		add("RD", base(), describedCVE, Answers{RD: id}, nil)
	}
	for _, id := range ids(opportunity) {
		add("O", base(), describedCVE, Answers{O: id}, nil)
		for _, adj := range append([]string{keep}, ids(opportunity)...) {
			add("O", base(), describedCVE, Answers{O: id}, &Adjusted{Opportunity: adj})
		}
	}
	walkImpacts(add)
	for _, id := range ids(accountability) {
		for _, tr := range []*string{nil, ptr("none"), ptr("per_request"), ptr("per_individual")} {
			d := base()
			d.Traceability = tr
			add("LAC", d, describedCVE, Answers{LAC: id}, nil)
		}
	}
	for _, id := range ids(nonCompliance) {
		for _, fw := range [][]string{nil, {"PCI-DSS"}} {
			d := base()
			d.Frameworks = fw
			add("NC", d, describedCVE, Answers{NC: id}, nil)
		}
	}
	for _, det := range detections() {
		for _, set := range channelSets() {
			d := base()
			d.Detection = det
			add("ID", d, describedCVE, Answers{ID: set}, nil)
		}
	}
	return reached, inputs
}

// walkImpacts walks the technical impacts over the value the CVE's vectors
// give their axis, none included, and confidentiality over data_sensitivity;
// then Privacy violation over data_subjects, C at N or not, and the
// adjustment's confidentiality answers.
func walkImpacts(add func(string, Deployment, CVE, Answers, *Adjusted)) {
	for _, v := range impactValues {
		for _, ds := range sensitivities {
			d := base()
			d.DataSensitivity.Value = ds
			add("LC", d, impactCVE(v, v, v), Answers{}, nil)
		}
		add("LI", base(), impactCVE(v, v, v), Answers{}, nil)
		add("LAV", base(), impactCVE(v, v, v), Answers{}, nil)
	}
	adjustments := []*Adjusted{nil, {Confidentiality: affected}, {Confidentiality: notAffected}, {Confidentiality: cannotTell}}
	for _, id := range ids(privacyViolation) {
		for _, ds := range append([]*string{nil}, ptrs(ids(privacyViolation)[:5])...) {
			for _, c := range []CVE{describedCVE, impactCVE("N", "N", "N")} {
				for _, adj := range adjustments {
					d := base()
					d.DataSubjects = ds
					add("PV", d, c, Answers{PV: id}, adj)
				}
			}
		}
	}
}

func ptrs(ss []string) []*string {
	out := make([]*string, len(ss))
	for i := range ss {
		out[i] = &ss[i]
	}
	return out
}

// owaspLevelSets reads the level sets pkg/owasp's mirror test pins: the
// calculator's 1.0.1 release JAR parsed and scored every vector of their
// product. Read from that test, the rules stay tied to what the JAR ran.
func owaspLevelSets(t testing.TB) map[string][]int {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "owasp", "mirror_test.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var line string
	ast.Inspect(file, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if ok && len(vs.Names) == 1 && vs.Names[0].Name == "reachableLevelSets" && len(vs.Values) == 1 {
			if lit, ok := vs.Values[0].(*ast.BasicLit); ok {
				line, _ = strconv.Unquote(lit.Value)
			}
		}
		return line == ""
	})
	fields := strings.Fields(line)
	if len(fields) != len(vectorOrder) {
		t.Fatalf("pkg/owasp's reachableLevelSets holds %d sets, want %d", len(fields), len(vectorOrder))
	}
	sets := map[string][]int{}
	for i, field := range fields {
		for _, digit := range strings.Split(field, ",") {
			level, err := strconv.Atoi(digit)
			if err != nil {
				t.Fatal(err)
			}
			sets[vectorOrder[i]] = append(sets[vectorOrder[i]], level)
		}
	}
	return sets
}

// Every rule is a total function over a finite domain. Walked whole, every
// answer, cannot_tell included, and every value the CVSS v3 vectors give,
// none included, each input writes a vector the calculator parses and
// scores, and each rule reaches exactly the level set the calculator's JAR
// ran, but the levels C2's table leaves unreached: a rule that reaches
// another level fails here until the JAR is run over the new sets.
func TestRulesReachTheLevelSetsTheJARRan(t *testing.T) {
	reached, inputs := walk(t)
	sets := owaspLevelSets(t)
	// Loss of integrity's extensive, slightly corrupt: no v3 value gives it.
	unreached := map[string][]int{"LI": {5}}
	for _, f := range vectorOrder {
		want := slices.DeleteFunc(slices.Clone(sets[f]), func(l int) bool { return slices.Contains(unreached[f], l) })
		if got := slices.Sorted(maps.Keys(reached[f])); !slices.Equal(got, want) {
			t.Errorf("%s reaches %v, the JAR ran %v, %v of them unreached", f, got, sets[f], unreached[f])
		}
	}
	// Each domain's size: the answers or the vectors' values, times the
	// config states and the adjustment where the rule reads them.
	want := map[string]int{
		"SL": 1, "M": 4, "O": 35, "S": 3, "ED": 1, "EE": 5, "A": 1, "ID": 703,
		"LC": 16, "LI": 4, "LAV": 4, "LAC": 16, "FD": 5, "RD": 5, "NC": 8, "PV": 288,
	}
	if !maps.Equal(inputs, want) {
		t.Errorf("inputs walked per rule %v, want %v", inputs, want)
	}
}

// level returns one factor's level for a deployment and answers.
func level(t *testing.T, factor string, d Deployment, a Answers, adjusted *Adjusted) int {
	t.Helper()
	return levels(compute(t, d, a, adjusted).Vector)[factor]
}

func nonDecreasing(levels []int) bool {
	return slices.IsSorted(levels)
}

// Direction: each map follows OWASP's order, and moving a Go input one way
// never moves the level the other way.
func TestRulesDirection(t *testing.T) {
	answersOf := func(factor string, set func(*Answers, string), list []string) []int {
		var out []int
		for _, id := range list[:len(list)-1] {
			var a Answers
			set(&a, id)
			d := base()
			d.Frameworks = []string{"PCI-DSS"}
			out = append(out, level(t, factor, d, a, nil))
		}
		return out
	}
	readOnly := []struct {
		factor string
		set    func(*Answers, string)
		list   []string
	}{
		{"M", func(a *Answers, id string) { a.M = id }, ids(motive)},
		{"EE", func(a *Answers, id string) { a.EE = id }, ids(easeOfExploit)},
		{"FD", func(a *Answers, id string) { a.FD = id }, ids(financialDamage)},
		{"RD", func(a *Answers, id string) { a.RD = id }, ids(reputationDamage)},
		{"NC", func(a *Answers, id string) { a.NC = id }, ids(nonCompliance)},
		{"PV", func(a *Answers, id string) { a.PV = id }, ids(privacyViolation)},
		{"LAC", func(a *Answers, id string) { a.LAC = id }, ids(accountability)},
	}
	for _, c := range readOnly {
		if got := answersOf(c.factor, c.set, c.list); !nonDecreasing(got) {
			t.Errorf("%s: levels %v in the listed order, want non-decreasing", c.factor, got)
		}
	}
	// More access required, a lower level.
	o := answersOf("O", func(a *Answers, id string) { a.O = id }, ids(opportunity))
	slices.Reverse(o)
	if !nonDecreasing(o) {
		t.Errorf("O: levels %v in the listed order, want non-increasing", o)
	}

	var size []int
	for _, e := range []string{"internal", "private", "internet"} {
		d := base()
		d.Exposure.Value = e
		size = append(size, level(t, "S", d, Answers{}, nil))
	}
	if !nonDecreasing(size) {
		t.Errorf("S: levels %v from internal to internet, want non-decreasing", size)
	}

	// A worse value on an axis, no usable vector last, and more sensitive
	// data never lower a technical impact.
	for _, ds := range sensitivities {
		d := base()
		d.DataSensitivity.Value = ds
		var lc, li, lav []int
		for _, v := range impactValues {
			l := computeFor(t, d, impactCVE(v, v, v), Answers{}, nil)
			lc, li, lav = append(lc, int(l.Vector.LC)), append(li, int(l.Vector.LI)), append(lav, int(l.Vector.LAV))
		}
		for name, got := range map[string][]int{"LC": lc, "LI": li, "LAV": lav} {
			if !nonDecreasing(got) {
				t.Errorf("%s, data_sensitivity %s: levels %v from N to no vector, want non-decreasing", name, ds, got)
			}
		}
	}
	for _, v := range impactValues {
		var lc []int
		for _, ds := range sensitivities {
			d := base()
			d.DataSensitivity.Value = ds
			lc = append(lc, int(computeFor(t, d, impactCVE(v, v, v), Answers{}, nil).Vector.LC))
		}
		if !nonDecreasing(lc) {
			t.Errorf("LC from %q: levels %v from low to critical data, want non-decreasing", v, lc)
		}
	}
	for _, id := range ids(accountability) {
		var lac []int
		for _, tr := range traceabilities {
			d := base()
			d.Traceability = ptr(tr)
			lac = append(lac, level(t, "LAC", d, Answers{LAC: id}, nil))
		}
		slices.Reverse(lac)
		if !nonDecreasing(lac) {
			t.Errorf("LAC %s: more traceability raised the level: %v from per_individual to none", id, lac)
		}
	}
	for _, id := range ids(privacyViolation) {
		var pv []int
		for _, cap := range ids(privacyViolation)[:5] {
			d := base()
			d.DataSubjects = ptr(cap)
			pv = append(pv, level(t, "PV", d, Answers{PV: id}, nil))
		}
		if !nonDecreasing(pv) {
			t.Errorf("PV %s: levels %v from the smallest population to the largest, want non-decreasing", id, pv)
		}
	}
}

// Intrusion detection: a channel declared at a better level never raises
// it, a channel more never raises it, and cannot_tell is never below any
// set chosen.
func TestIntrusionDetectionDirection(t *testing.T) {
	for _, det := range detections()[1:] {
		d := base()
		d.Detection = det
		worst := level(t, "ID", d, Answers{ID: []string{cannotTell}}, nil)
		for _, set := range channelSets() {
			got := level(t, "ID", d, Answers{ID: set}, nil)
			if got > worst {
				t.Errorf("%+v: %v gives %d, above cannot_tell's %d", *det, set, got, worst)
			}
			for _, more := range []string{"network", "host", "application"} {
				if slices.Contains(set, more) || slices.Contains(set, cannotTell) || slices.Contains(set, "bogus") || len(set) == 0 {
					continue
				}
				if wider := level(t, "ID", d, Answers{ID: append(slices.Clone(set), more)}, nil); wider > got {
					t.Errorf("%+v: adding %s to %v raised %d to %d", *det, more, set, got, wider)
				}
			}
		}
		for _, better := range []func(*Detection){
			func(x *Detection) { x.Network = lowerDetection(x.Network, false) },
			func(x *Detection) { x.Host = lowerDetection(x.Host, false) },
			func(x *Detection) { x.Application = lowerDetection(x.Application, true) },
		} {
			improved := *det
			better(&improved)
			d2 := base()
			d2.Detection = &improved
			for _, set := range channelSets() {
				if before, after := level(t, "ID", d, Answers{ID: set}, nil), level(t, "ID", d2, Answers{ID: set}, nil); after > before {
					t.Errorf("%+v to %+v: %v went from %d to %d", *det, improved, set, before, after)
				}
			}
		}
	}
}

// lowerDetection returns the next better level a channel can be declared
// at, or the level itself at the best.
func lowerDetection(level string, application bool) string {
	best := 2
	if application {
		best = 3
	}
	i := slices.Index(detectionLevelNames, level)
	return detectionLevelNames[min(i+1, best)]
}
