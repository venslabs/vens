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

// describedCVE is a CVE a row describes, the case every rule but the
// likelihood fallback reads.
var describedCVE = CVE{ID: "CVE-T", Rows: []Row{{PkgName: "libexample", Description: "A described vulnerability."}}}

func compute(t *testing.T, d Deployment, floored [3]bool, a Answers, adjusted *Adjusted) Levels {
	t.Helper()
	return computeFor(t, d, describedCVE, floored, a, adjusted)
}

func computeFor(t *testing.T, d Deployment, c CVE, floored [3]bool, a Answers, adjusted *Adjusted) Levels {
	t.Helper()
	l, err := Compute(d, c, floored, a, adjusted)
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

// The adjustment states a rule's domain walks: none, then each answer.
var (
	adjustedAxis        = []string{affected, notAffected, cannotTell}
	sensitivities       = []string{"low", "medium", "high", "critical"}
	detectionLevelNames = []string{"not_logged", "logged", "logged_and_reviewed", activeInApplication}
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
	add := func(factor string, d Deployment, floored [3]bool, a Answers, adjusted *Adjusted) {
		level := levels(compute(t, d, floored, a, adjusted).Vector)[factor]
		if reached[factor] == nil {
			reached[factor] = map[int]bool{}
		}
		reached[factor][level] = true
		inputs[factor]++
	}
	for _, f := range []string{"SL", "ED", "A"} {
		add(f, base(), [3]bool{}, Answers{}, nil)
	}
	for _, e := range []string{"internal", "private", "internet"} {
		d := base()
		d.Exposure.Value = e
		add("S", d, [3]bool{}, Answers{}, nil)
	}
	for _, id := range ids(motive) {
		add("M", base(), [3]bool{}, Answers{M: id}, nil)
	}
	for _, id := range ids(easeOfExploit) {
		add("EE", base(), [3]bool{}, Answers{EE: id}, nil)
	}
	for _, id := range ids(financialDamage) {
		add("FD", base(), [3]bool{}, Answers{FD: id}, nil)
	}
	for _, id := range ids(reputationDamage) {
		add("RD", base(), [3]bool{}, Answers{RD: id}, nil)
	}
	for _, id := range ids(opportunity) {
		add("O", base(), [3]bool{}, Answers{O: id}, nil)
		for _, adj := range append([]string{keep}, ids(opportunity)...) {
			add("O", base(), [3]bool{}, Answers{O: id}, &Adjusted{Opportunity: adj})
		}
	}
	walkAxes(t, add)
	for _, id := range ids(accountability) {
		for _, tr := range []*string{nil, ptr("none"), ptr("per_request"), ptr("per_individual")} {
			d := base()
			d.Traceability = tr
			add("LAC", d, [3]bool{}, Answers{LAC: id}, nil)
		}
	}
	for _, id := range ids(nonCompliance) {
		for _, fw := range [][]string{nil, {"PCI-DSS"}} {
			d := base()
			d.Frameworks = fw
			add("NC", d, [3]bool{}, Answers{NC: id}, nil)
		}
	}
	for _, det := range detections() {
		for _, set := range channelSets() {
			d := base()
			d.Detection = det
			add("ID", d, [3]bool{}, Answers{ID: set}, nil)
		}
	}
	return reached, inputs
}

// walkAxes walks the rules Applicability and the adjustment's axes reach.
func walkAxes(t *testing.T, add func(string, Deployment, [3]bool, Answers, *Adjusted)) {
	t.Helper()
	axisStates := func(axis int, each func(floored [3]bool, adjusted *Adjusted)) {
		for _, fl := range []bool{false, true} {
			var floored [3]bool
			floored[axis] = fl
			each(floored, nil)
			for _, adj := range adjustedAxis {
				a := &Adjusted{}
				switch axis {
				case cvss.Confidentiality:
					a.Confidentiality = adj
				case cvss.Integrity:
					a.Integrity = adj
				default:
					a.Availability = adj
				}
				each(floored, a)
			}
		}
	}
	for _, id := range ids(integrity) {
		axisStates(cvss.Integrity, func(fl [3]bool, adj *Adjusted) { add("LI", base(), fl, Answers{LI: id}, adj) })
	}
	for _, id := range ids(availability) {
		axisStates(cvss.Availability, func(fl [3]bool, adj *Adjusted) { add("LAV", base(), fl, Answers{LAV: id}, adj) })
	}
	for _, id := range ids(confidentiality) {
		for _, ds := range sensitivities {
			d := base()
			d.DataSensitivity.Value = ds
			axisStates(cvss.Confidentiality, func(fl [3]bool, adj *Adjusted) { add("LC", d, fl, Answers{LC: id}, adj) })
		}
	}
	for _, id := range ids(privacyViolation) {
		for _, ds := range append([]*string{nil}, ptrs(ids(privacyViolation)[:5])...) {
			d := base()
			d.DataSubjects = ds
			axisStates(cvss.Confidentiality, func(fl [3]bool, adj *Adjusted) { add("PV", d, fl, Answers{PV: id}, adj) })
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

// Every rule is a total function over a finite domain. Walked whole, each
// reaches exactly the level set the calculator's JAR ran: a rule that
// reaches another level fails here until the JAR is run over the new sets.
func TestRulesReachTheLevelSetsTheJARRan(t *testing.T) {
	reached, inputs := walk(t)
	sets := owaspLevelSets(t)
	for _, f := range vectorOrder {
		if got := slices.Sorted(maps.Keys(reached[f])); !slices.Equal(got, sets[f]) {
			t.Errorf("%s reaches %v, the JAR ran %v", f, got, sets[f])
		}
	}
	// Each domain's size: the answers, times the config states, Applicability
	// and the adjustment where the rule reads them.
	want := map[string]int{
		"SL": 1, "M": 4, "O": 35, "S": 3, "ED": 1, "EE": 5, "A": 1, "ID": 703,
		"LC": 128, "LI": 48, "LAV": 48, "LAC": 16, "FD": 5, "RD": 5, "NC": 8, "PV": 288,
	}
	if !maps.Equal(inputs, want) {
		t.Errorf("inputs walked per rule %v, want %v", inputs, want)
	}
}

// level returns one factor's level for a deployment and answers.
func level(t *testing.T, factor string, d Deployment, floored [3]bool, a Answers, adjusted *Adjusted) int {
	t.Helper()
	return levels(compute(t, d, floored, a, adjusted).Vector)[factor]
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
			out = append(out, level(t, factor, d, [3]bool{}, a, nil))
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
		{"LI", func(a *Answers, id string) { a.LI = id }, ids(integrity)},
		{"LAV", func(a *Answers, id string) { a.LAV = id }, ids(availability)},
		{"FD", func(a *Answers, id string) { a.FD = id }, ids(financialDamage)},
		{"RD", func(a *Answers, id string) { a.RD = id }, ids(reputationDamage)},
		{"NC", func(a *Answers, id string) { a.NC = id }, ids(nonCompliance)},
		{"PV", func(a *Answers, id string) { a.PV = id }, ids(privacyViolation)},
		{"LC", func(a *Answers, id string) { a.LC = id }, ids(confidentiality)},
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
		size = append(size, level(t, "S", d, [3]bool{}, Answers{}, nil))
	}
	if !nonDecreasing(size) {
		t.Errorf("S: levels %v from internal to internet, want non-decreasing", size)
	}

	for _, id := range ids(confidentiality) {
		var lc []int
		for _, ds := range sensitivities {
			d := base()
			d.DataSensitivity.Value = ds
			lc = append(lc, level(t, "LC", d, [3]bool{}, Answers{LC: id}, nil))
		}
		if !nonDecreasing(lc) {
			t.Errorf("LC %s: levels %v from low to critical data, want non-decreasing", id, lc)
		}
	}
	for _, id := range ids(accountability) {
		var lac []int
		for _, tr := range traceabilities {
			d := base()
			d.Traceability = ptr(tr)
			lac = append(lac, level(t, "LAC", d, [3]bool{}, Answers{LAC: id}, nil))
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
			pv = append(pv, level(t, "PV", d, [3]bool{}, Answers{PV: id}, nil))
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
		worst := level(t, "ID", d, [3]bool{}, Answers{ID: []string{cannotTell}}, nil)
		for _, set := range channelSets() {
			got := level(t, "ID", d, [3]bool{}, Answers{ID: set}, nil)
			if got > worst {
				t.Errorf("%+v: %v gives %d, above cannot_tell's %d", *det, set, got, worst)
			}
			for _, more := range []string{"network", "host", "application"} {
				if slices.Contains(set, more) || slices.Contains(set, cannotTell) || slices.Contains(set, "bogus") || len(set) == 0 {
					continue
				}
				if wider := level(t, "ID", d, [3]bool{}, Answers{ID: append(slices.Clone(set), more)}, nil); wider > got {
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
				if before, after := level(t, "ID", d, [3]bool{}, Answers{ID: set}, nil), level(t, "ID", d2, [3]bool{}, Answers{ID: set}, nil); after > before {
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
