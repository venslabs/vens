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
	"fmt"
	"slices"

	"github.com/venslabs/vens/pkg/cvss"
	"github.com/venslabs/vens/pkg/owasp"
)

// exposures holds, per exposure, the attacker group the questions name, the
// worst-case group that can reach the deployment, and Size's level for it.
var exposures = map[string]struct {
	group string
	size  owasp.Size
}{
	"internet": {"anonymous Internet users", owasp.SizeAnonymousInternetUsers},
	"private":  {"authenticated users", owasp.SizeAuthenticatedUsers},
	"internal": {"intranet users", owasp.SizeIntranetUsers},
}

// critical picks Loss of confidentiality's column from data_sensitivity: low
// and medium data are non-sensitive, high and critical data critical.
var critical = map[string]bool{"low": false, "medium": false, "high": true, "critical": true}

// confidentialityLevels crosses the answer's extent with the column,
// non-sensitive then critical.
var confidentialityLevels = [...][2]owasp.LossOfConfidentiality{
	extentMinimal:   {owasp.LossOfConfidentialityMinimalNonSensitiveDataDisclosed, owasp.LossOfConfidentialityMinimalCriticalDataDisclosed},
	extentExtensive: {owasp.LossOfConfidentialityExtensiveNonSensitiveDataDisclosed, owasp.LossOfConfidentialityExtensiveCriticalDataDisclosed},
	extentAll:       {owasp.LossOfConfidentialityAllDataDisclosed, owasp.LossOfConfidentialityAllDataDisclosed},
}

// traceabilities lists traceability's values, the least recorded first.
var traceabilities = [...]string{"none", "per_request", "per_individual"}

// accountabilityLevels crosses the answer with traceability, in
// traceabilities' order. What is in place, not what is required, sets the
// level: an identified attacker leaves a trace only under per_individual.
var accountabilityLevels = [...][len(traceabilities)]owasp.LossOfAccountability{
	actorIdentified:         {owasp.LossOfAccountabilityPossiblyTraceable, owasp.LossOfAccountabilityPossiblyTraceable, owasp.LossOfAccountabilityFullyTraceable},
	actorUnidentified:       {owasp.LossOfAccountabilityCompletelyAnonymous, owasp.LossOfAccountabilityPossiblyTraceable, owasp.LossOfAccountabilityPossiblyTraceable},
	actorDefeatsAttribution: {owasp.LossOfAccountabilityCompletelyAnonymous, owasp.LossOfAccountabilityCompletelyAnonymous, owasp.LossOfAccountabilityCompletelyAnonymous},
}

const activeInApplication = "active_in_application"

// detectionLevels is Intrusion detection's level for a channel declared at
// each level. No control credits a channel: an enabled ids, siem or edr says
// neither that this attempt is logged nor that this service is covered.
var detectionLevels = map[string]owasp.IntrusionDetection{
	"not_logged":          owasp.IntrusionDetectionNotLogged,
	"logged":              owasp.IntrusionDetectionLoggedWithoutReview,
	"logged_and_reviewed": owasp.IntrusionDetectionLoggedAndReviewed,
	activeInApplication:   owasp.IntrusionDetectionActiveDetectionInApplication,
}

// The floors: an axis every CVSS vector gives N, or the adjustment answers
// not_affected, takes its factor's lowest level, and Privacy violation
// follows confidentiality.
const (
	confidentialityFloor = owasp.LossOfConfidentialityMinimalNonSensitiveDataDisclosed
	integrityFloor       = owasp.LossOfIntegrityMinimalSlightlyCorruptData
	availabilityFloor    = owasp.LossOfAvailabilityMinimalSecondaryServicesInterrupted
	privacyFloor         = owasp.PrivacyViolationOneIndividual
)

// isBand reports whether s is one of Privacy violation's bands.
func isBand(s string) bool {
	_, r := privacyViolation.read(s)
	return r == Answered
}

// band returns the level of one of Privacy violation's bands, which is also
// the cap a data_subjects declared at that band sets.
func band(s string) owasp.PrivacyViolation {
	level, _ := privacyViolation.read(s)
	return level
}

// asked reports whether a CVE gets factor f's question. A question is not
// asked where Go has decided the level, so the model cannot contradict Go,
// nor where no answer could move it.
func asked(f Factor, d Deployment, floored [3]bool, described bool) bool {
	switch f {
	case M, O, EE:
		// A description is a prerequisite of their answers: a CVE no row
		// describes takes cannot_tell's level for each.
		return described
	case ID:
		// Undeclared, every channel is the worst case; declared at one level,
		// every set of channels gives that level.
		if d.Detection == nil {
			return false
		}
		l := d.Detection.levels()
		return l[0] != l[1] || l[1] != l[2]
	case LC:
		return !floored[cvss.Confidentiality]
	case LI:
		return !floored[cvss.Integrity]
	case LAV:
		return !floored[cvss.Availability]
	case NC:
		return len(d.Frameworks) > 0
	case PV:
		// none and one_individual cap it at the lowest level; undeclared caps
		// nothing.
		return !floored[cvss.Confidentiality] && (d.DataSubjects == nil || band(*d.DataSubjects) > privacyFloor)
	}
	return true
}

// Questions returns the questions a CVE gets, in the order the calls ask
// them, from the deployment, whether a row describes the CVE, and the axes
// Applicability floored over its vectors, indexed as cvss's axes.
func Questions(d Deployment, c CVE, floored [3]bool) ([]Factor, error) {
	if err := d.Check(); err != nil {
		return nil, err
	}
	if err := checkCVE(c); err != nil {
		return nil, err
	}
	var questions []Factor
	for _, f := range order {
		if asked(f, d, floored, c.Described()) {
			questions = append(questions, f)
		}
	}
	return questions, nil
}

// Answers holds a CVE's answers as the replies gave them. Go reads a
// factor's answer only when the CVE was asked its question; any other value
// is read as cannot_tell.
type Answers struct {
	M, O, EE, LC, LI, LAV, LAC, FD, RD, NC, PV string
	// ID is the set of channels Intrusion detection's answer chose.
	ID []string
}

// The adjustment's answers besides Opportunity's own. Its cannot_tell is an
// abstention: it leaves the baseline and is not counted.
const (
	keep        = "keep"
	affected    = "affected"
	notAffected = "not_affected"
)

// Adjusted is a flagged CVE's adjustment reply. A field the call did not ask,
// or the reply left out, is empty. Only an Opportunity answer below the
// baseline of a CVE a row describes, or an axis answered not_affected, moves
// a level: keep, affected, cannot_tell and anything off the lists leave the
// baseline.
type Adjusted struct {
	Opportunity     string
	Confidentiality string
	Integrity       string
	Availability    string
}

// Levels is a CVE's 16 levels and what Go read to reach them.
type Levels struct {
	Vector owasp.Vector
	// Sources says where each of the 16 levels came from.
	Sources map[Factor]Source
	// Readings holds how the answer to each question the CVE was asked was
	// read, and NoDescription for Motive, Opportunity and Ease of exploit
	// when no row describes the CVE, which is not asked them.
	Readings map[Factor]Reading
	// Counters names, in factor order, each counter the CVE adds one to: a
	// cannot_tell, or an answer read as one, and each undeclared field a
	// rule fell back on.
	Counters []string
}

// Compute applies the 16 rules to one CVE: the deployment, the CVE's rows,
// the axes Applicability floored over its vectors (indexed as cvss's axes),
// its answers, and for a flagged CVE its adjustment, nil otherwise. The
// adjustment never raises a level, leaves Loss of accountability and the
// business factors as computed, and leaves the Opportunity of a CVE no row
// describes at cannot_tell's level, whatever it answers.
func Compute(d Deployment, c CVE, floored [3]bool, a Answers, adjusted *Adjusted) (Levels, error) {
	if err := d.Check(); err != nil {
		return Levels{}, err
	}
	if err := checkCVE(c); err != nil {
		return Levels{}, err
	}
	if adjusted == nil {
		adjusted = &Adjusted{}
	}
	s := &scorer{d: d, floored: floored, described: c.Described(), levels: Levels{
		Sources: map[Factor]Source{}, Readings: map[Factor]Reading{},
	}}
	var v owasp.Vector
	// Every finding is a published CVE a scanner matched: OWASP's worst case
	// holds for the skill of the group, its discovery and awareness.
	v.SL = from(s, SL, SourceConstant, owasp.SkillLevelSecurityPenetrationSkills)
	v.M = likelihood(s, motive, a.M)
	v.O = likelihood(s, opportunity, a.O)
	// A description is a prerequisite of any Opportunity answer, the
	// adjustment's too, whether or not the call asked it.
	if level, r := opportunity.read(adjusted.Opportunity); r == Answered && asked(O, d, floored, s.described) {
		v.O = lowered(s, O, v.O, level)
	}
	v.S = from(s, S, SourceConfig, exposures[d.Exposure.Value].size)
	v.ED = from(s, ED, SourceConstant, owasp.EaseOfDiscoveryAutomatedToolsAvailable)
	v.EE = likelihood(s, easeOfExploit, a.EE)
	v.A = from(s, A, SourceConstant, owasp.AwarenessPublicKnowledge)
	v.ID = s.intrusionDetection(a.ID)
	v.LC = s.confidentiality(a.LC, adjusted.Confidentiality)
	v.LI = axis(s, integrity, a.LI, adjusted.Integrity, integrityFloor)
	v.LAV = axis(s, availability, a.LAV, adjusted.Availability, availabilityFloor)
	v.LAC = s.accountability(a.LAC)
	v.FD = answered(s, financialDamage, a.FD)
	v.RD = answered(s, reputationDamage, a.RD)
	v.NC = s.nonCompliance(a.NC)
	v.PV = s.privacy(a.PV, adjusted.Confidentiality)
	s.levels.Vector = v
	return s.levels, nil
}

type scorer struct {
	d         Deployment
	floored   [3]bool
	described bool
	levels    Levels
}

func (s *scorer) count(counter string) {
	s.levels.Counters = append(s.levels.Counters, counter)
}

func (s *scorer) note(f Factor, r Reading) {
	s.levels.Readings[f] = r
	if r != Answered {
		s.count(table[f].counter)
	}
}

// from records where a level came from.
func from[L any](s *scorer, f Factor, source Source, level L) L {
	s.levels.Sources[f] = source
	return level
}

// answered reads an asked factor's answer through its contract.
func answered[V any](s *scorer, c contract[V], id string) V {
	value, r := c.read(id)
	s.note(c.factor, r)
	return from(s, c.factor, SourceAnswer, value)
}

// likelihood reads Motive's, Opportunity's or Ease of exploit's answer. A CVE
// no row describes is not asked them, a description being a prerequisite of
// their answers: each takes cannot_tell's level, counted, whatever id holds.
func likelihood[L ~int](s *scorer, c contract[L], id string) L {
	if asked(c.factor, s.d, s.floored, s.described) {
		return answered(s, c, id)
	}
	level, _ := c.read(cannotTell)
	s.note(c.factor, NoDescription)
	return from(s, c.factor, SourceAnswer, level)
}

// lowered is the adjusted level where it is below the baseline: the
// adjustment never raises one.
func lowered[L ~int](s *scorer, f Factor, baseline, adjusted L) L {
	if adjusted < baseline {
		return from(s, f, SourceAdjustment, adjusted)
	}
	return baseline
}

// axis is Loss of integrity's or of availability's level: the floor when
// Applicability floored the axis, which is then not asked, or when the
// adjustment answered not_affected; the answer's level otherwise.
func axis[L owasp.LossOfIntegrity | owasp.LossOfAvailability](s *scorer, c contract[L], id, adjusted string, floor L) L {
	if !asked(c.factor, s.d, s.floored, s.described) {
		return from(s, c.factor, SourceFloor, floor)
	}
	level := answered(s, c, id)
	if adjusted == notAffected {
		return lowered(s, c.factor, level, floor)
	}
	return level
}

func (s *scorer) intrusionDetection(chosen []string) owasp.IntrusionDetection {
	if s.d.Detection == nil {
		s.count("detection_undeclared")
		return from(s, ID, SourceConfig, owasp.IntrusionDetectionNotLogged)
	}
	levels := s.d.Detection.levels()
	if !asked(ID, s.d, s.floored, s.described) {
		return from(s, ID, SourceConfig, levels[0])
	}
	level, r := readChannels(chosen, levels)
	s.note(ID, r)
	return from(s, ID, SourceAnswer, level)
}

// readChannels returns the lowest level among the channels chosen, each
// counted once: an attempt seen in any of them can be detected. A set that is
// empty, holds cannot_tell or holds an id off the list reads as cannot_tell,
// the highest of the three.
func readChannels(chosen []string, levels [3]owasp.IntrusionDetection) (owasp.IntrusionDetection, Reading) {
	worst := slices.Max(levels[:])
	channels, r := readSet(chosen)
	if r != Answered {
		return worst, r
	}
	lowest := worst
	for _, c := range channels {
		lowest = min(lowest, levels[c])
	}
	return lowest, Answered
}

// readSet reads Intrusion detection's answer: the channels chosen, or how a
// set that names none is read.
func readSet(chosen []string) ([]channel, Reading) {
	if len(chosen) == 0 {
		return nil, Invalid
	}
	var channels []channel
	reading := Answered
	for _, id := range chosen {
		c, r := intrusionDetection.read(id)
		switch r {
		case Invalid:
			return nil, Invalid
		case CannotTell:
			reading = CannotTell
		default:
			channels = append(channels, c)
		}
	}
	if reading == CannotTell {
		return nil, CannotTell
	}
	return channels, Answered
}

// ReadAnswer returns how Go reads an answer to factor f's question, as a
// reply gives it: one id, or for Intrusion detection the ids of the set
// chosen. An answer of no other shape is read as Invalid. Unlike Compute, it
// does not read the CVE: Motive's, Opportunity's and Ease of exploit's
// answers for a CVE no row describes are Answered here.
func ReadAnswer(f Factor, answer ...string) (Reading, error) {
	q, ok := table[f]
	if !ok {
		return 0, fmt.Errorf("%q is not a model-answered factor", f)
	}
	if f == ID {
		_, r := readSet(answer)
		return r, nil
	}
	switch {
	case len(answer) != 1 || !slices.Contains(q.ids, answer[0]):
		return Invalid, nil
	case answer[0] == cannotTell:
		return CannotTell, nil
	}
	return Answered, nil
}

func (s *scorer) confidentiality(id, adjusted string) owasp.LossOfConfidentiality {
	if !asked(LC, s.d, s.floored, s.described) {
		return from(s, LC, SourceFloor, confidentialityFloor)
	}
	e := answered(s, confidentiality, id)
	column := 0
	if critical[s.d.DataSensitivity.Value] {
		column = 1
	}
	level := confidentialityLevels[e][column]
	if adjusted == notAffected {
		return lowered(s, LC, level, confidentialityFloor)
	}
	return level
}

func (s *scorer) accountability(id string) owasp.LossOfAccountability {
	a := answered(s, accountability, id)
	// Undeclared, nothing is known to record the requests: the worst case.
	t := 0
	if s.d.Traceability == nil {
		s.count("traceability_missing")
	} else {
		t = slices.Index(traceabilities[:], *s.d.Traceability)
	}
	return accountabilityLevels[a][t]
}

// nonCompliance is OWASP's lowest level, a floor, when no framework applies.
func (s *scorer) nonCompliance(id string) owasp.NonCompliance {
	if !asked(NC, s.d, s.floored, s.described) {
		return from(s, NC, SourceConfig, owasp.NonComplianceMinorViolation)
	}
	return answered(s, nonCompliance, id)
}

// privacy is the lower of the answer's band and the declared population's;
// undeclared, the population caps nothing.
func (s *scorer) privacy(id, adjustedConfidentiality string) owasp.PrivacyViolation {
	switch {
	case s.floored[cvss.Confidentiality]:
		return from(s, PV, SourceFloor, privacyFloor)
	case !asked(PV, s.d, s.floored, s.described):
		// data_subjects declares none or one individual: the cap is the floor.
		return from(s, PV, SourceConfig, privacyFloor)
	}
	level := answered(s, privacyViolation, id)
	if s.d.DataSubjects == nil {
		s.count("data_subjects_missing")
	} else if limit := band(*s.d.DataSubjects); limit < level {
		level = from(s, PV, SourceConfig, limit)
	}
	if adjustedConfidentiality == notAffected {
		return lowered(s, PV, level, privacyFloor)
	}
	return level
}
