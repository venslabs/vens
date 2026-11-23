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

// primaryServices picks Loss of availability's column from
// availability_requirement: low and medium are secondary services, high and
// critical primary, a cut vens declares.
var primaryServices = map[string]bool{"low": false, "medium": false, "high": true, "critical": true}

// The levels Loss of confidentiality, integrity and availability take from
// the worst value a CVE's usable CVSS v3 vectors give the axis: N the
// factor's lowest level; for confidentiality, the non-sensitive then the
// critical column; for availability, the secondary then the primary services
// column. With no usable v3 vector, each takes OWASP's worst level, which no
// value gives: no default is documented for it.
var (
	confidentialityLevels = map[string][2]owasp.LossOfConfidentiality{
		"N": {owasp.LossOfConfidentialityMinimalNonSensitiveDataDisclosed, owasp.LossOfConfidentialityMinimalNonSensitiveDataDisclosed},
		"L": {owasp.LossOfConfidentialityMinimalNonSensitiveDataDisclosed, owasp.LossOfConfidentialityMinimalCriticalDataDisclosed},
		"H": {owasp.LossOfConfidentialityExtensiveNonSensitiveDataDisclosed, owasp.LossOfConfidentialityExtensiveCriticalDataDisclosed},
	}
	integrityLevels = map[string]owasp.LossOfIntegrity{
		"N": owasp.LossOfIntegrityMinimalSlightlyCorruptData,
		"L": owasp.LossOfIntegrityMinimalSeriouslyCorruptData,
		"H": owasp.LossOfIntegrityExtensiveSeriouslyCorruptData,
	}
	availabilityLevels = map[string][2]owasp.LossOfAvailability{
		"N": {owasp.LossOfAvailabilityMinimalSecondaryServicesInterrupted, owasp.LossOfAvailabilityMinimalSecondaryServicesInterrupted},
		"L": {owasp.LossOfAvailabilityMinimalSecondaryServicesInterrupted, owasp.LossOfAvailabilityMinimalPrimaryServicesInterrupted},
		"H": {owasp.LossOfAvailabilityExtensiveSecondaryServicesInterrupted, owasp.LossOfAvailabilityExtensivePrimaryServicesInterrupted},
	}
)

// vectorMissing counts a CVE with no usable CVSS v3 vector, whose three
// technical impacts read from it take their worst level.
const vectorMissing = "cvss_v3_missing"

// availabilityMissing counts a CVE whose Loss of availability is read from
// its usable CVSS v3 vectors while availability_requirement is undeclared:
// no default being documented, the primary column, the higher, is read.
const availabilityMissing = "availability_requirement_missing"

// traceabilities lists traceability's values, the least recorded first.
var traceabilities = [...]string{"none", "per_request", "per_individual"}

// accountabilityLevels crosses the answer with traceability, in
// traceabilities' order. What is in place, not what is required, sets the
// level: an identified attacker leaves a trace only under per_individual. No
// accountability loss gets the lowest level the column gives, never one the
// records in place cannot back.
var accountabilityLevels = [...][len(traceabilities)]owasp.LossOfAccountability{
	actorNoLoss:             {owasp.LossOfAccountabilityPossiblyTraceable, owasp.LossOfAccountabilityPossiblyTraceable, owasp.LossOfAccountabilityFullyTraceable},
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

// privacyFloor is Privacy violation's lowest level: a CVE whose usable CVSS
// v3 vectors give C:N takes it, and none and one_individual cap it at it.
const privacyFloor = owasp.PrivacyViolationOneIndividual

// profile is what the rules read of a CVE besides its answers: whether a row
// describes it, and what its CVSS v3 vectors give the technical impacts.
type profile struct {
	described bool
	impact    cvss.Impact
}

func profileOf(c CVE) profile {
	return profile{described: c.Described(), impact: cvss.ImpactOf(c.vectors())}
}

// noConfidentiality reports whether the CVE has a usable CVSS v3 vector and
// the worst C they give is N: Privacy violation then takes its floor.
func (p profile) noConfidentiality() bool {
	return !p.impact.Vectorless() && p.impact.Values[cvss.Confidentiality] == "N"
}

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
func asked(f Factor, d Deployment, p profile) bool {
	switch f {
	case M, O, EE:
		// A description is a prerequisite of their answers: a CVE no row
		// describes takes cannot_tell's level for each.
		return p.described
	case ID:
		// Undeclared, every channel is the worst case; declared at one level,
		// every set of channels gives that level.
		if d.Detection == nil {
			return false
		}
		l := d.Detection.levels()
		return l[0] != l[1] || l[1] != l[2]
	case NC:
		return len(d.Frameworks) > 0
	case PV:
		// C:N on every usable v3 vector floors it; none and one_individual cap
		// it at the floor; undeclared caps nothing.
		return !p.noConfidentiality() && (d.DataSubjects == nil || band(*d.DataSubjects) > privacyFloor)
	}
	return true
}

// Questions returns the questions a CVE gets, in the order the calls ask
// them, from the deployment, whether a row describes the CVE and what its
// CVSS v3 vectors give confidentiality.
func Questions(d Deployment, c CVE) ([]Factor, error) {
	if err := d.Check(); err != nil {
		return nil, err
	}
	if err := checkCVE(c); err != nil {
		return nil, err
	}
	p := profileOf(c)
	var questions []Factor
	for _, f := range order {
		if asked(f, d, p) {
			questions = append(questions, f)
		}
	}
	return questions, nil
}

// Answers holds a CVE's answers as the replies gave them. Go reads a
// factor's answer only when the CVE was asked its question; any other value
// is read as cannot_tell.
type Answers struct {
	M, O, EE, LAC, FD, RD, NC, PV string
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
// baseline of a CVE a row describes, or confidentiality answered
// not_affected for a CVE asked Privacy violation, moves a level, and the
// second moves Privacy violation alone: keep, affected, cannot_tell and
// anything off the lists leave the baselines.
type Adjusted struct {
	Opportunity     string
	Confidentiality string
}

// Levels is a CVE's 16 levels and what Go read to reach them.
type Levels struct {
	Vector owasp.Vector
	// Sources says where each of the 16 levels came from.
	Sources map[Factor]Source
	// Readings holds how the answer to each question the CVE was asked was
	// read, and NoDescription for Motive, Opportunity and Ease of exploit when
	// no row describes the CVE, which is not asked them.
	Readings map[Factor]Reading
	// Impact is what the CVE's CVSS v3 vectors gave Loss of
	// confidentiality, integrity and availability.
	Impact cvss.Impact
	// ImpactFallback reports that the missing-input rule supplied Loss of
	// confidentiality, integrity and availability, the CVE having no usable
	// CVSS v3 vector: set where cvss_v3_missing is counted, never read from
	// the levels.
	ImpactFallback bool
	// Counters names, in factor order, each counter the CVE adds one to: a
	// cannot_tell, or an answer read as one, each undeclared field a rule fell
	// back on, and cvss_v3_missing.
	Counters []string
}

// Compute applies the 16 rules to one CVE: the deployment, the CVE's rows
// and their CVSS vectors, its answers, and for a flagged CVE its adjustment,
// nil otherwise. The adjustment never raises a level, leaves the Opportunity
// of a CVE no row describes at cannot_tell's level, whatever it answers, and
// through its confidentiality answer lowers Privacy violation alone. Loss of
// confidentiality, integrity and availability are read from the worst value
// each axis takes over the CVE's usable CVSS v3 vectors, the first crossed
// with data_sensitivity, the last with availability_requirement; with none
// usable, each takes its worst level, counted. A CVE whose usable v3 vectors
// give C:N has Privacy violation at its floor, not asked.
func Compute(d Deployment, c CVE, a Answers, adjusted *Adjusted) (Levels, error) {
	if err := d.Check(); err != nil {
		return Levels{}, err
	}
	if err := checkCVE(c); err != nil {
		return Levels{}, err
	}
	p := profileOf(c)
	s := &scorer{d: d, p: p, levels: Levels{
		Sources: map[Factor]Source{}, Readings: map[Factor]Reading{}, Impact: p.impact,
	}}
	if adjusted == nil {
		adjusted = &Adjusted{}
	}
	var v owasp.Vector
	// Every finding is a published CVE a scanner matched: OWASP's worst case
	// holds for the skill of the group, its discovery and awareness.
	v.SL = from(s, SL, SourceConstant, owasp.SkillLevelSecurityPenetrationSkills)
	v.M = likelihood(s, motive, a.M)
	v.O = s.opportunity(a.O, adjusted.Opportunity)
	v.S = from(s, S, SourceConfig, exposures[d.Exposure.Value].size)
	v.ED = from(s, ED, SourceConstant, owasp.EaseOfDiscoveryAutomatedToolsAvailable)
	v.EE = likelihood(s, easeOfExploit, a.EE)
	v.A = from(s, A, SourceConstant, owasp.AwarenessPublicKnowledge)
	v.ID = s.intrusionDetection(a.ID)
	v.LC, v.LI, v.LAV = s.technicalImpacts()
	v.LAC = s.accountability(a.LAC)
	v.FD = answered(s, financialDamage, a.FD)
	v.RD = answered(s, reputationDamage, a.RD)
	v.NC = s.nonCompliance(a.NC)
	v.PV = s.privacy(a.PV, adjusted.Confidentiality)
	s.levels.Vector = v
	return s.levels, nil
}

type scorer struct {
	d      Deployment
	p      profile
	levels Levels
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
	if asked(c.factor, s.d, s.p) {
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

// technicalImpacts are Loss of confidentiality's, integrity's and
// availability's levels, read from the worst value each axis takes over the
// CVE's usable CVSS v3 vectors, confidentiality's in data_sensitivity's
// column, availability's in availability_requirement's, the primary one when
// it is undeclared, counted. With no usable v3 vector, each is OWASP's worst
// level, the CVE is counted once and marked as the fallback's.
func (s *scorer) technicalImpacts() (owasp.LossOfConfidentiality, owasp.LossOfIntegrity, owasp.LossOfAvailability) {
	if s.levels.Impact.Vectorless() {
		s.count(vectorMissing)
		s.levels.ImpactFallback = true
		return from(s, LC, SourceCVSS, owasp.LossOfConfidentialityAllDataDisclosed),
			from(s, LI, SourceCVSS, owasp.LossOfIntegrityAllDataTotallyCorrupt),
			from(s, LAV, SourceCVSS, owasp.LossOfAvailabilityAllServicesCompletelyLost)
	}
	values := s.levels.Impact.Values
	column := 0
	if critical[s.d.DataSensitivity.Value] {
		column = 1
	}
	services := 1
	if r := s.d.AvailabilityRequirement; r == nil {
		s.count(availabilityMissing)
	} else if !primaryServices[*r] {
		services = 0
	}
	return from(s, LC, SourceCVSS, confidentialityLevels[values[cvss.Confidentiality]][column]),
		from(s, LI, SourceCVSS, integrityLevels[values[cvss.Integrity]]),
		from(s, LAV, SourceCVSS, availabilityLevels[values[cvss.Availability]][services])
}

// opportunity is Opportunity's level: the answer's, lowered by the
// adjustment's answer for a CVE a row describes, a description being a
// prerequisite of any Opportunity answer, the adjustment's too, whether or
// not the call asked it.
func (s *scorer) opportunity(id, adjusted string) owasp.Opportunity {
	level := likelihood(s, opportunity, id)
	if lower, r := opportunity.read(adjusted); r == Answered && asked(O, s.d, s.p) {
		return lowered(s, O, level, lower)
	}
	return level
}

func (s *scorer) intrusionDetection(chosen []string) owasp.IntrusionDetection {
	if s.d.Detection == nil {
		s.count("detection_undeclared")
		return from(s, ID, SourceConfig, owasp.IntrusionDetectionNotLogged)
	}
	levels := s.d.Detection.levels()
	if !asked(ID, s.d, s.p) {
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

// accountability crosses the answer with traceability.
func (s *scorer) accountability(id string) owasp.LossOfAccountability {
	a := answered(s, accountability, id)
	// Undeclared, nothing is known to record the requests: the worst case.
	t := 0
	if s.d.Traceability == nil {
		s.count("traceability_missing")
	} else {
		t = slices.Index(traceabilities[:], *s.d.Traceability)
	}
	return from(s, LAC, SourceAnswer, accountabilityLevels[a][t])
}

// nonCompliance is OWASP's lowest level, a floor, when no framework applies.
func (s *scorer) nonCompliance(id string) owasp.NonCompliance {
	if !asked(NC, s.d, s.p) {
		return from(s, NC, SourceConfig, owasp.NonComplianceMinorViolation)
	}
	return answered(s, nonCompliance, id)
}

// privacy is the lower of the answer's band and the declared population's,
// undeclared capping nothing, and the floor when the adjustment answered
// confidentiality not_affected; the floor, not asked, when the CVE's usable
// CVSS v3 vectors give C:N.
func (s *scorer) privacy(id, adjustedConfidentiality string) owasp.PrivacyViolation {
	switch {
	case s.p.noConfidentiality():
		return from(s, PV, SourceFloor, privacyFloor)
	case !asked(PV, s.d, s.p):
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
