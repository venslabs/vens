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
	"github.com/venslabs/vens/pkg/owasp"
	"github.com/venslabs/vens/pkg/riskconfig"
)

// The 13 questions and their answers. A question names the attacker group
// as {group}; Non-compliance's names the declared frameworks as {frameworks}.
// cannot_tell means only that the facts given do not decide: a model answer
// has no documented default, so it maps to the factor's worst legal level.

const cannotTellText = "The facts given do not say."

// impactCannotTellText is cannot_tell's text on reachability, whose list
// says that the vulnerable code is not reachable here, and on the four
// technical impact questions, three of which list that the exploit has no
// such impact: neither is cannot_tell.
const impactCannotTellText = "The facts given do not decide between the answers above."

// notReachable is how reachability's answer says the vulnerable code is not
// reachable here, reading reachability as the system prompt defines it once.
const notReachable = "the facts given show that the vulnerable code is not reachable in this deployment, as defined above"

// notReachableID is reachability's one answer that is not read as reachable;
// noImpactID is the answer below the scales of Loss of confidentiality,
// integrity and availability, which lands on the factor's floor, so it never
// raises a level any other answer would give. Loss of accountability's
// identified answer is its no accountability loss.
const (
	notReachableID = "not_reachable"
	noImpactID     = "no_impact"
)

const notReachableText = "Not reachable here: " + notReachable + "."

// reachability is asked of every CVE first. Its answer decides once, for
// Opportunity, Ease of exploit and the four technical impacts, whether their
// questions are asked: not reachable sets each to its lowest level instead.
// cannot_tell is read as reachable, the worst case.
var reachability = contract[bool]{
	factor:   R,
	question: "Can {group} reach the vulnerable code of this vulnerability in this deployment, whatever access or effort that takes, as reachability is defined above?",
	answers: []answer[bool]{
		{"reachable", "Reachable here: the vulnerable code is reachable in this deployment, as defined above.", true},
		{notReachableID, notReachableText, false},
		{cannotTell, impactCannotTellText, true},
	},
	counter: "reachability_cannot_tell",
}

var motive = contract[owasp.Motive]{
	factor:   M,
	question: "How motivated are {group} to find and exploit this vulnerability in this service? Judge by the reward that exploiting it here would bring them: what a successful exploit gives an attacker, and what this service is and holds.",
	answers: []answer[owasp.Motive]{
		{"low_or_no_reward", "Low or no reward: exploiting it here brings them nothing they could use, sell or leverage.", owasp.MotiveLowOrNoReward},
		{"possible_reward", "Possible reward: it brings them something of some value here.", owasp.MotivePossibleReward},
		{"high_reward", "High reward: it brings them something of high value here, such as control of the service, its data or its users.", owasp.MotiveHighReward},
		{cannotTell, cannotTellText, owasp.MotiveHighReward},
	},
	counter: "motive_cannot_tell",
}

var opportunity = contract[owasp.Opportunity]{
	factor:   O,
	question: "What access or resources do {group} need, beyond what they already have in this deployment, to find and exploit this vulnerability here?",
	answers: []answer[owasp.Opportunity]{
		{"no_access_or_resources_required", "No access or resources required: from where they already are, they can reach and trigger the vulnerable code in this deployment.", owasp.OpportunityNoAccessOrResourcesRequired},
		{"some_access_or_resources_required", "Some access or resources required: something most of them can obtain, such as an ordinary account, an action by a user of the service, or a common setting.", owasp.OpportunitySomeAccessOrResourcesRequired},
		{"special_access_or_resources_required", "Special access or resources required: something few of them have, such as a privileged account, a foothold on the host, or a feature or role this deployment does not have by default.", owasp.OpportunitySpecialAccessOrResourcesRequired},
		{"full_access_or_expensive_resources_required", "Full access or expensive resources required: full control of the host, physical access, or resources few attackers have.", owasp.OpportunityFullAccessOrExpensiveResourcesRequired},
		{cannotTell, cannotTellText, owasp.OpportunityNoAccessOrResourcesRequired},
	},
	counter: "opportunity_cannot_tell",
}

var easeOfExploit = contract[owasp.EaseOfExploit]{
	factor:   EE,
	question: "How easy is it for {group}, from where they already are, to actually exploit this vulnerability in this deployment, as it is deployed and with the controls in front of it? Any access control the exposure itself requires, such as the corporate network or the VPN or authenticated tunnel, is not one of those controls: {group} are already past it. Choose the one answer that holds here.",
	answers: []answer[owasp.EaseOfExploit]{
		{"theoretical", "Theoretical: no practical way to exploit it in this deployment is known.", owasp.EaseOfExploitTheoretical},
		{"difficult", "Difficult: a practical way exists, but here it needs expert work, rare conditions, chaining with another flaw, or getting through a control in front of this deployment that they have not already passed, even where a public exploit exists elsewhere.", owasp.EaseOfExploitDifficult},
		{"easy", "Easy: a practical way exists here that needs none of that, and no public exploit or tool performs it.", owasp.EaseOfExploitEasy},
		{"automated_tools_available", "Automated tools available: none of that is needed here, and a public exploit or tool performs it.", owasp.EaseOfExploitAutomatedToolsAvailable},
		{cannotTell, cannotTellText, owasp.EaseOfExploitAutomatedToolsAvailable},
	},
	counter: "ease_of_exploit_cannot_tell",
}

// channel is where Intrusion detection's answer says an attempt would show.
type channel int

const (
	channelNetwork channel = iota
	channelHost
	channelApplication
	// noChannel is cannot_tell's, which names none.
	noChannel
)

// The one question whose answer is a set: the model chooses every channel
// that applies, and cannot_tell alone.
var intrusionDetection = contract[channel]{
	factor:   ID,
	question: "Where would an attempt to exploit this vulnerability in this deployment show? Choose every place that applies.",
	answers: []answer[channel]{
		{"network", "Network: the attempt crosses the network to or from this deployment.", channelNetwork},
		{"host", "Host: the attempt runs code, starts processes, or changes files or privileges on the host.", channelHost},
		{"application", "Application: the attempt passes through this service's own request handling or logic, where the application itself could log or detect it.", channelApplication},
		{cannotTell, "The facts given do not say. Chosen alone.", noChannel},
	},
	counter: "intrusion_detection_cannot_tell",
}

// extent is how much data Loss of confidentiality's answer says an exploit
// discloses, which Go crosses with data_sensitivity. extentNone is no_impact's:
// it discloses nothing here.
type extent int

const (
	extentNone extent = iota
	extentMinimal
	extentExtensive
	extentAll
)

var confidentiality = contract[extent]{
	factor:   LC,
	question: "If {group} exploited this vulnerability in this deployment, how much of the data this service handles could they read? The data it handles is what the deployment's description and notes say it holds or processes. Where they do not say, it handles whatever the service can read. Count all the distinct data they could read by exploiting it as often as they can.",
	answers: []answer[extent]{
		{noImpactID, "No data disclosed: it is reachable, but exploiting it here discloses none of the data this service handles, as when its only effect is a crash, a slowdown or a change that reveals nothing.", extentNone},
		{"minimal", "Minimal: a small, bounded amount, such as a few values, one record, a file path, a version string, or a fragment of memory or metadata.", extentMinimal},
		{"extensive", "Extensive: a large amount, such as many records, whole files or tables, or the data of many users, but not all the data this service can read.", extentExtensive},
		{"all", "All: all the data this service can read, as when the exploit runs code as the service or yields the credentials or keys that open every store it reads.", extentAll},
		{cannotTell, impactCannotTellText, extentAll},
	},
	counter: "confidentiality_cannot_tell",
}

var integrity = contract[owasp.LossOfIntegrity]{
	factor:   LI,
	question: "If {group} exploited this vulnerability in this deployment, how much of the data this service handles could they corrupt, and how badly? Count all the distinct data they could corrupt by exploiting it as often as they can.",
	answers: []answer[owasp.LossOfIntegrity]{
		{noImpactID, "No data corrupted: it is reachable, but exploiting it here changes none of the data this service handles, as when its only effect is a crash, a slowdown or a disclosure.", integrityFloor},
		{"minimal_slightly_corrupt", "Minimal, slightly corrupt: a little of the data, such as one record, file, setting or message, changed in ways that are easy to notice or undo, such as a malformed value, a log line or a cache entry that is rebuilt.", owasp.LossOfIntegrityMinimalSlightlyCorruptData},
		{"minimal_seriously_corrupt", "Minimal, seriously corrupt: a little of the data, changed in ways that matter, such as an altered record, credential, setting or file that the service or its users will trust and act on.", owasp.LossOfIntegrityMinimalSeriouslyCorruptData},
		{"extensive_slightly_corrupt", "Extensive, slightly corrupt: much of the data, changed in ways that are easy to notice or undo.", owasp.LossOfIntegrityExtensiveSlightlyCorruptData},
		{"extensive_seriously_corrupt", "Extensive, seriously corrupt: much of the data, changed in ways that matter, but not everything this service holds.", owasp.LossOfIntegrityExtensiveSeriouslyCorruptData},
		{"all_data_totally_corrupt", "All data totally corrupt: everything this service holds can be overwritten or destroyed, as when the exploit runs code as the service.", owasp.LossOfIntegrityAllDataTotallyCorrupt},
		{cannotTell, impactCannotTellText, owasp.LossOfIntegrityAllDataTotallyCorrupt},
	},
	counter: "integrity_cannot_tell",
}

var availability = contract[owasp.LossOfAvailability]{
	factor:   LAV,
	question: "If {group} exploited this vulnerability in this deployment, how much of this service could they interrupt, and how vital is what they would interrupt? Primary is what the deployment's description and notes say this service exists to do, and any part it cannot do that without; secondary is anything else it runs, such as a tool in the image, an optional feature, an admin or debug function, or a background task. Where they do not say, count what is interrupted as primary.",
	answers: []answer[owasp.LossOfAvailability]{
		{noImpactID, "Nothing interrupted: it is reachable, but exploiting it here interrupts nothing this service does, as when its only effect is a disclosure or a change of data.", availabilityFloor},
		{"minimal_secondary_interrupted", "Minimal, secondary: a brief or partial interruption of something secondary, such as one request, process or worker failing and being restarted.", owasp.LossOfAvailabilityMinimalSecondaryServicesInterrupted},
		{"minimal_primary_interrupted", "Minimal, primary: a brief or partial interruption of something primary, such as one request, process or worker failing and being restarted.", owasp.LossOfAvailabilityMinimalPrimaryServicesInterrupted},
		{"extensive_secondary_interrupted", "Extensive, secondary: a lasting or broad interruption of something secondary: it stays down until someone acts, or fails for everyone for as long as the attack goes on.", owasp.LossOfAvailabilityExtensiveSecondaryServicesInterrupted},
		{"extensive_primary_interrupted", "Extensive, primary: a lasting or broad interruption of something primary: it stays down until someone acts, or fails for everyone for as long as the attack goes on.", owasp.LossOfAvailabilityExtensivePrimaryServicesInterrupted},
		{"all_services_completely_lost", "All services completely lost: the service and what runs with it, completely, as when the exploit takes down the host or every instance of the service.", owasp.LossOfAvailabilityAllServicesCompletelyLost},
		{cannotTell, impactCannotTellText, owasp.LossOfAvailabilityAllServicesCompletelyLost},
	},
	counter: "availability_cannot_tell",
}

// actor is what Loss of accountability's answer says of the attacker's
// traces, which Go crosses with traceability. actorNoLoss is identified's, and
// a CVE not reachable here takes it: no accountability loss.
type actor int

const (
	actorNoLoss actor = iota
	actorUnidentified
	actorDefeatsAttribution
)

// Authentication and attribution are asked apart, and not having to
// authenticate never counts as no accountability loss.
var accountability = contract[actor]{
	factor:   LAC,
	question: "To exploit this vulnerability in this deployment, must {group} authenticate to this service under an identity of their own? Apart from that, could the exploit let them act as someone else, or erase, forge or bypass the records of who did what? Answer the two facts separately; whether records exist is not asked.",
	answers: []answer[actor]{
		{"identified", "Identified, no accountability loss: they must authenticate to this service under an identity of their own, and the exploit does not let them act as someone else or tamper with the records of who did what.", actorNoLoss},
		{"unidentified", "Unidentified: they need not authenticate to this service, or there is no service to authenticate to, and the exploit does not let them act as someone else or tamper with the records of who did what.", actorUnidentified},
		{"defeats_attribution", "Defeats attribution: whether or not they authenticate, the exploit lets them act as someone else, or erase, forge or bypass the records of who did what.", actorDefeatsAttribution},
		{cannotTell, impactCannotTellText, actorDefeatsAttribution},
	},
	counter: "accountability_cannot_tell",
}

var financialDamage = contract[owasp.FinancialDamage]{
	factor:   FD,
	question: "If {group} exploited this vulnerability in this service, how much financial damage would result?",
	answers: []answer[owasp.FinancialDamage]{
		{"less_than_cost_to_fix", "Less than the cost to fix the vulnerability.", owasp.FinancialDamageLessThanTheCostToFixTheVulnerability},
		{"minor_effect_on_annual_profit", "A minor effect on annual profit.", owasp.FinancialDamageMinorEffectOnAnnualProfit},
		{"significant_effect_on_annual_profit", "A significant effect on annual profit.", owasp.FinancialDamageSignificantEffectOnAnnualProfit},
		{"bankruptcy", "Bankruptcy.", owasp.FinancialDamageBankruptcy},
		{cannotTell, cannotTellText, owasp.FinancialDamageBankruptcy},
	},
	counter: "financial_damage_cannot_tell",
}

var reputationDamage = contract[owasp.ReputationDamage]{
	factor:   RD,
	question: "If {group} exploited this vulnerability in this service and it became known, how much would it harm the business's reputation?",
	answers: []answer[owasp.ReputationDamage]{
		{"minimal_damage", "Minimal damage: few would notice or care.", owasp.ReputationDamageMinimalDamage},
		{"loss_of_major_accounts", "Loss of major accounts: important customers or partners would leave or reconsider.", owasp.ReputationDamageLossOfMajorAccounts},
		{"loss_of_goodwill", "Loss of goodwill: customers or the public would trust the business less.", owasp.ReputationDamageLossOfGoodwill},
		{"brand_damage", "Brand damage: lasting, public harm to the brand.", owasp.ReputationDamageBrandDamage},
		{cannotTell, cannotTellText, owasp.ReputationDamageBrandDamage},
	},
	counter: "reputation_cannot_tell",
}

var nonCompliance = contract[owasp.NonCompliance]{
	factor:   NC,
	question: "This service must comply with {frameworks}. If {group} exploited this vulnerability here, how serious a violation of those frameworks would it cause?",
	answers: []answer[owasp.NonCompliance]{
		{"minor_violation", "Minor violation: at most a minor or technical breach of a requirement.", owasp.NonComplianceMinorViolation},
		{"clear_violation", "Clear violation: a clear breach of a requirement, such as exposure or alteration of the data or controls a framework protects.", owasp.NonComplianceClearViolation},
		{"high_profile_violation", "High profile violation: a breach that would have to be reported or would draw a regulator's attention.", owasp.NonComplianceHighProfileViolation},
		{cannotTell, cannotTellText, owasp.NonComplianceHighProfileViolation},
	},
	counter: "non_compliance_cannot_tell",
}

// Privacy violation's answers are data_subjects' bands, ids and levels read
// from the config's one table: Go caps the answer's level with the declared
// band's, so the two cannot drift apart. Only the text each band is shown
// with is the question's. none takes OWASP's lowest level, a floor for a
// service holding no personal data.
var privacyViolation = contract[owasp.PrivacyViolation]{
	factor:   PV,
	question: "If {group} exploited this vulnerability in this deployment, how many distinct people's personal data could be disclosed, at most? Choose the band that holds that count.",
	answers: bandAnswers(riskconfig.DataSubjectsBands(), map[string]string{
		"none":           "None: no personal data could be disclosed (0 people).",
		"one_individual": "One individual: 1 person.",
		"hundreds":       "Hundreds: 2 to 999 people; a count under 100 belongs here.",
		"thousands":      "Thousands: 1,000 to 999,999 people.",
		"millions":       "Millions: 1,000,000 people or more.",
	}),
	counter: "privacy_cannot_tell",
}

// bandAnswers lists the bands in their order, each with its text, then
// cannot_tell at the largest band's level.
func bandAnswers(bands []riskconfig.Band, texts map[string]string) []answer[owasp.PrivacyViolation] {
	answers := make([]answer[owasp.PrivacyViolation], 0, len(bands)+1)
	var worst owasp.PrivacyViolation
	for _, b := range bands {
		answers = append(answers, answer[owasp.PrivacyViolation]{b.Name, texts[b.Name], b.Level})
		worst = max(worst, b.Level)
	}
	return append(answers, answer[owasp.PrivacyViolation]{cannotTell, cannotTellText, worst})
}

// table is the one table the request, the schema and the rules read, so the
// text shown, the enum and the map cannot drift apart.
var table = map[Factor]shown{
	R:   reachability.shown(),
	M:   motive.shown(),
	O:   opportunity.shown(),
	EE:  easeOfExploit.shown(),
	ID:  intrusionDetection.shown(),
	LC:  confidentiality.shown(),
	LI:  integrity.shown(),
	LAV: availability.shown(),
	LAC: accountability.shown(),
	FD:  financialDamage.shown(),
	RD:  reputationDamage.shown(),
	NC:  nonCompliance.shown(),
	PV:  privacyViolation.shown(),
}
