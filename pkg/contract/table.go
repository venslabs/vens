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

import "github.com/venslabs/vens/pkg/owasp"

// The 12 questions and their answers. A question names the attacker group
// as {group}; Non-compliance's names the declared frameworks as {frameworks}.
// cannot_tell maps to the factor's worst case.

const cannotTellText = "The facts given do not say."

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
	question: "How easy is it for {group} to actually exploit this vulnerability in this deployment, as it is deployed and with the controls in front of it? Choose the one answer that holds here.",
	answers: []answer[owasp.EaseOfExploit]{
		{"theoretical", "Theoretical: no practical way to exploit it in this deployment is known.", owasp.EaseOfExploitTheoretical},
		{"difficult", "Difficult: a practical way exists, but here it needs expert work, rare conditions, chaining with another flaw, or getting past a control in front of this deployment, even where a public exploit exists elsewhere.", owasp.EaseOfExploitDifficult},
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
// discloses, which Go crosses with data_sensitivity.
type extent int

const (
	extentMinimal extent = iota
	extentExtensive
	extentAll
)

var confidentiality = contract[extent]{
	factor:   LC,
	question: "If {group} exploited this vulnerability in this deployment, how much of the data this service handles could they read?",
	answers: []answer[extent]{
		{"minimal", "Minimal: a small, bounded amount, such as a few values, one record, or a fragment of memory or metadata.", extentMinimal},
		{"extensive", "Extensive: a large amount, such as many records, whole files or tables, or the data of many users.", extentExtensive},
		{"all", "All: all the data this service can read.", extentAll},
		{cannotTell, cannotTellText, extentAll},
	},
	counter: "confidentiality_cannot_tell",
}

var integrity = contract[owasp.LossOfIntegrity]{
	factor:   LI,
	question: "If {group} exploited this vulnerability in this deployment, how much of the data this service handles could they corrupt, and how badly?",
	answers: []answer[owasp.LossOfIntegrity]{
		{"minimal_slightly_corrupt", "Minimal, slightly corrupt: a little of the data, changed in ways that are easy to notice or undo.", owasp.LossOfIntegrityMinimalSlightlyCorruptData},
		{"minimal_seriously_corrupt", "Minimal, seriously corrupt: a little of the data, changed in ways that matter, such as altered records, credentials or settings.", owasp.LossOfIntegrityMinimalSeriouslyCorruptData},
		{"extensive_slightly_corrupt", "Extensive, slightly corrupt: much of the data, changed in ways that are easy to notice or undo.", owasp.LossOfIntegrityExtensiveSlightlyCorruptData},
		{"extensive_seriously_corrupt", "Extensive, seriously corrupt: much of the data, changed in ways that matter.", owasp.LossOfIntegrityExtensiveSeriouslyCorruptData},
		{"all_data_totally_corrupt", "All data totally corrupt: everything this service holds can be overwritten or destroyed.", owasp.LossOfIntegrityAllDataTotallyCorrupt},
		{cannotTell, cannotTellText, owasp.LossOfIntegrityAllDataTotallyCorrupt},
	},
	counter: "integrity_cannot_tell",
}

var availability = contract[owasp.LossOfAvailability]{
	factor:   LAV,
	question: "If {group} exploited this vulnerability in this deployment, how much of this service could they interrupt, and how vital is what they would interrupt?",
	answers: []answer[owasp.LossOfAvailability]{
		{"minimal_secondary_interrupted", "Minimal, secondary: a brief or partial interruption of something the service can do without for a while.", owasp.LossOfAvailabilityMinimalSecondaryServicesInterrupted},
		{"minimal_primary_interrupted", "Minimal, primary: a brief or partial interruption of what the service exists to do.", owasp.LossOfAvailabilityMinimalPrimaryServicesInterrupted},
		{"extensive_secondary_interrupted", "Extensive, secondary: a lasting or broad interruption of things the service can do without for a while.", owasp.LossOfAvailabilityExtensiveSecondaryServicesInterrupted},
		{"extensive_primary_interrupted", "Extensive, primary: a lasting or broad interruption of what the service exists to do.", owasp.LossOfAvailabilityExtensivePrimaryServicesInterrupted},
		{"all_services_completely_lost", "All services completely lost: the service and what runs with it, completely.", owasp.LossOfAvailabilityAllServicesCompletelyLost},
		{cannotTell, cannotTellText, owasp.LossOfAvailabilityAllServicesCompletelyLost},
	},
	counter: "availability_cannot_tell",
}

// actor is what Loss of accountability's answer says of the attacker's
// traces, which Go crosses with traceability.
type actor int

const (
	actorIdentified actor = iota
	actorUnidentified
	actorDefeatsAttribution
)

var accountability = contract[actor]{
	factor:   LAC,
	question: "To exploit this vulnerability in this deployment, must {group} authenticate to this service, and could the exploit let them act as someone else or erase, forge or bypass the records of who did what?",
	answers: []answer[actor]{
		{"identified", "Identified: they must authenticate to this service, and the exploit does not let them act as someone else or tamper with the records of who did what.", actorIdentified},
		{"unidentified", "Unidentified: they need not authenticate to this service, and the exploit does not let them act as someone else or tamper with those records.", actorUnidentified},
		{"defeats_attribution", "Defeats attribution: whether or not they authenticate, the exploit lets them act as someone else, or erase, forge or bypass the records of who did what.", actorDefeatsAttribution},
		{cannotTell, cannotTellText, actorDefeatsAttribution},
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

// Privacy violation's bands are data_subjects' too: Go caps the answer's
// level with the declared band's. none takes OWASP's lowest level, a floor
// for a service holding no personal data.
var privacyViolation = contract[owasp.PrivacyViolation]{
	factor:   PV,
	question: "If {group} exploited this vulnerability in this deployment, how many distinct people's personal data could be disclosed, at most? Choose the band that holds that count.",
	answers: []answer[owasp.PrivacyViolation]{
		{"none", "None: no personal data could be disclosed (0 people).", owasp.PrivacyViolationOneIndividual},
		{"one_individual", "One individual: 1 person.", owasp.PrivacyViolationOneIndividual},
		{"hundreds", "Hundreds: 2 to 999 people; a count under 100 belongs here.", owasp.PrivacyViolationHundredsOfPeople},
		{"thousands", "Thousands: 1,000 to 999,999 people.", owasp.PrivacyViolationThousandsOfPeople},
		{"millions", "Millions: 1,000,000 people or more.", owasp.PrivacyViolationMillionsOfPeople},
		{cannotTell, cannotTellText, owasp.PrivacyViolationMillionsOfPeople},
	},
	counter: "privacy_cannot_tell",
}

// table is the one table the request, the schema and the rules read, so the
// text shown, the enum and the map cannot drift apart.
var table = map[Factor]shown{
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
