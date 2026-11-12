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

// One type per factor. Its constants are the levels of the calculator's enum
// of the same name, constant for constant; each table lists them for Check.

// SkillLevel is SL, the threat agent's technical skill.
type SkillLevel int

const (
	SkillLevelNoTechnicalSkills           SkillLevel = 1
	SkillLevelSomeTechnicalSkills         SkillLevel = 3
	SkillLevelAdvancedComputerUser        SkillLevel = 5
	SkillLevelNetworkAndProgrammingSkills SkillLevel = 6
	SkillLevelSecurityPenetrationSkills   SkillLevel = 9
)

var skillLevels = []SkillLevel{
	SkillLevelNoTechnicalSkills, SkillLevelSomeTechnicalSkills, SkillLevelAdvancedComputerUser,
	SkillLevelNetworkAndProgrammingSkills, SkillLevelSecurityPenetrationSkills,
}

// Motive is M, what the threat agent gains.
type Motive int

const (
	MotiveLowOrNoReward  Motive = 1
	MotivePossibleReward Motive = 4
	MotiveHighReward     Motive = 9
)

var motives = []Motive{MotiveLowOrNoReward, MotivePossibleReward, MotiveHighReward}

// Opportunity is O, the access and resources an exploit takes.
type Opportunity int

const (
	OpportunityFullAccessOrExpensiveResourcesRequired Opportunity = 0
	OpportunitySpecialAccessOrResourcesRequired       Opportunity = 4
	OpportunitySomeAccessOrResourcesRequired          Opportunity = 7
	OpportunityNoAccessOrResourcesRequired            Opportunity = 9
)

var opportunities = []Opportunity{
	OpportunityFullAccessOrExpensiveResourcesRequired, OpportunitySpecialAccessOrResourcesRequired,
	OpportunitySomeAccessOrResourcesRequired, OpportunityNoAccessOrResourcesRequired,
}

// Size is S, the threat agent group.
type Size int

const (
	SizeDevelopers             Size = 2
	SizeSystemAdministrators   Size = 2
	SizeIntranetUsers          Size = 4
	SizePartners               Size = 5
	SizeAuthenticatedUsers     Size = 6
	SizeAnonymousInternetUsers Size = 9
)

var sizes = []Size{
	SizeDevelopers, SizeSystemAdministrators, SizeIntranetUsers, SizePartners,
	SizeAuthenticatedUsers, SizeAnonymousInternetUsers,
}

// EaseOfDiscovery is ED, how easily the threat agent finds the vulnerability.
type EaseOfDiscovery int

const (
	EaseOfDiscoveryPracticallyImpossible   EaseOfDiscovery = 1
	EaseOfDiscoveryDifficult               EaseOfDiscovery = 3
	EaseOfDiscoveryEasy                    EaseOfDiscovery = 7
	EaseOfDiscoveryAutomatedToolsAvailable EaseOfDiscovery = 9
)

var easesOfDiscovery = []EaseOfDiscovery{
	EaseOfDiscoveryPracticallyImpossible, EaseOfDiscoveryDifficult, EaseOfDiscoveryEasy,
	EaseOfDiscoveryAutomatedToolsAvailable,
}

// EaseOfExploit is EE, how easily the threat agent exploits it.
type EaseOfExploit int

const (
	EaseOfExploitTheoretical             EaseOfExploit = 1
	EaseOfExploitDifficult               EaseOfExploit = 3
	EaseOfExploitEasy                    EaseOfExploit = 5
	EaseOfExploitAutomatedToolsAvailable EaseOfExploit = 9
)

var easesOfExploit = []EaseOfExploit{
	EaseOfExploitTheoretical, EaseOfExploitDifficult, EaseOfExploitEasy, EaseOfExploitAutomatedToolsAvailable,
}

// Awareness is A, how well known the vulnerability is.
type Awareness int

const (
	AwarenessUnknown         Awareness = 1
	AwarenessHidden          Awareness = 4
	AwarenessObvious         Awareness = 6
	AwarenessPublicKnowledge Awareness = 9
)

var awarenesses = []Awareness{AwarenessUnknown, AwarenessHidden, AwarenessObvious, AwarenessPublicKnowledge}

// IntrusionDetection is ID, how likely an exploit is to be detected.
type IntrusionDetection int

const (
	IntrusionDetectionActiveDetectionInApplication IntrusionDetection = 1
	IntrusionDetectionLoggedAndReviewed            IntrusionDetection = 3
	IntrusionDetectionLoggedWithoutReview          IntrusionDetection = 8
	IntrusionDetectionNotLogged                    IntrusionDetection = 9
)

var intrusionDetections = []IntrusionDetection{
	IntrusionDetectionActiveDetectionInApplication, IntrusionDetectionLoggedAndReviewed,
	IntrusionDetectionLoggedWithoutReview, IntrusionDetectionNotLogged,
}

// LossOfConfidentiality is LC, how much data could be disclosed and how
// sensitive it is.
type LossOfConfidentiality int

const (
	LossOfConfidentialityMinimalNonSensitiveDataDisclosed   LossOfConfidentiality = 2
	LossOfConfidentialityMinimalCriticalDataDisclosed       LossOfConfidentiality = 6
	LossOfConfidentialityExtensiveNonSensitiveDataDisclosed LossOfConfidentiality = 6
	LossOfConfidentialityExtensiveCriticalDataDisclosed     LossOfConfidentiality = 7
	LossOfConfidentialityAllDataDisclosed                   LossOfConfidentiality = 9
)

var lossesOfConfidentiality = []LossOfConfidentiality{
	LossOfConfidentialityMinimalNonSensitiveDataDisclosed, LossOfConfidentialityMinimalCriticalDataDisclosed,
	LossOfConfidentialityExtensiveNonSensitiveDataDisclosed, LossOfConfidentialityExtensiveCriticalDataDisclosed,
	LossOfConfidentialityAllDataDisclosed,
}

// LossOfIntegrity is LI, how much data could be corrupted and how badly.
type LossOfIntegrity int

const (
	LossOfIntegrityMinimalSlightlyCorruptData    LossOfIntegrity = 1
	LossOfIntegrityMinimalSeriouslyCorruptData   LossOfIntegrity = 3
	LossOfIntegrityExtensiveSlightlyCorruptData  LossOfIntegrity = 5
	LossOfIntegrityExtensiveSeriouslyCorruptData LossOfIntegrity = 7
	LossOfIntegrityAllDataTotallyCorrupt         LossOfIntegrity = 9
)

var lossesOfIntegrity = []LossOfIntegrity{
	LossOfIntegrityMinimalSlightlyCorruptData, LossOfIntegrityMinimalSeriouslyCorruptData,
	LossOfIntegrityExtensiveSlightlyCorruptData, LossOfIntegrityExtensiveSeriouslyCorruptData,
	LossOfIntegrityAllDataTotallyCorrupt,
}

// LossOfAvailability is LAV, how much service could be lost and how vital it
// is.
type LossOfAvailability int

const (
	LossOfAvailabilityMinimalSecondaryServicesInterrupted   LossOfAvailability = 1
	LossOfAvailabilityMinimalPrimaryServicesInterrupted     LossOfAvailability = 5
	LossOfAvailabilityExtensiveSecondaryServicesInterrupted LossOfAvailability = 5
	LossOfAvailabilityExtensivePrimaryServicesInterrupted   LossOfAvailability = 7
	LossOfAvailabilityAllServicesCompletelyLost             LossOfAvailability = 9
)

var lossesOfAvailability = []LossOfAvailability{
	LossOfAvailabilityMinimalSecondaryServicesInterrupted, LossOfAvailabilityMinimalPrimaryServicesInterrupted,
	LossOfAvailabilityExtensiveSecondaryServicesInterrupted, LossOfAvailabilityExtensivePrimaryServicesInterrupted,
	LossOfAvailabilityAllServicesCompletelyLost,
}

// LossOfAccountability is LAC, whether the threat agent's actions trace back
// to an individual.
type LossOfAccountability int

const (
	LossOfAccountabilityFullyTraceable      LossOfAccountability = 1
	LossOfAccountabilityPossiblyTraceable   LossOfAccountability = 7
	LossOfAccountabilityCompletelyAnonymous LossOfAccountability = 9
)

var lossesOfAccountability = []LossOfAccountability{
	LossOfAccountabilityFullyTraceable, LossOfAccountabilityPossiblyTraceable, LossOfAccountabilityCompletelyAnonymous,
}

// FinancialDamage is FD, the financial damage an exploit causes.
type FinancialDamage int

const (
	FinancialDamageLessThanTheCostToFixTheVulnerability FinancialDamage = 1
	FinancialDamageMinorEffectOnAnnualProfit            FinancialDamage = 3
	FinancialDamageSignificantEffectOnAnnualProfit      FinancialDamage = 7
	FinancialDamageBankruptcy                           FinancialDamage = 9
)

var financialDamages = []FinancialDamage{
	FinancialDamageLessThanTheCostToFixTheVulnerability, FinancialDamageMinorEffectOnAnnualProfit,
	FinancialDamageSignificantEffectOnAnnualProfit, FinancialDamageBankruptcy,
}

// ReputationDamage is RD, the harm to the business's reputation.
type ReputationDamage int

const (
	ReputationDamageMinimalDamage       ReputationDamage = 1
	ReputationDamageLossOfMajorAccounts ReputationDamage = 4
	ReputationDamageLossOfGoodwill      ReputationDamage = 5
	ReputationDamageBrandDamage         ReputationDamage = 9
)

var reputationDamages = []ReputationDamage{
	ReputationDamageMinimalDamage, ReputationDamageLossOfMajorAccounts, ReputationDamageLossOfGoodwill,
	ReputationDamageBrandDamage,
}

// NonCompliance is NC, the exposure non-compliance brings.
type NonCompliance int

const (
	NonComplianceMinorViolation       NonCompliance = 2
	NonComplianceClearViolation       NonCompliance = 5
	NonComplianceHighProfileViolation NonCompliance = 7
)

var nonCompliances = []NonCompliance{NonComplianceMinorViolation, NonComplianceClearViolation, NonComplianceHighProfileViolation}

// PrivacyViolation is PV, how many people's personal information could be
// disclosed.
type PrivacyViolation int

const (
	PrivacyViolationOneIndividual     PrivacyViolation = 3
	PrivacyViolationHundredsOfPeople  PrivacyViolation = 5
	PrivacyViolationThousandsOfPeople PrivacyViolation = 7
	PrivacyViolationMillionsOfPeople  PrivacyViolation = 9
)

var privacyViolations = []PrivacyViolation{
	PrivacyViolationOneIndividual, PrivacyViolationHundredsOfPeople, PrivacyViolationThousandsOfPeople,
	PrivacyViolationMillionsOfPeople,
}
