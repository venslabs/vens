# Prompt Testing

The LLM prompt is tested in `pkg/generator/prompt_test.go`. These tests ensure the prompt stays consistent with the OWASP Risk Rating Methodology.

## What the tests check

- **Structure**: Role definition, section ordering (Role → Context → Task → Output)
- **OWASP factors**: All 4 factors present (Threat Agent, Vulnerability, Technical Impact, Business Impact)
- **Score ranges**: 0-9 scale with anchoring values (1-3, 4-6, 7-9)
- **Conditional sections**: Security controls, compliance, availability, audit requirements
- **Output format**: JSON schema fields, example validity

## Before modifying the prompt

1. Run the tests first: `go test ./pkg/generator/... -run TestPrompt`
2. Understand which test will fail and why
3. Update the test if your change is intentional

## Common gotchas

| Change | Test that will break |
|--------|---------------------|
| Remove "You are" at start | `TestPromptRoleDefinition` |
| Change section order | `TestPromptStructureOrder` |
| Remove a scoring range like "7-9" | `TestPromptAnchoringValues` |
| Remove "Cap at 9" | `TestPromptScoreNormalization` |
| Add conditional text without config check | `TestPromptSecurityControlsConditional` and friends |
| Break the JSON example | `TestOutputExampleValidJSON` |

## Adding new prompt features

If you add a conditional section (like compliance requirements):

1. Add a test that checks it's absent when the config field is empty
2. Add a test that checks it's present when the config field is set
3. See `TestPromptComplianceConditional` for the pattern

## Quick test commands

```bash
# All prompt tests
go test ./pkg/generator/... -run TestPrompt -v

# Just structure tests
go test ./pkg/generator/... -run "TestPromptCore|TestPromptStructure" -v

# Just conditional logic tests
go test ./pkg/generator/... -run "Conditional" -v
```
