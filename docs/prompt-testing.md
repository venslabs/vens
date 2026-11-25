# Prompt Testing

vens renders its requests in `pkg/contract` and sends them from `pkg/generator`: one system prompt per run, one request per question, and one adjustment request per flagged CVE. The tests hold these texts to the reviewed wording and the rules to the OWASP levels.

## What the tests check

- **Golden frames** (`pkg/contract/golden_test.go`): the system prompt, each question's request and the adjustment's request, for four deployments, equal the files under `pkg/contract/testdata`, and `testdata/SHA256SUMS` pins the sha256 of each frame.
- **Questions and rules** (`pkg/contract/questions_test.go`, `rules_test.go`): which questions a CVE gets, the level each answer maps to, `cannot_tell` and its counters, the adjustment never raising a level.
- **Rendering** (`pkg/contract/render_test.go`): the CVSS lines and the controls a question shows.
- **What reaches a request** (`pkg/generator/prompt_test.go`): the deployment block, the config fields each question shows, and the fields that reach no request, such as `audit_requirement`, `ids`, `siem`, `edr` and the fields vens reads alone.
- **Schemas** (`TestOutputSchemaRequired`): every schema sent closes every object and requires each property, as OpenAI's strict mode needs.
- **Length** (`pkg/generator/length_test.go`): no call sends more than the ceiling, over the committed reports and contexts.

## Before modifying the prompt

1. Run the tests first: `go test ./pkg/contract/... ./pkg/generator/...`
2. Understand which test will fail and why.
3. Rewrite the golden frames with `go test ./pkg/contract/ -run TestGolden -update`, review the diff, and update `pkg/contract/testdata/SHA256SUMS` in the same change: `-update` leaves the sums alone on purpose.

## Common gotchas

| Change | Test that will break |
|--------|---------------------|
| Any change to a question, an answer or the system prompt | `TestGoldenFrames`, then `TestGoldenFramesMatchPinnedSums` |
| Show a config field to a question that should not see it | `TestPromptAuditRequirementConditional` and friends |
| Add a field to a reply schema without requiring it | `TestOutputSchemaRequired` |
| Make the longest call longer than the ceiling | `TestPromptLength` |

## Quick test commands

```bash
# The rendered texts
go test ./pkg/contract/ -run TestGolden -v

# What reaches a request
go test ./pkg/generator/ -run TestPrompt -v

# The rules
go test ./pkg/contract/ -run "TestQuestions|TestRules|TestCannotTell" -v
```
