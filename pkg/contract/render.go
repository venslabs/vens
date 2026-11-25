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
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/venslabs/vens/pkg/cvss"
)

// The frames of every call. A {name} is filled in; the braces of the reply
// formats are sent as written.

const systemTemplate = `You are a security expert. You answer questions of the OWASP Risk Rating Methodology about vulnerabilities found in one deployment, described below. Each request lists vulnerabilities, then asks questions about them, each with its closed list of answers.

DEPLOYMENT
{deployment}

Judge each vulnerability from its own entry and this deployment. Choose cannot_tell only when the facts given do not decide between the other answers. In reasoning, state in one sentence the fact that decides the answer, before giving it.`

// reachabilityParagraph is 5f797bf's definition of reachability in the
// system prompt, which #310's C1 drops with the reachability question. S1's
// preregistration decides whether it stays dropped or comes back rewritten;
// to restore it, put it after the last paragraph's first sentence. 5f797bf
// also went on after "do not decide between the other answers" with ": an
// answer saying that the vulnerability is not reachable here, or that
// exploiting it has no such impact, is chosen like any other", naming
// answers C1 and C2 remove.
const reachabilityParagraph = "A vulnerability is reachable here when this deployment, as it is deployed, runs its vulnerable code where some input or action could trigger it, whatever access or effort that takes: how much it takes is for the questions on access and ease. It is not reachable here only when the facts given show it: this deployment does not run the vulnerable code, or nothing can trigger it here, as when it lies in a component, feature, platform or configuration this deployment does not use. When the facts given do not show it, judge the vulnerability as reachable."

// The deployment's lines. Description and Notes are left out when unset, and
// Listener when unknown.
const (
	projectLine     = "Project: {name}"
	descriptionLine = "Description: {description}"
	exposureLine    = "Exposure: {exposure} ({exposure_meaning}). The attacker group to consider is {group}."
	listenerLine    = "Listener: {listener} ({listener_meaning})."
	notesLine       = "Notes: {notes}"
)

// The entries come first, so that the part the questions of a batch share is
// a prefix of each request.
const requestTemplate = `VULNERABILITIES
{entries}

QUESTION
{question}
{facts}
ANSWERS
{answers}

Answer every vulnerability listed above once, by its vulnId, with {how_many} from ANSWERS.
Reply with {"answers": [{"vulnId": "...", "reasoning": "...", "answer": {answer_shape}}]}.`

const cvssSentence = `CVSS metrics {metrics} of the newest CVSS version published for each vulnerability, one line per source that published a vector; the sources can disagree. A vulnerability with no line has no published vector.`

// cvssShown names the metrics of the newest CVSS version a question shows.
// Only Opportunity and Ease of exploit are shown any; C, I and A are Go's,
// read for Loss of confidentiality, integrity and availability.
var cvssShown = map[Factor][]string{
	O:  {"AV", "AT", "PR", "UI"},
	EE: {"AC", "AT", "PR", "UI"},
}

// fill replaces each {name} placeholder in one pass, so that a value holding
// a placeholder's name is sent as written.
func fill(template string, pairs ...string) string {
	return strings.NewReplacer(pairs...).Replace(template)
}

func group(d Deployment) string {
	return exposures[d.Exposure.Value].group
}

// SystemPrompt returns the system prompt every call of a run shares: the
// role, the deployment and the rules.
func SystemPrompt(d Deployment) (string, error) {
	if err := d.Check(); err != nil {
		return "", err
	}
	lines := []string{fill(projectLine, "{name}", d.Name)}
	if d.Description != "" {
		lines = append(lines, fill(descriptionLine, "{description}", d.Description))
	}
	lines = append(lines, fill(exposureLine,
		"{exposure}", d.Exposure.Value, "{exposure_meaning}", d.Exposure.Meaning, "{group}", group(d)))
	if listenerShown(d.Listener.Value) {
		lines = append(lines, fill(listenerLine, "{listener}", d.Listener.Value, "{listener_meaning}", d.Listener.Meaning))
	}
	if d.Notes != "" {
		lines = append(lines, fill(notesLine, "{notes}", d.Notes))
	}
	return fill(systemTemplate, "{deployment}", strings.Join(lines, "\n")), nil
}

// Request returns the request of factor f's call over a batch: the batch's
// CVE entries, then the question, its facts and its closed answers. Each CVE
// of the batch is one the question is asked about.
func Request(f Factor, d Deployment, batch []CVE) (string, error) {
	q, ok := table[f]
	if !ok {
		return "", fmt.Errorf("%q is not a model-answered factor", f)
	}
	if err := d.Check(); err != nil {
		return "", err
	}
	if f == NC && len(d.Frameworks) == 0 {
		return "", errors.New("non-compliance is not asked when no framework is declared")
	}
	entries, err := entriesJSON(batch)
	if err != nil {
		return "", err
	}
	answers := make([]string, len(q.ids))
	for i, id := range q.ids {
		answers[i] = "- " + id + ": " + q.texts[i]
	}
	howMany, shape := "one answer id", `"..."`
	if f == ID {
		howMany, shape = "one or more answer ids", `["...", ...]`
	}
	return fill(requestTemplate,
		"{entries}", entries,
		"{question}", fill(q.question, "{group}", group(d), "{frameworks}", strings.Join(d.Frameworks, ", ")),
		"{facts}", facts(f, d, batch),
		"{answers}", strings.Join(answers, "\n"),
		"{how_many}", howMany,
		"{answer_shape}", shape,
	), nil
}

// facts is the block of a question's background lines and CVSS lines, empty
// for a question shown neither.
func facts(f Factor, d Deployment, batch []CVE) string {
	lines := background(f, d)
	if metrics, ok := cvssShown[f]; ok {
		lines = append(lines, fill(cvssSentence, "{metrics}", strings.Join(metrics, ", ")))
		lines = append(lines, cvssLines(metrics, batch)...)
	}
	if len(lines) == 0 {
		return ""
	}
	return "\nFOR THIS QUESTION\n" + strings.Join(lines, "\n") + "\n"
}

// background returns the config a question shows besides the deployment. A
// question Go crosses with a config field never shows that field.
func background(f Factor, d Deployment) []string {
	switch f {
	case M:
		return []string{setting("Business criticality", d.BusinessCriticality), setting("Data sensitivity", d.DataSensitivity)}
	case EE:
		if line := controlsLine(d.Controls); line != "" {
			return []string{line}
		}
	case PV:
		return []string{setting("Data sensitivity", d.DataSensitivity)}
	}
	return nil
}

func setting(label string, s Setting) string {
	return label + ": " + s.Value + " (" + s.Meaning + ")"
}

func controlsLine(controls []Control) string {
	var shown []string
	for _, key := range controlKeys {
		i := slices.IndexFunc(controls, func(c Control) bool { return c.Key == key })
		if i >= 0 {
			c := controls[i]
			shown = append(shown, c.Key+" ("+c.Description+"; scope: "+c.Scope+")")
		}
	}
	if len(shown) == 0 {
		return ""
	}
	return "Controls in front of this deployment: " + strings.Join(shown, "; ")
}

// cvssLines returns, per CVE in batch order, one line per distinct vector
// published at the newest CVSS version the scanner reports among its rows'
// vectors, or every vector when none reports a version vens reads, so that a
// CVE with no line has no published vector. A line shows the metrics as
// published: the model reads the vector as text, and a value off its
// version's scale or a vector that does not parse still says what its
// source wrote.
func cvssLines(metrics []string, batch []CVE) []string {
	var lines []string
	for _, c := range batch {
		vectors := c.vectors()
		newest := cvss.Newest(vectors)
		for _, v := range vectors {
			if v.Tier() != newest {
				continue
			}
			values := published(v.Vector)
			var shown []string
			for _, metric := range metrics {
				if value, ok := values[metric]; ok {
					shown = append(shown, metric+":"+value)
				}
			}
			line := fmt.Sprintf("- %s: CVSS %s, %s: %s", oneLine(c.ID), oneLine(v.Version), oneLine(v.Source), strings.Join(shown, " "))
			if !slices.Contains(lines, line) {
				lines = append(lines, line)
			}
		}
	}
	return lines
}

// published returns a vector's metrics as its source wrote them, the parts
// between slashes, spaces and control characters each split at their first
// colon: a part with none is skipped and a metric written twice takes its
// last value. Splitting there keeps a value from carrying another metric, or
// a line break that would forge a line of the request.
func published(vector string) map[string]string {
	values := map[string]string{}
	parts := strings.FieldsFunc(vector, func(r rune) bool {
		return r == '/' || unicode.IsSpace(r) || unicode.IsControl(r)
	})
	for _, part := range parts {
		if metric, value, ok := strings.Cut(part, ":"); ok {
			values[metric] = value
		}
	}
	return values
}

// oneLine replaces each control character, and each space other than a plain
// one, with a plain space: a scanner's field written into a line of the
// request cannot break it.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || (unicode.IsSpace(r) && r != ' ') {
			return ' '
		}
		return r
	}, s)
}
