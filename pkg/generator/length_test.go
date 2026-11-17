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

package generator_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf8"

	"github.com/venslabs/vens/internal/testutil"
	"github.com/venslabs/vens/pkg/generator"
	"github.com/venslabs/vens/pkg/llm"
	"github.com/venslabs/vens/pkg/riskconfig"
	"github.com/venslabs/vens/pkg/scanner"
)

// promptCeiling is the most characters a call may send, system prompt and
// request together: the longest call over the committed reports in the four
// deployments below, 24,106 characters at batch 10, rounded up to the next
// thousand.
const promptCeiling = 25_000

// longest records the longest call it is asked, answered by the mock.
type longest struct {
	mock  *testutil.MockLLM
	chars int
	calls int
}

func (l *longest) Generate(ctx context.Context, req llm.Request) (string, error) {
	l.chars = max(l.chars, utf8.RuneCountInString(req.System)+utf8.RuneCountInString(req.Human))
	l.calls++
	return l.mock.Generate(ctx, req)
}

func readReport(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Ext(path) != ".gz" {
		return b
	}
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	b, err = io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadConfig(t *testing.T, path string) *riskconfig.Config {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := riskconfig.Parse(b)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return cfg
}

// Every call stays under the ceiling: the string sent, system prompt and
// request, on the vens-demo scan and the quickstart's reports, in the
// vens-demo contexts and the quickstart's config, at batch 10 and batch 1.
func TestPromptLength(t *testing.T) {
	reports := []string{
		filepath.Join("..", "scanner", "testdata", "vens-demo-2026-09-23.trivy.json.gz"),
		filepath.Join("..", "..", "examples", "quickstart", "reports", "python-slim.trivy.json"),
		filepath.Join("..", "..", "examples", "quickstart", "reports", "python-slim.grype.json"),
	}
	configs := []string{
		filepath.Join("testdata", "contexts", "internal.yaml"),
		filepath.Join("testdata", "contexts", "internal-api.yaml"),
		filepath.Join("testdata", "contexts", "internet-facing.yaml"),
		filepath.Join("..", "..", "examples", "quickstart", "config.yaml"),
	}
	l := &longest{mock: testutil.NewMockLLM()}
	for _, report := range reports {
		data := readReport(t, report)
		s, err := scanner.DetectFormat(data)
		if err != nil {
			t.Fatal(err)
		}
		vulns, err := s.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, config := range configs {
			for _, batch := range []int{10, 1} {
				g, err := generator.New(generator.Opts{LLM: l, Config: loadConfig(t, config), BatchSize: batch})
				if err != nil {
					t.Fatal(err)
				}
				if err := g.GenerateRiskScore(context.Background(), vulns, nil); err != nil {
					t.Fatalf("%s in %s at batch %d: %v", report, config, batch, err)
				}
			}
		}
	}
	t.Logf("%d calls, the longest %d characters", l.calls, l.chars)
	if l.chars > promptCeiling {
		t.Errorf("a call sends %d characters, over the ceiling of %d", l.chars, promptCeiling)
	}
	// A ceiling far above the longest call no longer says how long the calls are.
	if l.chars < promptCeiling*9/10 {
		t.Errorf("the longest call sends %d characters: set the ceiling from it again", l.chars)
	}
}
