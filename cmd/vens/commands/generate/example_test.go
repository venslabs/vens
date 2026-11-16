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

package generate

import (
	"strings"
	"testing"

	"github.com/venslabs/vens/pkg/riskconfig"
)

// The config.yaml the help shows loads under the schema this vens reads.
func TestExampleConfigLoads(t *testing.T) {
	_, shown, ok := strings.Cut(Example(), "# Example config.yaml:\n")
	if !ok {
		t.Fatal("Example shows no config.yaml")
	}
	var lines []string
	for _, line := range strings.Split(shown, "\n") {
		if l, ok := strings.CutPrefix(line, "  # "); ok {
			lines = append(lines, l)
		}
	}
	cfg, err := riskconfig.Parse([]byte(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatalf("the example config.yaml does not load: %v", err)
	}
	if cfg.SchemaVersion != riskconfig.SchemaVersion {
		t.Errorf("schema_version %d, want %d", cfg.SchemaVersion, riskconfig.SchemaVersion)
	}
}
