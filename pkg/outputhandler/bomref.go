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
//
// See the License for the specific language governing permissions and
// limitations under the License.

package outputhandler

import (
	"fmt"
	"slices"
	"strings"
)

// UnreferencedError names the vulnerabilities that have no component to point
// at (empty BOMRef), each once and sorted, after prefix; nil when there are
// none. The generate command checks the parsed report with it before any LLM
// call, and Close checks the ratings it was given, so no VEX is written short
// of a CVE.
func UnreferencedError(prefix string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	names := slices.Clone(ids)
	slices.Sort(names)
	names = slices.Compact(names)
	noun := "vulnerabilities"
	if len(names) == 1 {
		noun = "vulnerability"
	}
	return fmt.Errorf("%s: %d %s with no component (empty BOMRef): %s", prefix, len(names), noun, strings.Join(names, ", "))
}
