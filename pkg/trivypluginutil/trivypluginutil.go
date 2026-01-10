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

package trivypluginutil

import (
	"log/slog"
	"os"
	"strings"
)

// IsTrivyPluginMode returns whether the binary is being executed as a trivy plugin mode.
// Not robust.
func IsTrivyPluginMode() bool {
	exe, err := os.Executable()
	if err != nil {
		slog.Error("failed to call os.Executable()", "error", err)
		return false
	}
	return strings.Contains(exe, "/.trivy/plugins/vens")
}
