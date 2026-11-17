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

package generator

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
)

// newDebugRunDir creates this run's directory under parent, private to the
// user: runs sharing a --debug-dir, even in parallel, never overwrite each
// other's files. It returns "" when it can't, which turns debug files off.
func newDebugRunDir(parent string) string {
	if err := os.MkdirAll(parent, 0755); err != nil {
		slog.Error("failed to create the debug dir", "dir", parent, "error", err)
		return ""
	}
	dir, err := os.MkdirTemp(parent, "run-*")
	if err != nil {
		slog.Error("failed to create the debug dir", "dir", parent, "error", err)
		return ""
	}
	slog.Info("Writing debug files", "dir", dir)
	return dir
}

// writeDebugFile writes one file of the run's debug directory, readable by the
// user only since it holds the deployment context and the CVE inventory. A
// failure is logged and the run goes on.
func (g *Generator) writeDebugFile(ctx context.Context, name, content string) {
	path := filepath.Join(g.debugRunDir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		slog.ErrorContext(ctx, "failed to write a debug file", "file", path, "error", err)
	}
}
