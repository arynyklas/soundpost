// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package uibundle is the one rule for what a built UI bundle must contain to be served: the server
// (httpapi.UIRoutes) refuses to start on a bundle that fails it, and the release build
// (build release) refuses to embed one, so a release that cannot start is never produced.
package uibundle

import (
	"fmt"
	"io/fs"
	"regexp"
	"strings"
)

var assetRef = regexp.MustCompile(`(?:src|href)="(/assets/[^"?#]+)"`)

// Check is nil for a bundle with an index that has the application root, a script, and every asset
// the index references present and non-empty.
func Check(assets fs.FS) error {
	if assets == nil {
		return fmt.Errorf("UI assets required")
	}
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		return fmt.Errorf("UI index: %w", err)
	}
	if !strings.Contains(string(index), `id="root"`) {
		return fmt.Errorf("UI root missing")
	}
	script := false
	for _, ref := range assetRef.FindAllSubmatch(index, -1) {
		name := strings.TrimPrefix(string(ref[1]), "/")
		if !fs.ValidPath(name) {
			return fmt.Errorf("invalid UI asset")
		}
		info, e := fs.Stat(assets, name)
		if e != nil || info.IsDir() || info.Size() == 0 {
			return fmt.Errorf("missing UI asset %s", name)
		}
		if strings.HasSuffix(name, ".js") {
			script = true
		}
	}
	if !script {
		return fmt.Errorf("built UI module missing")
	}
	return nil
}
