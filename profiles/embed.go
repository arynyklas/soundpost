// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package profiles embeds the pinned query-engine profile manifests so a built
// binary carries exactly the profiles the repository's conformance lock pins,
// instead of reading a loose directory at runtime.
package profiles

import (
	"embed"
	"io/fs"
)

//go:embed query/*.json
var query embed.FS

// Query returns the pinned PromQL and LogQL profile manifests as a filesystem
// whose root holds one JSON file per profile, the shape profile.Load reads.
func Query() (fs.FS, error) {
	return fs.Sub(query, "query")
}
