// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"github.com/arynyklas/soundpost/internal/model"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

func safeIdentity(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
func ValidateManifest(m Manifest) error {
	if m.Version != 1 || m.Org == (model.ID{}) || m.Project == (model.ID{}) || m.Source == (model.ID{}) || m.Build == (model.ID{}) || m.GeneratedSHA256 == (model.Hash{}) || m.MapSHA256 == (model.Hash{}) || m.Size == 0 || m.Size > model.ArtifactBundleLimit || m.RetainUntil <= 0 || !safeIdentity(m.DebugID, 256) || strings.ContainsAny(m.DebugID, "/\\:%?#") || !safeIdentity(m.Path, 4096) || strings.ContainsAny(m.Path, "\\:%?#") || strings.HasPrefix(m.Path, "/") || path.Clean(m.Path) != m.Path || m.Path == ".." || strings.HasPrefix(m.Path, "../") {
		return model.Fail(model.Invalid)
	}
	return nil
}
func artifactID(m Manifest) model.ID {
	raw, _ := model.CanonicalJSON(struct {
		Org, Project, Source, Build model.ID
		DebugID, Path               string
		Generated, Map              model.Hash
		Private                     bool
	}{m.Org, m.Project, m.Source, m.Build, m.DebugID, m.Path, m.GeneratedSHA256, m.MapSHA256, m.SourceContent})
	hash := model.HashCanonical(raw)
	var id model.ID
	copy(id[:], hash[:16])
	return id
}
