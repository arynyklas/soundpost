// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The loader hands back a spec only if it is sound: a document that decodes strictly but declares
// something the generator cannot honour (here a language without profiles) is an error, never a spec.
func TestLoadGenerationSpecValidatesWhatItDecodes(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, s GenerationSpec) string {
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err = os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	sound := cloneSpec(t, realSpec(t))
	if _, err := LoadGenerationSpec(write("sound.json", sound)); err != nil {
		t.Fatalf("the locked spec was refused: %v", err)
	}
	unsound := cloneSpec(t, realSpec(t))
	unsound.Languages[0].Profiles = nil
	spec, err := LoadGenerationSpec(write("unsound.json", unsound))
	if err == nil || !strings.Contains(err.Error(), "language promql has no profiles") {
		t.Fatalf("an unsound spec was loaded: %v (%d languages)", err, len(spec.Languages))
	}
}
