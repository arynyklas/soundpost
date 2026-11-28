// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"strings"
	"testing"
)

// The build client (packages/build/src/manifest.ts, test "indexed maps follow the backend policy") mirrors this backend's two depth bounds:
// map nesting counted in maps (root = level 1, at most 8: sourcemap Limits.MaxDepth and transformDocument) and the raw JSON depth that
// model.ValidateJSON enforces (64) for everything else. This test pins the backend side of the same shapes; a change to either bound
// fails one of the two tests.
func TestMapNestingIsBoundedInMapsAndExtensionKeysOnlyByTheRawJSONDepth(t *testing.T) {
	const leaf = `{"version":3,"sources":["src/app.ts"],"names":[],"mappings":"AAAA"}`
	wrap := func(levels int) string {
		doc := leaf
		for i := 1; i < levels; i++ {
			doc = `{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":` + doc + `}]}`
		}
		return doc
	}
	if _, _, err := transformMap([]byte(wrap(8)), false); err != nil {
		t.Fatalf("eight map levels refused: %v", err)
	}
	if _, _, err := transformMap([]byte(wrap(9)), false); err == nil {
		t.Fatal("nine map levels accepted")
	}
	nest := func(depth int) string {
		return strings.Repeat(`{"n":`, depth) + `"x"` + strings.Repeat(`}`, depth)
	}
	withExtension := func(depth int) []byte {
		return []byte(`{"version":3,"sources":["src/app.ts"],"names":[],"mappings":"AAAA","x_deep":` + nest(depth) + `}`)
	}
	if _, _, err := transformMap(withExtension(9), false); err != nil {
		t.Fatalf("nine nested extension objects refused: %v", err)
	}
	if _, _, err := transformMap(withExtension(70), false); err == nil {
		t.Fatal("seventy nested extension objects accepted")
	}
}
