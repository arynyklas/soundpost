// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/model"
)

// The client (packages/build/src/manifest.ts UNSAFE_TEXT, test "every Unicode format (Cf) rune ...") must reject at least what this
// backend rejects; this list is the same one the client test uses, so a change to either predicate fails one of them.
func TestManifestRejectsEveryUnicodeFormatRuneInPathAndDebugID(t *testing.T) {
	base := artifacts.Manifest{Version: 1, Org: model.ID{1}, Project: model.ID{2}, Source: model.ID{3}, Build: model.ID{4},
		GeneratedSHA256: model.Hash{5}, MapSHA256: model.Hash{6}, Size: 10, RetainUntil: 1, DebugID: "debug", Path: "assets/app.js"}
	if err := artifacts.ValidateManifest(base); err != nil {
		t.Fatalf("baseline manifest rejected: %v", err)
	}
	for _, r := range []rune{0xad, 0x600, 0x605, 0x61c, 0x6dd, 0x70f, 0x890, 0x8e2, 0x180e, 0x200b, 0x200f, 0x202a, 0x202e, 0x2060, 0x2064, 0x2066, 0x206f, 0xfeff, 0xfff9, 0xfffb, 0x110bd, 0x13430, 0x1bca0, 0x1d173, 0xe0001, 0xe0020, 0xe007f} {
		m := base
		m.Path = "assets/a" + string(r) + "pp.js"
		if artifacts.ValidateManifest(m) == nil {
			t.Errorf("path with U+%04X accepted", r)
		}
		m = base
		m.DebugID = "a" + string(r) + "b"
		if artifacts.ValidateManifest(m) == nil {
			t.Errorf("debug id with U+%04X accepted", r)
		}
	}
}
