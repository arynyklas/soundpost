// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The build record names the binaries by whatever directory they were built into (bin, or bin4-f1 of a lane that keeps one directory per
// candidate): the result carries their hashes either way. A result that names no soundpost build is refused by the qualify runner, so a
// gate run from a candidate directory used to be unrecordable (L2w20Admission30: the G4 run of bin4-f1).
func TestBuildFactsNameTheBinariesOfAnyBuildDirectory(t *testing.T) {
	const soundpost, harness = "711a1683cf111b0b459afb23b52ec1cd56ebda232232ecb7aee5ef6e9a6c8b36", "e7a4b781fa6b27f2cbc5df57946dac182cd42d8cc6610b8d890bd9ecf62782af"
	for _, dir := range []string{"/home/sp/l2w20load/bin", "/home/sp/l2w20load/bin4-f1", "/opt/build/out"} {
		path := filepath.Join(t.TempDir(), "BUILD.txt")
		text := "source_tree_sha256=86fb4676d926e0998c249d0a14399214a06a19d839146b4eb1d25c00526ddc97\ntags=netgo,osusergo\n" +
			`{"version":"0.0.0-overhead","build_id":"src-86fb4676d926e099"}` + "\n" +
			soundpost + "  " + dir + "/soundpost\n" + harness + "  " + dir + "/singlehost\ngo version go1.27.3 linux/amd64\n"
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		var r Result
		r.buildFacts(path)
		if r.Build.SoundpostSHA256 != soundpost || r.Build.HarnessSHA256 != harness || r.Build.SourceTreeSHA256 == "" || r.Build.VersionJSON == "" || r.Build.Go == "" {
			t.Fatalf("build directory %s: %+v", dir, r.Build)
		}
	}
}
