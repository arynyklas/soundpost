// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// When both generators fail, the SBOM check names both, each as its own item with its format; neither
// error is dropped and neither is printed as `<nil>`.
func TestSBOMCheckNamesBothGeneratorErrors(t *testing.T) {
	f := newFixture(t)
	r := f.reports()
	r.Created = "not-a-timestamp"
	var m ReleaseManifest
	var sbom Check
	for _, c := range checkSupplyChain(r, &m) {
		if c.Name == checkSBOM {
			sbom = c
		}
	}
	if len(sbom.Blocking) != 2 {
		t.Fatalf("want one blocking item per failed generator, got %v", sbom.Blocking)
	}
	if !strings.HasPrefix(sbom.Blocking[0], "SBOM generation failed (cyclonedx): ") || !strings.HasPrefix(sbom.Blocking[1], "SBOM generation failed (spdx): ") {
		t.Fatalf("items must name the format they came from, got %v", sbom.Blocking)
	}
	for _, b := range sbom.Blocking {
		if strings.Contains(b, "<nil>") || !strings.Contains(b, "--created") {
			t.Fatalf("item must carry the generator's own error: %q", b)
		}
	}
}
