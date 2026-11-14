// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/tools/browserevidence"
)

// The browser release evidence expects fixed row lists of the two smokes. These tests pin them to
// the smokes' own source, so a row added or renamed there cannot silently leave the gate's expected set.

func TestBrowserEvidenceExpectsEveryJourneyRow(t *testing.T) {
	var got []string
	for _, r := range assessJourneys(journeyObservation{}) {
		if !r.Required {
			t.Errorf("journey row %s is not required: the exporter would drop it", r.Name)
		}
		got = append(got, r.Name)
	}
	if strings.Join(got, ",") != strings.Join(browserevidence.JourneyRowIDs, ",") {
		t.Fatalf("assessJourneys rows\n got %v\nlist %v", got, browserevidence.JourneyRowIDs)
	}
}

func TestBrowserEvidenceExpectsEveryEvidenceSmokeRow(t *testing.T) {
	raw, err := os.ReadFile("evidence.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?:rows\.add|fail)\("([a-z_]+)", (true|false)`).FindAllStringSubmatch(src, -1) {
		if m[2] != "true" {
			t.Errorf("evidence smoke row %s is optional: the exporter would drop it", m[1])
		}
		ids[m[1]] = true
	}
	// Failure-only rows of an early abort: they never appear in a complete journey.
	delete(ids, "bootstrap")
	delete(ids, "tenants")
	var got []string
	for id := range ids {
		got = append(got, id)
	}
	sort.Strings(got)
	want := append([]string(nil), browserevidence.EvidenceRowIDs...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("evidence.go rows\n got %v\nlist %v", got, want)
	}
}
