// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/query/profile"
)

// TestOwnedMatchesRecordedNativeExtendedHistogramObservations replays, without a
// container runtime, the recorded observations of the pinned Prometheus references
// for the native-histogram corners of the smoothed and anchored extended selectors
// (22 histogram scenarios x 12 queries x 5 instants on 3.13.5, plus plain-window
// control rows on both pins; authored by conformance/query/author/ext-histogram-probe.py).
// The probe found one divergence (a smoothed instant selector between an exponential
// and a custom-bucket histogram yields no sample and one MixedExponentialCustomHistogramsWarning),
// fixed in internal/query/promql/select.go.
func TestOwnedMatchesRecordedNativeExtendedHistogramObservations(t *testing.T) {
	var lock SourceLock
	if err := ReadJSON("../../../conformance/query/source-lock.json", &lock); err != nil {
		t.Fatal(err)
	}
	// The recorded observations are content-locked: only the approved bytes are replayed.
	raw, err := readLocked(lock, "evidence/native-promql-extended-histogram-observations.json", "../../../conformance/query/evidence/native-promql-extended-histogram-observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Provenance string `json:"provenance"`
		Rows       []struct {
			Profile   string                `json:"profile"`
			CaseID    string                `json:"case_id"`
			Reference EvaluationObservation `json:"reference"`
		} `json:"rows"`
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	// These references were built natively from the pinned source archive, never run as the
	// digest-locked OCI image: the recorded file says so.
	if !strings.Contains(f.Provenance, "a native build of the pinned source archive") || !strings.Contains(f.Provenance, "not the digest-locked OCI image") {
		t.Fatalf("the recorded observations do not state that the references were a native build of the pinned source archive: %q", f.Provenance)
	}
	// The observations hold the references only; the authored inputs are the locked case file.
	rawCases, err := readLocked(lock, "cases/promql-extended-histograms.json", "../../../conformance/query/cases/promql-extended-histograms.json")
	if err != nil {
		t.Fatal(err)
	}
	var authored struct {
		Cases []EvaluationCase `json:"cases"`
	}
	if err = json.Unmarshal(rawCases, &authored); err != nil {
		t.Fatal(err)
	}
	byID := map[string]EvaluationCase{}
	for _, c := range authored.Cases {
		byID[c.ID] = c
	}
	if len(f.Rows) < 2860 {
		t.Fatalf("recorded extended-selector histogram observations shrank to %d rows", len(f.Rows))
	}
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range f.Rows {
		row := row
		authoredCase, ok := byID[row.CaseID]
		if !ok {
			t.Fatalf("recorded observation names no authored case: %s", row.CaseID)
		}
		authoredCase.Profiles = []string{row.Profile}
		t.Run(row.Profile[len("promql-prometheus-"):]+"/"+row.CaseID, func(t *testing.T) {
			var manifest profile.Profile
			if err := ReadJSON("../../../profiles/query/"+row.Profile+".json", &manifest); err != nil {
				t.Fatal(err)
			}
			sorted := append([]string(nil), authoredCase.Enabled...)
			sort.Strings(sorted)
			featureID := ""
			for _, set := range manifest.FeatureSets {
				candidate := append([]string(nil), set.Enabled...)
				sort.Strings(candidate)
				if strings.Join(candidate, "\x00") == strings.Join(sorted, "\x00") {
					featureID = set.ID
				}
			}
			p, err := registry.Resolve(row.Profile, featureID)
			if err != nil {
				t.Fatal(err)
			}
			owned, err := observeOwnedEvaluation(context.Background(), authoredCase, p)
			if err != nil {
				t.Fatalf("owned observation failed: %v", err)
			}
			if diff := CompareEvaluation(row.Reference, owned); len(diff) != 0 {
				t.Fatalf("owned differs from recorded native observation: %#v\nquery: %s", diff, authoredCase.Query)
			}
		})
	}
}
