// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestOwnedMatchesRecordedNativeLogQLIntervalObservations replays, without a container runtime,
// the recorded observations of the pinned Loki 3.5.2 reference for raw log queries evaluated with
// interval > 0 over stored rows of multiplicity > 1 (02.07#14): eight fixture families (copies of
// a row in one stream, ties across streams, identical rows with distinct ids, a dense run over two
// streams, a line filter that removes chain members, the interval boundary +-1 ns, rows at and
// before 1970, ties under a label_format that reorders the query-visible labels), up to ten
// intervals, six limits, both directions, range and instant; authored by
// conformance/query/author/logql-interval-probe.py. The owned engine must reproduce every
// observation: a kept entry carries multiplicity 1 (its other copies are at distance 0 and thinned
// away), except after an entry before 1970, where the pinned readStreams outputs every entry; the
// tied entry that a limit or an interval keeps is the one of the lowest original stream hash.
func TestOwnedMatchesRecordedNativeLogQLIntervalObservations(t *testing.T) {
	var lock SourceLock
	if err := ReadJSON("../../../conformance/query/source-lock.json", &lock); err != nil {
		t.Fatal(err)
	}
	// The recorded observations are content-locked: only the approved bytes are replayed.
	raw, err := readLocked(lock, "evidence/native-logql-interval-observations.json", "../../../conformance/query/evidence/native-logql-interval-observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Provenance string `json:"provenance"`
		Rows       []struct {
			CaseID    string           `json:"case_id"`
			Reference LogQLObservation `json:"reference"`
		} `json:"rows"`
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	// This reference was built natively from the pinned source archive, never run as the
	// digest-locked OCI image: the recorded file says so.
	if !strings.Contains(f.Provenance, "a native build of the pinned source archive") || !strings.Contains(f.Provenance, "not the digest-locked OCI image") {
		t.Fatalf("the recorded observations do not state that the reference was a native build of the pinned source archive: %q", f.Provenance)
	}
	// The observations hold the references only; the authored inputs are the locked case file.
	cases, err := readLogQLCases(lock, "../../../conformance/query/cases/logql-interval-multiplicity.json", "logql-metric")
	if err != nil {
		t.Fatal(err)
	}
	// A floor, not an exact count: recorded rows may be added, never silently lost.
	if len(f.Rows) < 970 || len(cases) != len(f.Rows) {
		t.Fatalf("recorded interval observations: %d rows for %d authored cases (floor 970)", len(f.Rows), len(cases))
	}
	byID := map[string]LogQLCase{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	// The probe is not vacuous: most rows ask for a thinning interval over a row of multiplicity > 1.
	thinned := 0
	for _, c := range cases {
		many := false
		for _, e := range c.Entries {
			many = many || e.Multiplicity > 1
		}
		if c.Interval > 0 && many {
			thinned++
		}
	}
	if thinned < 800 {
		t.Fatalf("only %d authored cases carry interval > 0 over a row of multiplicity > 1", thinned)
	}
	p, err := resolveLogQLProfile("../../../profiles/query", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range f.Rows {
		row := row
		c, ok := byID[row.CaseID]
		if !ok {
			t.Fatalf("recorded observation names no authored case: %s", row.CaseID)
		}
		delete(byID, row.CaseID)
		t.Run(strings.TrimPrefix(row.CaseID, "logql-interval-multiplicity/"), func(t *testing.T) {
			owned, err := observeOwnedLogQL(context.Background(), c, p)
			if err != nil {
				t.Fatalf("owned observation failed: %v", err)
			}
			if diff := CompareLogQL(row.Reference, owned); len(diff) != 0 {
				t.Fatalf("owned differs from recorded native observation: %#v\nquery: %s interval %d limit %d %s", diff, c.Query, c.Interval, c.Limit, c.Direction)
			}
		})
	}
	if len(byID) != 0 {
		t.Fatalf("%d authored cases have no recorded observation", len(byID))
	}
}
