// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import "testing"

func metricAt(at UnixNano) Record { return Record{ID: NewID(), Kind: Metric, ObservedAt: at} }

func TestDeletePredicateRangeIsHalfOpenAndScopedToSignalAndProject(t *testing.T) {
	org, p1, p2 := NewID(), NewID(), NewID()
	p := DeletePredicate{Operation: NewID(), Org: org, Mode: DeleteHistoricalRange, Projects: []ID{p1}, Signals: []Kind{Metric}, Start: 10, End: 20}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for at, want := range map[UnixNano]bool{9: false, 10: true, 19: true, 20: false} {
		if got := p.CoversRecord(org, p1, metricAt(at)); got != want {
			t.Fatalf("t=%d covered=%v want %v", at, got, want)
		}
	}
	if p.CoversRecord(org, p2, metricAt(15)) || p.CoversRecord(NewID(), p1, metricAt(15)) {
		t.Fatal("predicate leaked to another project/org")
	}
	if p.CoversRecord(org, p1, Record{ID: NewID(), Kind: Log, ObservedAt: 15}) {
		t.Fatal("predicate leaked to another signal")
	}
}

func TestDeletePredicateRejectsAmbiguousShapes(t *testing.T) {
	org, p1 := NewID(), NewID()
	bad := []DeletePredicate{
		{Operation: NewID(), Org: org, Mode: DeleteHistoricalRange, Projects: []ID{p1}, Start: 1, End: 2}, // no signals is not "all"
		{Operation: NewID(), Org: org, Mode: DeleteHistoricalRange, Projects: []ID{p1}, Signals: []Kind{Metric}, Start: 2, End: 2},
		{Operation: NewID(), Org: org, Mode: DeleteEntity, Projects: []ID{p1, NewID()}, Entities: []ID{NewID()}},
		{Operation: NewID(), Org: org, Mode: DeleteEntity, Projects: []ID{p1}, Entities: []ID{NewID()}, Signals: []Kind{Metric}},
		{Operation: NewID(), Org: org, Mode: DeleteRetireOrg, Projects: []ID{p1}},
		{Operation: NewID(), Org: org, Mode: "wipe"},
	}
	for i, p := range bad {
		if p.Validate() == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}

func TestDeletePredicateEntityCoversOnlyOwnedChunks(t *testing.T) {
	org, project, replay := NewID(), NewID(), NewID()
	p := DeletePredicate{Operation: NewID(), Org: org, Mode: DeleteEntity, Projects: []ID{project}, Entities: []ID{replay}}
	chunk := Record{Kind: Replay, Payload: Payload{Replay: &ReplayChunk{Replay: replay}}}
	other := Record{Kind: Replay, Payload: Payload{Replay: &ReplayChunk{Replay: NewID()}}}
	link := Record{Kind: ErrorKind, Payload: Payload{Error: &ErrorOccurrence{Replay: &replay}}}
	if !p.CoversRecord(org, project, chunk) || p.CoversRecord(org, project, other) || p.CoversRecord(org, project, link) {
		t.Fatal("entity deletion must cover exactly the owned chunks")
	}
	if !p.CoversBlob(BlobManifest{Org: org, Project: project, Root: replay}) || p.CoversBlob(BlobManifest{Org: org, Project: project, Root: NewID()}) {
		t.Fatal("artifact root match")
	}
}

func TestLegalHoldOverlapErrsTowardHolding(t *testing.T) {
	org, p1, p2 := NewID(), NewID(), NewID()
	hold := LegalHold{ID: NewID(), Org: org, Projects: []ID{p1}, Signals: []Kind{Metric}, Start: 100, End: 200}
	rng := func(project ID, s, e UnixNano, k Kind) DeletePredicate {
		return DeletePredicate{Operation: NewID(), Org: org, Mode: DeleteHistoricalRange, Projects: []ID{project}, Signals: []Kind{k}, Start: s, End: e}
	}
	cases := []struct {
		p    DeletePredicate
		want bool
	}{{rng(p1, 150, 160, Metric), true}, {rng(p1, 50, 100, Metric), false}, {rng(p1, 200, 300, Metric), false}, {rng(p1, 199, 300, Metric), true}, {rng(p2, 150, 160, Metric), false}, {rng(p1, 150, 160, Log), false},
		{DeletePredicate{Operation: NewID(), Org: org, Mode: DeleteRetireOrg}, true}, {DeletePredicate{Operation: NewID(), Org: org, Mode: DeleteRetireProject, Projects: []ID{p2}}, false}}
	for i, c := range cases {
		if got := hold.Overlaps(c.p); got != c.want {
			t.Fatalf("case %d overlaps=%v want %v", i, got, c.want)
		}
	}
	released := hold
	released.ReleasedAt = 5
	if released.Overlaps(cases[0].p) {
		t.Fatal("released hold still blocks")
	}
}
