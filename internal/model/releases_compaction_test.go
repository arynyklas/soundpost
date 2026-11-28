// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model_test

import (
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func foldEvidence(n int, release func(i int) *model.ID) []model.GroupingEvidence {
	out := make([]model.GroupingEvidence, n)
	for i := range out {
		out[i] = model.GroupingEvidence{
			OccurrenceID: model.ID{0xaa, byte(i >> 8), byte(i)}, EventTime: model.UnixNano(1000 + (i*37)%501), ArrivalTime: model.UnixNano(9000 - (i*53)%977), ReleaseID: release(i),
		}
	}
	return out
}

// Fold is the only way an aggregate grows: it is exact (counts, bounds, first
// event per release, a bounded tail of the newest folded IDs), it never edits its
// receiver, and folding in two steps equals folding at once.
func TestCompactionFoldIsExactAndComposable(t *testing.T) {
	a, b := model.ID{1}, model.ID{2}
	releases := func(i int) *model.ID {
		switch {
		case i%7 == 0:
			return nil
		case i < 40 || i%5 == 0:
			return &a
		default:
			return &b
		}
	}
	list := foldEvidence(900, releases)
	whole := (*model.GroupingCompaction)(nil).Fold(list)

	if whole.Count != 900 {
		t.Fatalf("count %d", whole.Count)
	}
	minE, maxE, minA, maxA := list[0].EventTime, list[0].EventTime, list[0].ArrivalTime, list[0].ArrivalTime
	first := map[model.ID]model.UnixNano{}
	var order []model.ID
	for _, e := range list {
		minE, maxE = min(minE, e.EventTime), max(maxE, e.EventTime)
		minA, maxA = min(minA, e.ArrivalTime), max(maxA, e.ArrivalTime)
		if e.ReleaseID != nil {
			if at, ok := first[*e.ReleaseID]; !ok {
				first[*e.ReleaseID] = e.EventTime
				order = append(order, *e.ReleaseID)
			} else if e.EventTime < at {
				first[*e.ReleaseID] = e.EventTime
			}
		}
	}
	if whole.FirstEvent != minE || whole.LastEvent != maxE || whole.FirstArrival != minA || whole.LastArrival != maxA {
		t.Fatalf("bounds %+v, want event [%d,%d] arrival [%d,%d]", whole, minE, maxE, minA, maxA)
	}
	if len(whole.Releases) != len(order) {
		t.Fatalf("releases %+v", whole.Releases)
	}
	for i, r := range whole.Releases {
		if r.Release != order[i] || r.FirstEvent != first[r.Release] {
			t.Fatalf("release %d: %+v, want %v at %d", i, r, order[i], first[order[i]])
		}
	}
	if len(whole.Recent) != model.GroupingDedupTail {
		t.Fatalf("tail %d", len(whole.Recent))
	}
	for i, id := range whole.Recent {
		if id != list[900-model.GroupingDedupTail+i].OccurrenceID {
			t.Fatalf("tail %d is not the newest folded IDs", i)
		}
	}

	step := (*model.GroupingCompaction)(nil).Fold(list[:333]).Fold(list[333:700]).Fold(list[700:])
	if !reflect.DeepEqual(step, whole) {
		t.Fatalf("folding in steps differs from folding at once:\n%+v\n%+v", step, whole)
	}

	// The receiver is never edited, and an empty fold is a copy.
	before := *step
	before.Recent = append([]model.ID(nil), step.Recent...)
	before.Releases = append([]model.GroupingCompactedRelease(nil), step.Releases...)
	next := step.Fold(list[:1])
	next.Recent[0], next.Releases[0].FirstEvent = model.ID{9}, -1
	if !reflect.DeepEqual(*step, before) {
		t.Fatalf("Fold edited its receiver")
	}
	if same := step.Fold(nil); !reflect.DeepEqual(same, step) || same == step {
		t.Fatalf("an empty fold must be an equal copy")
	}
	if (*model.GroupingCompaction)(nil).Fold(nil) != nil {
		t.Fatalf("nothing folded into nothing is nothing")
	}
	if !whole.ObservedBy(a, first[a]) || whole.ObservedBy(a, first[a]-1) || whole.ObservedBy(model.ID{7}, 1<<40) || (*model.GroupingCompaction)(nil).ObservedBy(a, 1<<40) {
		t.Fatalf("ObservedBy is not the first-event rule")
	}
}
