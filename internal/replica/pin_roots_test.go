// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"slices"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The artifact roots a pin recorded are durable in its header and reported by Pins, a pin that
// recorded none says so (RootsKnown false), and an empty recorded set stays "known, empty".
func TestPinRecordsContainedRootsAndSurvivesARestart(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	s := openSolo(t, dir, id, nil)
	for range 3 {
		s.propose(Data, "processed")
	}
	processed := uint64(s.group.Status().ApplicationCursor.Index)
	r1, r2 := model.NewID(), model.NewID()
	owner := model.NewID()
	with, err := s.group.PinJournalForRoots(processed, owner, []model.ID{r1, r2})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := s.group.PinJournalForRoots(processed, owner, nil)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := s.group.PinJournalFor(processed, owner)
	if err != nil {
		t.Fatal(err)
	}
	check := func(when string, g *Group) {
		t.Helper()
		pins, err := g.Pins()
		if err != nil || len(pins) != 3 {
			t.Fatalf("%s: pins %+v %v", when, pins, err)
		}
		for _, p := range pins {
			switch p.ID {
			case with.id:
				if !p.RootsKnown || !slices.Equal(p.Roots, []model.ID{r1, r2}) {
					t.Fatalf("%s: recorded roots %+v", when, p)
				}
			case empty.id:
				if !p.RootsKnown || len(p.Roots) != 0 {
					t.Fatalf("%s: empty set %+v", when, p)
				}
			case unknown.id:
				if p.RootsKnown {
					t.Fatalf("%s: a pin that recorded no roots reports a set %+v", when, p)
				}
			default:
				t.Fatalf("%s: unexpected pin %v", when, p.ID)
			}
		}
	}
	check("live", s.group)
	s.close()
	re := openSolo(t, dir, id, nil)
	check("after restart", re.group)
}
