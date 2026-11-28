// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// Every pin carries the owner stamp it was taken with, durably: the stamp is reported by Pins, and
// survives the process that took the pin dying, so a reaper can tell which dead owner holds it.
func TestPinOwnerStampIsReportedAndSurvivesARestart(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	s := openSolo(t, dir, id, nil)
	for range 4 {
		s.propose(Data, "processed")
	}
	processed := uint64(s.group.Status().ApplicationCursor.Index)
	ownerA, ownerB := model.NewID(), model.NewID()
	pinA, err := s.group.PinJournalFor(processed, ownerA)
	if err != nil {
		t.Fatal(err)
	}
	pinB, err := s.group.PinJournalFor(processed, ownerB)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := s.group.PinJournal(processed)
	if err != nil {
		t.Fatal(err)
	}
	want := map[model.ID]model.ID{pinA.id: ownerA, pinB.id: ownerB, plain.id: {}}
	check := func(when string, g *Group) {
		t.Helper()
		pins, err := g.Pins()
		if err != nil || len(pins) != 3 {
			t.Fatalf("%s: pins %+v %v", when, pins, err)
		}
		for _, p := range pins {
			if stamp, ok := want[p.ID]; !ok || p.Stamp != stamp {
				t.Fatalf("%s: pin %v has stamp %v, want %v", when, p.ID, p.Stamp, stamp)
			}
		}
	}
	check("live", s.group)
	s.close() // the process dies
	re := openSolo(t, dir, id, nil)
	check("after restart", re.group)

	// A reaper filtering on owner A drops exactly A's pin.
	pins, _ := re.group.Pins()
	for _, p := range pins {
		if p.Stamp == ownerA {
			if err = re.group.DropPin(p.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	left, err := re.group.Pins()
	if err != nil || len(left) != 2 {
		t.Fatalf("after dropping owner A: %+v %v", left, err)
	}
	for _, p := range left {
		if p.Stamp == ownerA {
			t.Fatalf("owner A's pin survived: %+v", p)
		}
	}
}
