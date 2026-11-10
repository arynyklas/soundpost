// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"soundpost/internal/model"
	"testing"
	"time"
)

// TestPerOrgCapBoundsOneOrganizationsWorkers pins the per-organization clause of
// the admission rule on its own: the global cap (2) and the per-principal cap
// (1) both have room for a second principal of the same organization, so only
// the per-organization cap (1) can refuse it. Another organization must still
// get the remaining global worker.
func TestPerOrgCapBoundsOneOrganizationsWorkers(t *testing.T) {
	l := DefaultLimits()
	l.MaxConcurrent, l.MaxPerOrg, l.MaxPerPrincipal, l.MaxQueuedPerOrg = 2, 1, 1, 0
	s := newScheduler(l)
	bg := context.Background()
	orgA, orgB := model.NewID(), model.NewID()
	p1, p2, q1 := model.NewID(), model.NewID(), model.NewID()

	r1, err := s.Acquire(bg, orgA, p1)
	if err != nil {
		t.Fatal(err)
	}
	if r2, err := s.Acquire(bg, orgA, p2); err == nil {
		r2()
		t.Fatalf("a second principal of the same organization ran past MaxPerOrg=1 (active=%d)", s.state().Active)
	} else if code(err) != model.Quota {
		t.Fatalf("the per-organization refusal is a typed Quota fault, got %v", err)
	}
	rb, err := s.Acquire(bg, orgB, q1)
	if err != nil {
		t.Fatalf("another organization must keep the free global worker: %v", err)
	}
	if st := s.state(); st.Active != 2 || st.Queued != 0 {
		t.Fatalf("%+v", st)
	}
	r1()
	r2, err := s.Acquire(bg, orgA, p2)
	if err != nil {
		t.Fatalf("the organization's slot is free again after release: %v", err)
	}
	r2()
	rb()
	if st := s.state(); st.Active != 0 || st.Queued != 0 {
		t.Fatalf("slots leaked: %+v", st)
	}
}

// TestOneOrganizationsPrincipalsCannotOccupyEveryWorker queues the principals
// of one organization that are over its cap instead of refusing them, and shows
// that a different organization is admitted at once while the first
// organization's queued principals wait for the organization's own slot, not for
// a global one.
func TestOneOrganizationsPrincipalsCannotOccupyEveryWorker(t *testing.T) {
	l := DefaultLimits()
	l.MaxConcurrent, l.MaxPerOrg, l.MaxPerPrincipal, l.MaxQueuedPerOrg, l.MaxQueueWait = 3, 2, 1, 4, 5*time.Second
	s := newScheduler(l)
	bg := context.Background()
	orgA, orgB := model.NewID(), model.NewID()
	p := []model.ID{model.NewID(), model.NewID(), model.NewID(), model.NewID()}

	a1, err := s.Acquire(bg, orgA, p[0])
	if err != nil {
		t.Fatal(err)
	}
	a2, err := s.Acquire(bg, orgA, p[1])
	if err != nil {
		t.Fatal(err)
	}
	third := make(chan func(), 1)
	go func() {
		r, err := s.Acquire(bg, orgA, p[2])
		if err != nil {
			t.Errorf("queued third principal: %v", err)
			third <- func() {}
			return
		}
		third <- r
	}()
	for deadline := time.Now().Add(5 * time.Second); s.state().Queued != 1; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the third principal of one organization was not queued: %+v", s.state())
		}
	}
	select {
	case <-third:
		t.Fatalf("the third principal of one organization took the third global worker (active=%d)", s.state().Active)
	case <-time.After(100 * time.Millisecond):
	}
	if st := s.state(); st.Active != 2 {
		t.Fatalf("the organization holds exactly its two workers: %+v", st)
	}

	b1, err := s.Acquire(bg, orgB, p[3])
	if err != nil {
		t.Fatalf("a second organization must still find a worker: %v", err)
	}
	a1()
	select {
	case r := <-third:
		r()
	case <-time.After(5 * time.Second):
		t.Fatal("releasing one of the organization's workers must admit its queued principal")
	}
	a2()
	b1()
	if st := s.state(); st.Active != 0 || st.Queued != 0 {
		t.Fatalf("slots leaked: %+v", st)
	}
}
