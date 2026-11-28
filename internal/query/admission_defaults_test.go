// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// The shipped admission defaults let ten interactive queries run at once (the Queries gate row), from ten
// organizations and from one organization's principals, without any of them waiting in the queue. With
// the former defaults (8 running, 2 per principal) the ninth and tenth query of a closed-loop mix always
// queued behind the heavy 24 h queries, and the queue wait was the p95 of every fast class.
func TestDefaultAdmissionRunsTenInteractiveQueriesWithoutQueueing(t *testing.T) {
	const active = 10
	id := func(n byte) model.ID { return model.ID{n} }
	cases := map[string]func(i int) (org, principal model.ID){
		"ten organizations, one principal each": func(i int) (model.ID, model.ID) { return id(byte(i + 1)), id(byte(i + 101)) },
		"five organizations, two principals":    func(i int) (model.ID, model.ID) { return id(byte(i%5 + 1)), id(byte(i + 101)) },
	}
	for name, who := range cases {
		t.Run(name, func(t *testing.T) {
			l := DefaultLimits()
			s := newScheduler(l)
			var releases []func()
			for i := range active {
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				org, principal := who(i)
				release, err := s.Acquire(ctx, org, principal)
				cancel()
				if err != nil {
					t.Fatalf("query %d of %d did not start at once: %v (limits %d/%d/%d)", i+1, active, err, l.MaxConcurrent, l.MaxPerOrg, l.MaxPerPrincipal)
				}
				releases = append(releases, release)
			}
			if st := s.state(); st.Active != active || st.Queued != 0 || st.Stats.Queued != 0 {
				t.Fatalf("active %d queued %d (ever queued %d), want %d running and none queued", st.Active, st.Queued, st.Stats.Queued, active)
			}
			for _, r := range releases {
				r()
			}
		})
	}
}

// A query that has to queue is counted against the limit that blocked it, so the operator and the gate can
// say which limit a workload runs into.
func TestAdmissionCountsTheLimitThatBlocked(t *testing.T) {
	l := DefaultLimits()
	l.MaxConcurrent, l.MaxPerOrg, l.MaxPerPrincipal, l.MaxQueuedPerOrg, l.MaxQueueWait = 3, 2, 1, 4, 100*time.Millisecond
	s := newScheduler(l)
	org, other := model.ID{1}, model.ID{2}
	p, q := model.ID{11}, model.ID{12}
	hold := func(org, principal model.ID) func() {
		r, err := s.Acquire(context.Background(), org, principal)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r1 := hold(org, p)
	r2 := hold(org, q)
	r3 := hold(other, p)
	wait := func(org, principal model.ID) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := s.Acquire(ctx, org, principal); err == nil {
			t.Fatal("a query over a limit started")
		}
	}
	wait(org, p)   // global (3 of 3), org (2 of 2) and principal (1 of 1)
	wait(other, q) // global only
	st := s.state().Stats
	if st.Queued != 2 || st.BlockedGlobal != 2 || st.BlockedOrg != 1 || st.BlockedPrincipal != 1 {
		t.Fatalf("%+v", st)
	}
	r1()
	r2()
	r3()
}
