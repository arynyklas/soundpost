// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"container/list"
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"sync"
	"time"
)

// scheduler is fair admission for running queries: at most `global` run at once,
// at most `perOrg` per organization and `perPrincipal` per principal. Queries
// that cannot start wait in a bounded queue per organization and are admitted
// round-robin across organizations, so one organization's backlog never
// monopolizes the workers. Every refusal is a typed error: a full queue is a
// Quota fault, a wait past maxWait is a Timeout fault and a cancelled wait is a
// Cancelled fault.
type scheduler struct {
	global, perOrg, perPrincipal, maxQueued int
	maxWait                                 time.Duration

	mu        sync.Mutex
	active    int
	orgActive map[model.ID]int
	principal map[principalKey]int
	queues    map[model.ID]*list.List
	ring      []model.ID
	next      int
}
type principalKey struct{ org, principal model.ID }
type waiter struct {
	org, principal model.ID
	ready          chan struct{}
	granted        bool
}

func newScheduler(l Limits) *scheduler {
	return &scheduler{global: l.MaxConcurrent, perOrg: l.MaxPerOrg, perPrincipal: l.MaxPerPrincipal, maxQueued: l.MaxQueuedPerOrg, maxWait: l.MaxQueueWait,
		orgActive: map[model.ID]int{}, principal: map[principalKey]int{}, queues: map[model.ID]*list.List{}}
}

func (s *scheduler) canRun(org, principal model.ID) bool {
	return s.active < s.global && s.orgActive[org] < s.perOrg && s.principal[principalKey{org, principal}] < s.perPrincipal
}
func (s *scheduler) start(org, principal model.ID) {
	s.active++
	s.orgActive[org]++
	s.principal[principalKey{org, principal}]++
}

// Acquire returns the release function of one admitted query.
func (s *scheduler) Acquire(ctx context.Context, org, principal model.ID) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, ctxFault(err)
	}
	s.mu.Lock()
	if s.canRun(org, principal) {
		s.start(org, principal)
		s.mu.Unlock()
		return s.releaser(org, principal), nil
	}
	q := s.queues[org]
	if q != nil && q.Len() >= s.maxQueued || q == nil && s.maxQueued == 0 {
		s.mu.Unlock()
		return nil, model.Fail(model.Quota)
	}
	if q == nil {
		q = list.New()
		s.queues[org] = q
		s.ring = append(s.ring, org)
	}
	w := &waiter{org: org, principal: principal, ready: make(chan struct{})}
	el := q.PushBack(w)
	s.mu.Unlock()

	timer := time.NewTimer(s.maxWait)
	defer timer.Stop()
	var cause error
	select {
	case <-w.ready:
		return s.releaser(org, principal), nil
	case <-ctx.Done():
		cause = ctxFault(ctx.Err())
	case <-timer.C:
		cause = model.Fail(model.Timeout)
	}
	s.mu.Lock()
	if w.granted {
		// The slot was granted as the wait ended: hand it straight back.
		s.mu.Unlock()
		s.releaser(org, principal)()
		return nil, cause
	}
	s.removeLocked(org, el)
	s.mu.Unlock()
	return nil, cause
}
func (s *scheduler) removeLocked(org model.ID, el *list.Element) {
	q := s.queues[org]
	if q == nil {
		return
	}
	q.Remove(el)
	if q.Len() == 0 {
		s.dropQueueLocked(org)
	}
}
func (s *scheduler) dropQueueLocked(org model.ID) {
	delete(s.queues, org)
	for i, id := range s.ring {
		if id == org {
			s.ring = append(s.ring[:i], s.ring[i+1:]...)
			if s.next > i {
				s.next--
			}
			break
		}
	}
	if s.next >= len(s.ring) {
		s.next = 0
	}
}
func (s *scheduler) releaser(org, principal model.ID) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			s.active--
			if s.orgActive[org]--; s.orgActive[org] <= 0 {
				delete(s.orgActive, org)
			}
			key := principalKey{org, principal}
			if s.principal[key]--; s.principal[key] <= 0 {
				delete(s.principal, key)
			}
			s.dispatchLocked()
			s.mu.Unlock()
		})
	}
}

// dispatchLocked grants every slot that can run, starting after the last
// organization served and taking each organization's first eligible waiter.
func (s *scheduler) dispatchLocked() {
	for s.active < s.global && len(s.ring) > 0 {
		granted := false
		for n := 0; n < len(s.ring) && !granted; n++ {
			i := (s.next + n) % len(s.ring)
			org := s.ring[i]
			q := s.queues[org]
			for el := q.Front(); el != nil; el = el.Next() {
				w := el.Value.(*waiter)
				if !s.canRun(w.org, w.principal) {
					continue
				}
				s.start(w.org, w.principal)
				w.granted = true
				close(w.ready)
				q.Remove(el)
				if q.Len() == 0 {
					s.dropQueueLocked(org)
					if len(s.ring) > 0 {
						s.next = i % len(s.ring)
					}
				} else {
					s.next = (i + 1) % len(s.ring)
				}
				granted = true
				break
			}
		}
		if !granted {
			return
		}
	}
}

// schedulerState is a consistent snapshot for observability and tests.
type schedulerState struct{ Active, Queued int }

func (s *scheduler) state() schedulerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	queued := 0
	for _, q := range s.queues {
		queued += q.Len()
	}
	return schedulerState{Active: s.active, Queued: queued}
}
