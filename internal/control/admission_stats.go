// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// failures counts the failures of the steps of an admission transition by where they happened and the fault code (or the
// type of an error that is not a fault).
var failures sync.Map // string -> *atomic.Uint64

func noteFailure(site string, err error) {
	cause := fmt.Sprintf("%T", err)
	var fault *model.Fault
	if errors.As(err, &fault) {
		cause = string(fault.Code)
	}
	if text := err.Error(); len(text) > 80 {
		cause += " " + text[:80]
	} else {
		cause += " " + text
	}
	counter, _ := failures.LoadOrStore(site+":"+cause, new(atomic.Uint64))
	counter.(*atomic.Uint64).Add(1)
}

// steps is where the time of the steps around an admission transition goes (the owner's lookups before a round, the wait for a
// round, the call to the leader), by name, for a diagnostic build's report: n, ns, max_ns of each.
var steps sync.Map // string -> *stepStat

type stepStat struct{ n, ns, max atomic.Uint64 }

// noteStep adds the time since from to the step named site.
func noteStep(site string, from time.Time) { noteStepD(site, time.Since(from)) }

// noteStepD adds d to the step named site (a count in the unit of d for a step that counts something else).
func noteStepD(site string, dur time.Duration) {
	d := uint64(dur)
	v, ok := steps.Load(site)
	if !ok {
		v, _ = steps.LoadOrStore(site, new(stepStat))
	}
	st := v.(*stepStat)
	st.n.Add(1)
	st.ns.Add(d)
	for old := st.max.Load(); d > old && !st.max.CompareAndSwap(old, d); old = st.max.Load() {
	}
}

// roundLabel is "settle" for a round that carries a settlement and "plain" for the others.
func roundLabel(items []*admissionItem) string {
	for _, it := range items {
		if it.kind == writerSettleAdmissions {
			return "settle"
		}
	}
	return "plain"
}

// stepCounts is the report of noteStep.
func stepCounts() map[string]any {
	out := map[string]any{}
	steps.Range(func(k, v any) bool {
		st := v.(*stepStat)
		out[k.(string)] = map[string]any{"n": st.n.Load(), "ns": st.ns.Load(), "max_ns": st.max.Load()}
		return true
	})
	return out
}

// roundStats is where the admission rounds (admission_group.go) spend their time, for a diagnostic build's report
// (diag_stats_on.go): atomics only, a few additions per round.
type roundStats struct {
	laneBusyNS atomic.Uint64 // wall time the runner of the rounds spent with work (queued or building, and in the proposal)

	attempts, lost     atomic.Uint64 // proposals made, and the ones lost to the application-index race
	items, bytes       atomic.Uint64 // transitions carried by those proposals, and their payload bytes
	queueN, queueNS    atomic.Uint64 // transitions that started a round, and the time they waited in the queue
	queueMaxNS         atomic.Uint64
	lockNS, readNS     atomic.Uint64 // per attempt: waiting for the update lock; the linearizable read barrier
	buildNS, proposeNS atomic.Uint64 // judging the transitions in the read transaction; the proposal until it is decided and applied here
	proposeMaxNS       atomic.Uint64
	shed               atomic.Uint64 // transitions refused because the queue was full
	readsSkipped       atomic.Uint64 // rounds the leader made without the read barrier (its first attempt)
	settleRounds       atomic.Uint64 // proposals that carried a settlement command
	settleCommands     atomic.Uint64 // settlement commands those proposals carried (more than the rounds only when a round carried several)

	kinds sync.Map // writer -> *atomic.Uint64: the items of decided rounds, by the writer that asked
}

func (r *roundStats) waited(items []*admissionItem) {
	now := time.Now()
	for _, it := range items {
		if it.queued.IsZero() {
			continue // a sparse transition: not timed
		}
		d := uint64(now.Sub(it.queued))
		r.queueN.Add(1)
		r.queueNS.Add(d)
		for {
			m := r.queueMaxNS.Load()
			if d <= m || r.queueMaxNS.CompareAndSwap(m, d) {
				break
			}
		}
	}
}

func (r *roundStats) proposed(d time.Duration, items, payload int, lost bool) {
	r.attempts.Add(1)
	r.items.Add(uint64(items))
	r.bytes.Add(uint64(payload))
	r.proposeNS.Add(uint64(d))
	if lost {
		r.lost.Add(1)
	}
	for {
		m := r.proposeMaxNS.Load()
		if uint64(d) <= m || r.proposeMaxNS.CompareAndSwap(m, uint64(d)) {
			break
		}
	}
}

// committed counts the items of a round that was decided, by the writer that asked (a sparse transition of the workers' books by
// "sparse").
func (r *roundStats) committed(items []*admissionItem) {
	for _, it := range items {
		kind := string(it.kind)
		if it.plan != nil {
			kind = "sparse"
		}
		counter, _ := r.kinds.LoadOrStore(kind, new(atomic.Uint64))
		counter.(*atomic.Uint64).Add(1)
	}
}

// settling counts the settlement commands of a proposal: a round carries at most one (admission_group.go), so the two counters stay equal.
func (r *roundStats) settling(items []*admissionItem) {
	n := 0
	for _, it := range items {
		if it.kind == writerSettleAdmissions {
			n++
		}
	}
	if n != 0 {
		r.settleRounds.Add(1)
		r.settleCommands.Add(uint64(n))
	}
}

func (r *roundStats) kindCounts() map[string]any {
	out := map[string]any{}
	r.kinds.Range(func(k, v any) bool {
		out[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	return out
}
