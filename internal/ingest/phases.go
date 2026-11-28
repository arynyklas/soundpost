// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// phaseTime is the calls of one step of Admit and the time they took, summed; the longest one.
type phaseTime struct{ n, ns, maxNS atomic.Uint64 }

func (p *phaseTime) add(from time.Time) {
	d := uint64(time.Since(from))
	p.n.Add(1)
	p.ns.Add(d)
	for {
		m := p.maxNS.Load()
		if d <= m || p.maxNS.CompareAndSwap(m, d) {
			return
		}
	}
}

// phaseTimes is where a batch spends its time before and in Admit (a diagnostic build reports it: PhaseStats).
var phaseTimes struct{ authenticate, resolve, preflight, reserve, appendTime, finalize, revalidate phaseTime }

// NoteAuthenticate adds the time the HTTP layer took to authenticate a source to the phases a diagnostic build reports.
func NoteAuthenticate(from time.Time) { phaseTimes.authenticate.add(from) }

// outcomes counts how Admit ended: the admitted batches, and the refusals by the code of their fault; "bounded" is the requests
// refused by maxInFlight before any work was done for them, "in_flight_max" the most requests in progress at once.
var outcomes struct {
	admitted    atomic.Uint64
	bounded     atomic.Uint64
	inFlightMax atomic.Int64
	refused     sync.Map // model.Code -> *atomic.Uint64
}

func noteOutcome(err error) {
	switch {
	case err == nil:
		outcomes.admitted.Add(1)
	default:
		code := model.Code("other")
		var fault *model.Fault
		if errors.As(err, &fault) {
			code = fault.Code
		}
		counter, _ := outcomes.refused.LoadOrStore(code, new(atomic.Uint64))
		counter.(*atomic.Uint64).Add(1)
	}
}

// finalizeFailed counts the finalizations that failed (the batch is answered as unavailable and retried by its sender) by the
// fault code, or by the type of an error that is not a fault.
var finalizeFailed sync.Map // string -> *atomic.Uint64

func noteFinalizeFailed(err error) {
	cause := fmt.Sprintf("%T", err)
	var fault *model.Fault
	if errors.As(err, &fault) {
		cause = string(fault.Code)
	}
	counter, _ := finalizeFailed.LoadOrStore(cause, new(atomic.Uint64))
	counter.(*atomic.Uint64).Add(1)
}

// PhaseStats is the cumulative calls, time and longest call of each step of a batch's admission, in nanoseconds, and how the
// admissions ended.
func PhaseStats() map[string]any {
	one := func(p *phaseTime) map[string]any {
		return map[string]any{"n": p.n.Load(), "ns": p.ns.Load(), "max_ns": p.maxNS.Load()}
	}
	refused := map[string]any{}
	outcomes.refused.Range(func(code, n any) bool {
		refused[string(code.(model.Code))] = n.(*atomic.Uint64).Load()
		return true
	})
	failed := map[string]any{}
	finalizeFailed.Range(func(cause, n any) bool {
		failed[cause.(string)] = n.(*atomic.Uint64).Load()
		return true
	})
	return map[string]any{"finalize_failed": failed,
		"authenticate": one(&phaseTimes.authenticate), "resolve": one(&phaseTimes.resolve),
		"preflight": one(&phaseTimes.preflight), "reserve": one(&phaseTimes.reserve), "append": one(&phaseTimes.appendTime),
		"finalize": one(&phaseTimes.finalize), "revalidate": one(&phaseTimes.revalidate),
		"admitted": outcomes.admitted.Load(), "bounded": outcomes.bounded.Load(), "in_flight_max": outcomes.inFlightMax.Load(), "refused": refused,
	}
}
