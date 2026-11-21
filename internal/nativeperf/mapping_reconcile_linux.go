//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Reconciliation (04.06): the kernel announces executable mmaps but not mremap, mprotect or munmap, so the helper
// compares the process's real maps with what the announcements predict, every mappingReconcileInterval and once more
// before the final proof of a stopped capture, and publishes only the ranges that differ plus a confirmation that the
// rest matched (mapping_epoch.go explains how a consumer uses them). The reader does the bounded, identity-checked
// read; nothing here opens a file or a path.
const mappingReconcileInterval = 250 * time.Millisecond

// reconciler is the prediction of one target's mapping table: the last read, then every announcement since.
type reconciler struct {
	reader  *MappingReader
	process ProcessKey
	model   []mappingEntry
	lastAt  model.MonoNano // the end of the last group's read
	pending []timedMapping // announcements of this process after the last read's end, in arrival order
}

func (s *ProfileSource) announce(e SanitizedEvent) {
	if e.Kind != EventMapping || e.Mapping == nil || e.Mapping.Snapshot {
		return
	}
	for _, r := range s.recon {
		if r.process == e.Mapping.Process {
			r.pending = append(r.pending, timedMapping{at: e.Time, m: *e.Mapping})
		}
	}
}

// sweepNow returns every mapping announcement and ring overflow already written to the rings, oldest first, and
// feeds the announcements to the predictions. A bounded sweep that dropped records ends with a ring overflow.
func (s *ProfileSource) sweepNow(sampleTime model.MonoNano) ([]SanitizedEvent, error) {
	sweeper, ok := s.source.(sidebandSweeper)
	if !ok {
		return nil, nil
	}
	events, full, e := sweeper.sweepSideband()
	if e != nil {
		s.invalidateReaders()
		return nil, e
	}
	if full {
		// The announcements past the bound were dropped: say so as a ring overflow at the first of them.
		at := sampleTime
		if len(events) > 0 {
			at = events[0].Time
		}
		events = append(events, SanitizedEvent{Kind: EventLoss, Time: at, Domain: s.domain, Loss: &LossEvent{Count: 1, Reason: ReasonLoss}})
	}
	for _, event := range events {
		s.announce(event)
	}
	return events, nil
}

// enrich queues, ahead of the item just fetched (s.pending[0]): for a CPU sample, every announcement and overflow the
// kernel had already written, so the consumer holds all of them older than the sample; and, when one is due, a
// reconciliation group that confirms (or corrects) the interval the sample lies in.
func (s *ProfileSource) enrich(ctx context.Context) error {
	item := s.pending[0]
	cpu := item.Event != nil && item.Event.Kind == EventCPU
	s.mu.Lock()
	final := item.Proof != nil && item.Proof.Final && s.finalDue
	s.mu.Unlock()
	if !cpu && !final {
		return nil
	}
	var at model.MonoNano
	if cpu {
		at = item.Event.Time
	}
	ahead, e := s.sweepNow(at)
	if e != nil {
		return e
	}
	if final || time.Now().After(s.nextReconcile) {
		more, e := s.reconcile(ctx, final)
		if e != nil {
			return e
		}
		ahead = append(ahead, more...)
	}
	if len(ahead) == 0 {
		return nil
	}
	items := make([]AcquisitionItem, 0, len(ahead)+1)
	for i := range ahead {
		items = append(items, AcquisitionItem{Event: &ahead[i]})
	}
	s.pending = append(items, item)
	return nil
}

// reconcile reads every target's maps, compares them with the prediction and returns the group's events. A read the
// reader refuses for its rate limit, or that saw the maps change while it ran, is skipped and tried again later (the
// consumer then simply has no confirmation for that stretch); a failed identity check is the capture's failure.
func (s *ProfileSource) reconcile(ctx context.Context, final bool) ([]SanitizedEvent, error) {
	var out []SanitizedEvent
	for _, r := range s.recon {
		var table MappingTable
		var since model.MonoNano
		var err error
		for range 3 {
			if since, err = schedulerNow(); err != nil {
				return nil, err
			}
			if table, err = r.reader.Read(ctx); !errors.Is(err, ErrResourceBudget) || !final {
				break
			}
			// the stopped capture owes its last confirmation: wait out the reader's minimum interval
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(r.reader.policy.MinReadInterval + 10*time.Millisecond):
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(err, ErrResourceBudget) || r.reader.Guard() == nil {
				continue
			}
			s.invalidateReaders()
			return nil, err
		}
		at, err := schedulerNow()
		if err != nil {
			return nil, err
		}
		// announcements written while the read ran are part of the prediction up to its end
		late, err := s.sweepNow(at)
		if err != nil {
			return nil, err
		}
		out = append(out, late...)
		sort.SliceStable(r.pending, func(i, j int) bool { return r.pending[i].at < r.pending[j].at })
		predicted := r.model
		next := table.entries
		var keep []timedMapping
		for _, u := range r.pending {
			switch {
			case u.at <= r.lastAt:
				// older than the previous group's read: not part of what the consumer replays after it
			case u.at <= at:
				predicted = paint(predicted, entryOf(u.m))
			default:
				next = paint(next, entryOf(u.m))
				keep = append(keep, u)
			}
		}
		for _, row := range diffEntries(r.process, predicted, table.entries, since, at) {
			out = append(out, SanitizedEvent{Kind: EventMapping, Time: at, Domain: s.domain, Mapping: &row})
		}
		out = append(out, confirmEvent(r.process, s.domain, since, at))
		r.model, r.pending, r.lastAt = next, keep, at
	}
	s.nextReconcile = time.Now().Add(mappingReconcileInterval)
	return out, nil
}
