// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"io"
	"math"
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// A range query evaluates every grid step as an instant, and the windows of
// consecutive steps overlap whenever the step is not longer than the range
// interval. Reading each step's window from storage separately scans and
// pipelines a row once per window that holds it. The union scan reads the
// union of the windows of one range selector once, runs the pipeline over each
// row once, keeps the few facts the accumulation needs, and answers every step
// from those rows. The per-row facts are step independent: the pipeline sees
// the row, never the evaluation time (only the wall clock of a `now` template
// function varies, and it varies between two per-step reads as well).
//
// The union path must be indistinguishable from the per-step path:
//   - Each step runs the same accumulation (evaluateRange) over the retained
//     rows of its window, in source order, and re-charges the row's pipeline
//     bytes while it consumes the row, so a step needs at least what it
//     needed before. What the union keeps is charged on top of that, at no
//     less than what the per-step accumulation charges for the same rows, so
//     the union path never fits where the per-step path would not.
//   - A failure that belongs to a row (the pipeline rejected it) is retained
//     with the row and surfaces only in a step whose window holds the row, at
//     the position of the row in that window. A failure of the source
//     iterator itself ends every step after its last retained row.
//   - Quota failures, whether the union does not fit or a step overran the
//     account because of what the union holds, drop the union and evaluate
//     the step again, and every later step, per step. A failure of the context
//     or of the account is returned as it is.
//   - Selectors with gaps between their windows (step longer than the
//     interval), instant queries, single-step ranges and variants keep the
//     per-step path: nothing is scanned twice there.

// retainedRowBytes is charged for every retained row: not less than the 192
// bytes the accumulation charges for the point the row becomes, and the
// retained row (about 100 bytes) is smaller than that.
const retainedRowBytes = 192

// rangeEntry is one retained row, or the failure the pipeline reported for the
// row at that timestamp.
type rangeEntry struct {
	rangeRow
	err error
}

// rangeUnion is the retained result of one union scan of one range selector.
type rangeUnion struct {
	entries []rangeEntry
	// sorted reports non-decreasing timestamps, which lets a step find its
	// window by bisection instead of by walking every entry.
	sorted bool
	// terminal is the source iterator's own failure; it follows the last entry.
	terminal  error
	closeErr  error
	isPartial bool
	marks     []model.Cursor
	held      int64
}

// unionHull reports the union of the windows (left, right] of every step of
// the range query for rg as the half-open raw read [first, last), and whether
// the union path applies at all.
func (s *metricState) unionHull(rg *RangeExpr) (first, last model.UnixNano, ok bool) {
	ev := s.plan.Evaluation
	if s.perStep || s.variantInput || ev.Instant || rg.Interval <= 0 || ev.Step <= 0 || ev.Step > rg.Interval || ev.End <= ev.Start {
		return 0, 0, false
	}
	span := uint64(ev.End) - uint64(ev.Start)
	if span > math.MaxInt64 || span/uint64(ev.Step) == 0 {
		return 0, 0, false
	}
	lastAt := int64(ev.Start) + int64(span/uint64(ev.Step))*ev.Step
	right0, err := metricSub(int64(ev.Start), rg.Offset)
	if err != nil {
		return 0, 0, false
	}
	left0, err := metricSub(right0, rg.Interval)
	if err != nil {
		return 0, 0, false
	}
	rightN, err := metricSub(lastAt, rg.Offset)
	if err != nil || rightN == math.MaxInt64 {
		return 0, 0, false
	}
	return model.UnixNano(left0 + 1), model.UnixNano(rightN + 1), true
}

// union returns the retained rows of rg, reading them on first use, or nil
// when the step is to be evaluated per step.
func (s *metricState) union(rg *RangeExpr, p PipelinePlan) (*rangeUnion, error) {
	if u, ok := s.unions[rg]; ok {
		return u, nil
	}
	first, last, ok := s.unionHull(rg)
	if !ok {
		return nil, nil
	}
	// The union reads through its own regex scope: what it spends is the union
	// path's, so falling back leaves the budgets of the per-step path untouched.
	q := p
	q.RegexScope = nil
	if err := q.compile(s.ctx); err != nil {
		return nil, nil
	}
	s.unionTried = true
	u, err := s.readUnion(rg, q, first, last)
	if err != nil {
		return nil, err
	}
	if s.unions == nil {
		s.unions = map[*RangeExpr]*rangeUnion{}
	}
	s.unions[rg] = u
	s.unionHeld += u.held
	return u, nil
}

// readUnion scans [first, last) once and pipelines every row once.
func (s *metricState) readUnion(rg *RangeExpr, p PipelinePlan, first, last model.UnixNano) (u *rangeUnion, err error) {
	it, err := s.selectRows(p, first, last)
	if err != nil {
		return nil, err
	}
	a := s.account
	// u is cleared by an error return before the deferred close runs, so the
	// deferred function works on ru.
	ru := &rangeUnion{sorted: true}
	u = ru
	defer func() {
		closeErr := it.Close()
		if err != nil {
			a.Release(ru.held)
			return
		}
		ru.closeErr = closeErr
		ru.isPartial = it.Partial()
		ru.marks = it.Watermarks()
	}()
	sets := map[string]*rangeLabels{}
	var hashBuffer []byte
	charge := func(n int64) error {
		if e := a.Reserve(n); e != nil {
			return e
		}
		u.held += n
		return nil
	}
	var previous model.UnixNano
	for {
		if err = a.Check(s.ctx); err != nil {
			return nil, err
		}
		row, e := it.Next(s.ctx)
		if errors.Is(e, io.EOF) {
			return u, nil
		}
		if e != nil {
			if isQuota(e) || a.Check(s.ctx) != nil {
				return nil, e
			}
			u.terminal = e
			return u, nil
		}
		r, e := RunLogRow(s.ctx, p, row, a)
		if e != nil {
			if isQuota(e) || a.Check(s.ctx) != nil {
				return nil, e
			}
			if err = s.retain(u, &previous, rangeEntry{rangeRow: rangeRow{at: row.Timestamp}, err: e}, charge); err != nil {
				return nil, err
			}
			continue
		}
		if !r.Retained {
			a.Release(r.Bytes)
			continue
		}
		key := value.LabelKey(r.Labels)
		labels := sets[key]
		if labels == nil {
			// The set is kept with its derived group, which is about as large
			// as the set itself.
			if err = charge(2*(value.SeriesBytes(value.Series{Labels: r.Labels})+int64(len(key))) + 128); err != nil {
				a.Release(r.Bytes)
				return nil, err
			}
			labels = newRangeLabels(value.CloneLabels(r.Labels))
			sets[key] = labels
		}
		entry := rangeEntry{rangeRow: rangeRow{
			retained: true, at: r.Entry.Timestamp, multiplicity: r.Entry.Multiplicity, id: r.Entry.ID,
			labels: labels, lineLen: len(r.Entry.Line), languageError: r.Entry.languageError != "", bytes: r.Bytes,
		}}
		if r.Unwrapped != nil {
			entry.value, entry.hasValue = *r.Unwrapped, true
		}
		if len(r.OriginalStreamLabels) > 0 {
			hashBuffer = metricStreamHashBytes(hashBuffer, r.OriginalStreamLabels)
			entry.hash = metricXXH64(hashBuffer)
		}
		// The pipeline's own charge is released; the replay charges it again
		// for the row it consumes.
		a.Release(r.Bytes)
		if err = s.retain(u, &previous, entry, charge); err != nil {
			return nil, err
		}
	}
}

// retain appends one entry and charges for it.
func (s *metricState) retain(u *rangeUnion, previous *model.UnixNano, e rangeEntry, charge func(int64) error) error {
	if err := charge(retainedRowBytes); err != nil {
		return err
	}
	if len(u.entries) > 0 && e.at < *previous {
		u.sorted = false
	}
	*previous = e.at
	u.entries = appendDoubling(u.entries, e)
	return nil
}

// appendDoubling is append that doubles a full slice: append grows a large slice by a quarter, which copies
// a slice of a million entries about five times over while it is filled.
func appendDoubling[T any](s []T, v T) []T {
	if len(s) == cap(s) {
		grown := make([]T, len(s), max(2*cap(s), 64))
		copy(grown, s)
		s = grown
	}
	return append(s, v)
}

// dropUnions releases everything the union scans retain and sends every later
// step down the per-step path.
func (s *metricState) dropUnions() {
	s.account.Release(s.unionHeld)
	s.unionHeld = 0
	s.unions = nil
	s.perStep = true
}

func isQuota(err error) bool {
	var fault *model.Fault
	return errors.As(err, &fault) && fault.Code == model.Quota
}

// replay feeds the rows of the window (left, right] to the accumulation.
func (u *rangeUnion) replay(a value.Account, left, right int64) rangeRows {
	r := &unionRows{union: u, account: a, left: left, right: right}
	if u.sorted {
		r.at = sort.Search(len(u.entries), func(i int) bool { return int64(u.entries[i].at) > left })
	}
	return r
}

type unionRows struct {
	union       *rangeUnion
	account     value.Account
	left, right int64
	at          int
}

func (r *unionRows) next(context.Context) (rangeRow, error) {
	entries := r.union.entries
	for r.at < len(entries) {
		e := &entries[r.at]
		at := int64(e.at)
		if at > r.right && r.union.sorted {
			r.at = len(entries)
			break
		}
		r.at++
		if at <= r.left || at > r.right {
			continue
		}
		if e.err != nil {
			return rangeRow{}, e.err
		}
		// The per-step path held the row's pipeline charge while it consumed it.
		if err := r.account.Reserve(e.bytes); err != nil {
			return rangeRow{}, err
		}
		return e.rangeRow, nil
	}
	if r.union.terminal != nil {
		return rangeRow{}, r.union.terminal
	}
	return rangeRow{}, io.EOF
}
func (r *unionRows) close() error               { return r.union.closeErr }
func (r *unionRows) partial() bool              { return r.union.isPartial }
func (r *unionRows) watermarks() []model.Cursor { return append([]model.Cursor(nil), r.union.marks...) }

// selectRows opens the raw read of a pipeline's selector over [start, end).
func (s *metricState) selectRows(p PipelinePlan, start, end model.UnixNano) (scan.LogIterator, error) {
	ms := make([]scan.LabelMatcher, len(p.Matchers))
	for i, m := range p.Matchers {
		ms[i] = scan.LabelMatcher{Name: m.Name, Op: m.Op, Value: m.Value}
	}
	it, err := s.src.Select(s.ctx, scan.LogSelection{Start: start, End: end, Matchers: ms, Profile: s.plan.Profile, Account: s.account, RegexScope: p.RegexScope})
	if err != nil {
		return nil, err
	}
	if it == nil {
		return nil, model.Fail(model.Corrupt)
	}
	return it, nil
}
