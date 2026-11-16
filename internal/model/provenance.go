// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import "errors"

// Provenance is the closed interval [From,To] of record times an opaque control
// state (a condition or a job) was folded from: the earliest and the latest time of
// any record the state ever absorbed (09.08x-W1). The times are the ones a
// historical range deletion ranges over (the event time of the record), so a
// deletion can tell, even after evidence rolled out of the state's bounded parts,
// whether the state derives from a deleted record: it does when the interval meets
// the range. The interval is an over-approximation (it also covers the times
// between its ends that were never folded): a state is erased too much, never too
// little. It is two numbers whatever the state has folded, and it is the join of
// the times folded (earliest, latest), so it does not depend on the order in which
// they arrive.
//
// A state without a provenance (a nil *Provenance) was written before the field
// existed: its earlier evidence is unknown, so it is never started late (see
// conditions.State and jobs.JobState).
type Provenance struct {
	From UnixNano `json:"from_ns"`
	To   UnixNano `json:"to_ns"`
}

// With returns the provenance that also covers at, never changing its receiver (a
// state is cloned by copying the pointer). A time that is not positive is no
// evidence of an instant (the convention of the erasure rule) and is not recorded.
func (p *Provenance) With(at UnixNano) *Provenance {
	if at <= 0 {
		return p
	}
	if p == nil {
		return &Provenance{From: at, To: at}
	}
	if at >= p.From && at <= p.To {
		return p
	}
	out := *p
	out.From, out.To = min(out.From, at), max(out.To, at)
	return &out
}

// Meets reports whether the interval meets the half-open interval [start,end): the
// range of a historical deletion.
func (p *Provenance) Meets(start, end UnixNano) bool {
	return p != nil && p.To >= start && p.From < end
}

// Validate reports whether p is a provenance a producer can have written: positive
// times with From <= To.
func (p Provenance) Validate() error {
	if p.From <= 0 || p.To < p.From {
		return errors.New("provenance: the interval is not positive and ordered")
	}
	return nil
}
