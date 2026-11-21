//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"math"
	"sync"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// stamp is one event as the consumer saw it: when (event clock), on which CPU's stream, and whether it is a scheduler
// event (the per-CPU ring) or a task-scoped sample.
type stamp struct {
	t     uint64
	cpu   uint32
	sched bool
}

// tap is the capture's event sink. It records every event and proof the stream delivered, in order, and hands them to
// the consumer's own correlation (the committed qual.StreamCorrelation: the per-session Correlator, with the
// acquisition proofs applied where they arrived and Revoke on an identity error) for a scheduler capture.
type tap struct {
	mu            sync.Mutex
	cpu           uint32
	corr          *qual.StreamCorrelation
	stamps        []stamp
	initial       []uint32
	progress      int
	final         *nativeperf.AcquisitionProof
	provenThrough uint64
}

func newTap(cpu uint32, scheduler bool, cfg nativeperf.Config) *tap {
	t := &tap{cpu: cpu}
	if scheduler {
		t.corr = qual.NewStreamCorrelation(cfg, func(uint64) (uint64, error) { return qual.CorrelationReservationBytes, nil })
	}
	return t
}

func (t *tap) Event(e nativeperf.SanitizedEvent) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stamps = append(t.stamps, stamp{t: uint64(e.Time), cpu: e.CPU, sched: e.Switch != nil || e.Wakeup != nil})
	if t.corr != nil {
		return t.corr.Event(e)
	}
	return true
}

func (t *tap) Proof(p nativeperf.AcquisitionProof) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case p.Final:
		q := p
		t.final = &q
	case p.Progress:
		t.progress++
	default:
		t.initial = append([]uint32(nil), p.CPUs...)
	}
	if t.corr != nil {
		t.corr.Proof(p)
	}
}

// Revoke is called by qual.Capture when the stream ended on an identity error (generation_changed,
// thread_coverage_changed, topology_changed): the unproven tail from provenThrough on is revoked.
func (t *tap) Revoke(provenThrough uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.provenThrough = provenThrough
	if t.corr != nil {
		t.corr.Revoke(provenThrough)
	}
}

// view reduces the capture to what the judge reads. off/on are the hotplug writes (zero windows for a capture without
// hotplug: every scheduler event then counts as "before"), repinned is when the target was put back on the CPU.
func (t *tap) view(res qual.CaptureResult, off, on window, repinned uint64) captureView {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := captureView{Ready: res.Ready, ErrorCode: res.ErrorCode, ReadError: res.ReadError, Complete: res.Complete,
		InitialCPUs: t.initial, Progress: t.progress, FinalProof: t.final != nil, LossEvents: res.LossEvents,
		StartedNs: res.StartedNs, EndedNs: res.EndedNs, Events: len(t.stamps), ProvenThrough: t.provenThrough}
	if t.final != nil {
		v.FinalCPUs = append([]uint32(nil), t.final.CPUs...)
	}
	before := off.Start
	if before == 0 {
		before = math.MaxUint64
	}
	for _, s := range t.stamps {
		onCPU := s.cpu == t.cpu
		if onCPU && s.t < before {
			v.OnCPUBefore++
			if s.sched {
				v.SchedOnCPUPre++
			}
		}
		if onCPU && off.done() && s.t > off.End && (on.Start == 0 || s.t < on.Start) {
			v.OnCPUWhileOff++
			if s.sched {
				v.SchedWhileOff++
			}
		}
		if onCPU && repinned != 0 && s.t > repinned {
			v.OnCPUAfterPin++
			if s.sched {
				v.SchedOnCPUPin++
			}
		}
		if on.done() && s.t > on.End {
			v.AfterOnline++
			if s.sched {
				v.SchedAfterBack++
			}
		}
	}
	if t.corr != nil {
		c := t.corr.Result()
		v.Revoked, v.CorrelationErr = c.Revoked, c.Err
		scanIntervals(&v, c.Intervals)
	}
	return v
}

// scanIntervals judges the intervals the correlator returned. A correction is non-additive coverage replacement for
// [Start, End): a measured interval overlapped by it is invalidated by the consumer (Interval.Correction), so an
// overlap is counted and reported, while an interval that is invalid, negative, or newer than the end of the
// domain-wide generation correction a revoked stream ends with (evidence from after the stream ended) is a defect.
// Other corrections (a task's unmeasured start) are counted and not analysed here.
func scanIntervals(v *captureView, intervals []nativeperf.Interval) {
	v.Intervals = len(intervals)
	for _, i := range intervals {
		if i.End < i.Start {
			v.Negative++
		}
		if i.Validate() != nil {
			v.Invalid++
		}
		if i.Correction {
			v.Corrections++
			if i.Reason == nativeperf.ReasonGeneration && i.Task == (nativeperf.TaskKey{}) {
				v.CorrectionFrom, v.CorrectionTo, v.CorrectionWhy = uint64(i.Start), uint64(i.End), string(i.Reason)
			}
		}
	}
	if v.CorrectionWhy == "" {
		return
	}
	for _, i := range intervals {
		if i.Correction {
			continue
		}
		if uint64(i.End) > v.CorrectionTo {
			v.NewerThanCorrection++
		}
		if uint64(i.End) > v.CorrectionFrom {
			v.Overlapped++
			if uint64(i.Start) < v.CorrectionFrom {
				v.Straddling++
			}
		}
	}
}
