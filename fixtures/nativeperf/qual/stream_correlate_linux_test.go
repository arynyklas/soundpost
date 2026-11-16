//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"sort"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

func fixedShare(uint64) (uint64, error) { return CorrelationReservationBytes, nil }

// drive feeds a finished capture to s as the live stream would: each non-final proof before the event it preceded.
func drive(res CaptureResult, s *StreamCorrelation, mix bool) (kept []nativeperf.SanitizedEvent) {
	next := 0
	for i, e := range res.Events {
		for ; next < len(res.Proofs) && !res.Proofs[next].Final && res.ProofAt[next] <= i; next++ {
			s.Proof(res.Proofs[next])
		}
		if mix && i%50 == 0 {
			for _, extra := range []nativeperf.SanitizedEvent{{Kind: nativeperf.EventCPU, CPUEvent: &nativeperf.CPUSample{}}, {Kind: nativeperf.EventLoss, Loss: &nativeperf.LossEvent{Count: 1}}} {
				if s.Event(extra) {
					kept = append(kept, extra)
				}
			}
		}
		if s.Event(e) {
			kept = append(kept, e)
		}
	}
	for ; next < len(res.Proofs); next++ {
		s.Proof(res.Proofs[next])
	}
	return kept
}

func count(events []nativeperf.SanitizedEvent, f func(nativeperf.SanitizedEvent) bool) (n int) {
	for _, e := range events {
		if f(e) {
			n++
		}
	}
	return n
}

// The live sink is the same correlation as the replay of a finished capture, and the capture result it feeds keeps no
// switch and no wakeup.
func TestStreamCorrelationRetainsNoSchedulerEventAndMatchesTheReplay(t *testing.T) {
	res, cycles := longCapture(400, true)
	want := Correlate(res, nativeperf.DefaultConfig(1))
	s := NewStreamCorrelation(nativeperf.DefaultConfig(1), fixedShare)
	kept := drive(res, s, false)
	got := s.Result()
	if len(kept) != 0 {
		t.Fatalf("%d scheduler events were retained", len(kept))
	}
	if got.Err != "" || got.ConsumeErrors != 0 || got.SwitchEvents != want.SwitchEvents || got.WakeupEvents != want.WakeupEvents || len(got.Intervals) != len(want.Intervals) || got.ProgressProofs != want.ProgressProofs || got.PeakHeapEvents != want.PeakHeapEvents {
		t.Fatalf("stream %+v\nreplay %+v", got, want)
	}
	if blocked, runnable := sumKinds(got); blocked != cycles*1_000_000 || runnable != cycles*1_000_000 {
		t.Fatalf("%d %d", blocked, runnable)
	}
	if got.IntervalBytes == 0 || got.IntervalBytes != IntervalsFootprint(got.Intervals) {
		t.Fatalf("interval bytes %d", got.IntervalBytes)
	}
}

func TestStreamCorrelationKeepsSamplesAndLossesForTheJudges(t *testing.T) {
	s := NewStreamCorrelation(nativeperf.DefaultConfig(1), fixedShare)
	res, _ := longCapture(200, true)
	kept := drive(res, s, true)
	if len(kept) != 24 || count(kept, func(e nativeperf.SanitizedEvent) bool { return e.CPUEvent != nil }) != 12 || count(kept, func(e nativeperf.SanitizedEvent) bool { return e.Loss != nil }) != 12 {
		t.Fatalf("kept %d", len(kept))
	}
	if c := s.Result(); c.CPUSamples != 12 || c.LossEvents != 12 {
		t.Fatalf("%+v", c)
	}
}

// Nothing is inferred: events or progress before the topology proof, a stream without its final proof and a refused
// reservation all end in an explicit error and no intervals.
func TestStreamCorrelationFailsExplicitly(t *testing.T) {
	domain := nativeperf.ClockDomain{HostID: "host-a", BootID: "boot-a"}
	initial := nativeperf.AcquisitionProof{Domain: domain, CPUs: []uint32{0, 1}, Through: 1}
	final := nativeperf.AcquisitionProof{Domain: domain, CPUs: []uint32{0, 1}, Through: 2, Final: true}

	s := NewStreamCorrelation(nativeperf.DefaultConfig(1), fixedShare)
	s.Event(nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, CPUEvent: &nativeperf.CPUSample{}})
	s.Proof(initial)
	s.Proof(final)
	if c := s.Result(); c.Err == "" {
		t.Fatalf("an event before the topology proof was consumed: %+v", c)
	}
	s = NewStreamCorrelation(nativeperf.DefaultConfig(1), fixedShare)
	s.Proof(nativeperf.AcquisitionProof{Domain: domain, CPUs: []uint32{0, 1}, Through: 2, Progress: true})
	if c := s.Result(); c.Err == "" {
		t.Fatalf("a progress proof before the topology proof was applied: %+v", c)
	}
	s = NewStreamCorrelation(nativeperf.DefaultConfig(1), fixedShare)
	s.Proof(initial)
	if c := s.Result(); c.Err == "" || len(c.Intervals) != 0 {
		t.Fatalf("a capture without its final proof reported intervals: %+v", c)
	}
	s = NewStreamCorrelation(nativeperf.DefaultConfig(1), func(uint64) (uint64, error) { return 0, nativeperf.ErrResourceBudget })
	s.Proof(initial)
	s.Proof(final)
	if c := s.Result(); c.Err == "" || c.ReservationBytes != 0 {
		t.Fatalf("a refused reservation configured a correlator: %+v", c)
	}
}

// KeepOnly releases the intervals the judge does not read and the footprint is the kept ones' only.
func TestStreamCorrelationKeepOnlyReleasesTheIntervalsTheJudgeDoesNotRead(t *testing.T) {
	res, cycles := longCapture(300, true)
	all := NewStreamCorrelation(nativeperf.DefaultConfig(1), fixedShare)
	drive(res, all, false)
	want := all.Result()
	s := NewStreamCorrelation(nativeperf.DefaultConfig(1), fixedShare)
	s.KeepOnly(func(iv nativeperf.Interval) bool { return iv.Kind == nativeperf.IntervalBlocked })
	drive(res, s, false)
	got := s.Result()
	blocked, runnable := sumKinds(got)
	if got.Err != "" || blocked != cycles*1_000_000 || runnable != 0 || got.IntervalsDropped == 0 || len(got.Intervals)+got.IntervalsDropped != len(want.Intervals) {
		t.Fatalf("kept %d dropped %d of %d (blocked %d runnable %d): %+v", len(got.Intervals), got.IntervalsDropped, len(want.Intervals), blocked, runnable, got.Err)
	}
	if got.IntervalBytes >= want.IntervalBytes || got.IntervalBytes != IntervalsFootprint(got.Intervals) {
		t.Fatalf("footprint %d, unfiltered %d", got.IntervalBytes, want.IntervalBytes)
	}
}

// Scope narrows the correlation to the judged thread: its intervals are unchanged, the correlator buffers less.
func TestStreamCorrelationScopeLeavesTheThreadsIntervalsUnchangedAndBuffersLess(t *testing.T) {
	domain := nativeperf.ClockDomain{HostID: "host-a", BootID: "boot-a"}
	loop := nativeperf.TaskKey{BootID: "boot-a", PIDNamespace: 1, TGID: 7, TID: 7, ProcessStart: 1, Generation: 1}
	helper := nativeperf.TaskKey{BootID: "boot-a", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}
	base := uint64(10_000_000_000)
	res := CaptureResult{Proofs: []nativeperf.AcquisitionProof{{Domain: domain, CPUs: []uint32{0, 1}, Through: model.MonoNano(base - 1)}}, ProofAt: []int{0}}
	for i := range 40 {
		at := base + uint64(i)*100_000_000
		for _, ev := range schedEvents(domain, loop, at) {
			res.Events = append(res.Events, ev)
		}
		for _, ev := range schedEvents(domain, helper, at+10_000_000) {
			ev.CPU = 1
			if ev.Wakeup != nil {
				ev.Wakeup.TargetCPU = 1
			}
			res.Events = append(res.Events, ev)
		}
	}
	sort.SliceStable(res.Events, func(i, j int) bool { return res.Events[i].Time < res.Events[j].Time })
	for i := range res.Events {
		res.Events[i].Sequence = model.Uint64(i + 1)
	}
	res.Proofs = append(res.Proofs, nativeperf.AcquisitionProof{Domain: domain, CPUs: []uint32{0, 1}, Through: model.MonoNano(base + 5_000_000_000), Final: true})
	res.ProofAt = append(res.ProofAt, len(res.Events))

	wide := NewStreamCorrelation(nativeperf.DefaultConfig(1), fixedShare)
	drive(res, wide, false)
	narrow := NewStreamCorrelation(nativeperf.DefaultConfig(1), fixedShare)
	narrow.Scope(7)
	drive(res, narrow, false)
	w, n := wide.Result(), narrow.Result()
	if w.Err != "" || n.Err != "" || w.ConsumeErrors != 0 || n.ConsumeErrors != 0 {
		t.Fatalf("wide %+v\nnarrow %+v", w, n)
	}
	of := func(c Correlation, tid uint32) (blocked, runnable uint64, intervals int) {
		for _, iv := range c.Intervals {
			if iv.Correction || iv.Task.TID != tid {
				continue
			}
			intervals++
			switch iv.Kind {
			case nativeperf.IntervalBlocked:
				blocked += uint64(iv.End - iv.Start)
			case nativeperf.IntervalRunnable:
				runnable += uint64(iv.End - iv.Start)
			}
		}
		return
	}
	wb, wr, wn := of(w, 7)
	nb, nr, nn := of(n, 7)
	if wb != 40*40_000_000 || wr != 40*15_000_000 || nb != wb || nr != wr || nn != wn {
		t.Fatalf("loop thread intervals differ: wide %d/%d (%d) narrow %d/%d (%d)", wb, wr, wn, nb, nr, nn)
	}
	if _, _, helperIntervals := of(n, 8); helperIntervals != 0 || n.ScopedOut != 40*3 || w.ScopedOut != 0 {
		t.Fatalf("the helper thread's events were not scoped out: %+v", n)
	}
}
