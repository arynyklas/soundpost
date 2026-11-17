//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"reflect"
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

// A switch that involves the judged thread also names the thread on the other side. That other task's own history is
// scoped out (its switch-in elsewhere never reaches the correlator), so handing the correlator the other side would
// leave it "switched out" forever and the next switch from it would revoke the coverage of the whole domain. Scope
// hands the correlator the judged thread's side of the switch only: no domain-wide correction, the same intervals.
func TestStreamCorrelationScopeDoesNotLeaveTheOtherSideOfASwitchStuckOut(t *testing.T) {
	domain := nativeperf.ClockDomain{HostID: "host-a", BootID: "boot-a"}
	loop := nativeperf.TaskKey{BootID: "boot-a", PIDNamespace: 1, TGID: 7, TID: 7, ProcessStart: 1, Generation: 1}
	other := nativeperf.TaskKey{BootID: "boot-a", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}
	base := uint64(10_000_000_000)
	res := CaptureResult{Proofs: []nativeperf.AcquisitionProof{{Domain: domain, CPUs: []uint32{0, 1}, Through: model.MonoNano(base - 1)}}, ProofAt: []int{0}}
	switchAt := func(at uint64, cpu uint32, prev, next *nativeperf.TaskKey) nativeperf.SanitizedEvent {
		sw := &nativeperf.SchedulerSwitch{Previous: prev, Next: next}
		if prev != nil {
			sw.PreviousState, sw.MissingCallchain = 1, nativeperf.ReasonMissingSwitchCallchain
		}
		return nativeperf.SanitizedEvent{Kind: nativeperf.EventSwitch, Time: model.MonoNano(at), CPU: cpu, Domain: domain, Switch: sw}
	}
	for i := range 4 {
		a := base + uint64(i)*100_000_000
		l, o := loop, other
		res.Events = append(res.Events,
			switchAt(a, 0, &l, nil),
			switchAt(a+5_000_000, 1, &o, &l),   // the other thread leaves, the judged thread runs
			switchAt(a+10_000_000, 1, nil, &o), // the other thread runs again: not the judged thread's event
			switchAt(a+20_000_000, 0, &l, nil),
			switchAt(a+25_000_000, 1, &o, &l), // the other thread leaves again
			switchAt(a+30_000_000, 1, nil, &o))
	}
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
	loopOf := func(c Correlation) (out []nativeperf.Interval) {
		for _, iv := range c.Intervals {
			if iv.Task.TID == 7 || iv.Task == (nativeperf.TaskKey{}) {
				iv.SwitchOutCallchain = nil
				out = append(out, iv)
			}
		}
		return out
	}
	for _, iv := range n.Intervals {
		if iv.Correction && iv.Task == (nativeperf.TaskKey{}) {
			t.Fatalf("the scoped correlation revoked the whole domain: %+v", iv)
		}
	}
	if !reflect.DeepEqual(loopOf(w), loopOf(n)) {
		t.Fatalf("the judged thread's intervals differ:\nwide   %+v\nnarrow %+v", loopOf(w), loopOf(n))
	}
}

// The row judges read the kind and the extent of an interval, never its switch-out stack: DropStacks retains the
// intervals without them, which is memory the consumer's allowance does not have to cover, and changes nothing else.
func TestStreamCorrelationDropStacksRetainsTheSameIntervalsWithoutTheirStacks(t *testing.T) {
	domain := nativeperf.ClockDomain{HostID: "host-a", BootID: "boot-a"}
	key := nativeperf.TaskKey{BootID: "boot-a", PIDNamespace: 1, TGID: 7, TID: 7, ProcessStart: 1, Generation: 1}
	base := uint64(10_000_000_000)
	res := CaptureResult{Proofs: []nativeperf.AcquisitionProof{{Domain: domain, CPUs: []uint32{0}, Through: model.MonoNano(base - 1)}}, ProofAt: []int{0}}
	chain := make([]nativeperf.CallchainEntry, 64)
	for i := range chain {
		chain[i] = nativeperf.CallchainEntry{IP: model.Uint64(0x400000 + i)}
	}
	for i := range 30 {
		a := base + uint64(i)*100_000_000
		k := key
		res.Events = append(res.Events,
			nativeperf.SanitizedEvent{Kind: nativeperf.EventSwitch, Time: model.MonoNano(a), CPU: 0, Domain: domain,
				Switch: &nativeperf.SchedulerSwitch{Previous: &k, PreviousState: 1, SwitchOutCallchain: chain}},
			nativeperf.SanitizedEvent{Kind: nativeperf.EventWakeup, Time: model.MonoNano(a + 40_000_000), CPU: 0, Domain: domain, Task: key, Wakeup: &nativeperf.SchedulerWakeup{Target: key}},
			nativeperf.SanitizedEvent{Kind: nativeperf.EventSwitch, Time: model.MonoNano(a + 55_000_000), CPU: 0, Domain: domain, Switch: &nativeperf.SchedulerSwitch{Next: &k}})
	}
	for i := range res.Events {
		res.Events[i].Sequence = model.Uint64(i + 1)
	}
	res.Proofs = append(res.Proofs, nativeperf.AcquisitionProof{Domain: domain, CPUs: []uint32{0}, Through: model.MonoNano(base + 5_000_000_000), Final: true})
	res.ProofAt = append(res.ProofAt, len(res.Events))

	full := NewStreamCorrelation(nativeperf.DefaultConfig(1), fixedShare)
	drive(res, full, false)
	lean := NewStreamCorrelation(nativeperf.DefaultConfig(1), fixedShare)
	lean.DropStacks()
	drive(res, lean, false)
	f, l := full.Result(), lean.Result()
	if f.Err != "" || l.Err != "" || len(f.Intervals) == 0 || len(f.Intervals) != len(l.Intervals) {
		t.Fatalf("full %+v\nlean %+v", f, l)
	}
	withStacks := 0
	for i := range f.Intervals {
		if len(f.Intervals[i].SwitchOutCallchain) != 0 {
			withStacks++
		}
		if len(l.Intervals[i].SwitchOutCallchain) != 0 {
			t.Fatalf("interval %d kept its stack: %+v", i, l.Intervals[i])
		}
		stripped := f.Intervals[i]
		stripped.SwitchOutCallchain = nil
		if !reflect.DeepEqual(stripped, l.Intervals[i]) {
			t.Fatalf("interval %d differs beyond its stack:\nfull %+v\nlean %+v", i, f.Intervals[i], l.Intervals[i])
		}
	}
	if withStacks == 0 || l.IntervalBytes*2 > f.IntervalBytes {
		t.Fatalf("the stacks were not what the footprint held: %d intervals with stacks, %d B full, %d B lean", withStacks, f.IntervalBytes, l.IntervalBytes)
	}
}

// A judge that only adds up durations needs one summed interval per task and kind, not thousands of them: FoldDurations
// retains exactly that, keeps every coverage correction as it came, and the counts of what the correlator returned.
func TestStreamCorrelationFoldDurationsKeepsTheSumsAndTheCorrections(t *testing.T) {
	domain := nativeperf.ClockDomain{HostID: "host-a", BootID: "boot-a"}
	key := nativeperf.TaskKey{BootID: "boot-a", PIDNamespace: 1, TGID: 7, TID: 7, ProcessStart: 1, Generation: 1}
	base := uint64(10_000_000_000)
	res := CaptureResult{Proofs: []nativeperf.AcquisitionProof{{Domain: domain, CPUs: []uint32{0}, Through: model.MonoNano(base - 1)}}, ProofAt: []int{0}}
	for i := range 30 {
		a := base + uint64(i)*100_000_000
		res.Events = append(res.Events, schedEvents(domain, key, a)...)
	}
	res.Events = append(res.Events, nativeperf.SanitizedEvent{Kind: nativeperf.EventLoss, Time: model.MonoNano(base + 3_100_000_000), CPU: 0, Domain: domain,
		Loss: &nativeperf.LossEvent{Count: 1, Reason: nativeperf.ReasonLoss}})
	for i := range res.Events {
		res.Events[i].Sequence = model.Uint64(i + 1)
	}
	res.Proofs = append(res.Proofs, nativeperf.AcquisitionProof{Domain: domain, CPUs: []uint32{0}, Through: model.MonoNano(base + 5_000_000_000), Final: true})
	res.ProofAt = append(res.ProofAt, len(res.Events))

	full := NewStreamCorrelation(nativeperf.DefaultConfig(1), fixedShare)
	drive(res, full, false)
	folded := NewStreamCorrelation(nativeperf.DefaultConfig(1), fixedShare)
	folded.FoldDurations()
	drive(res, folded, false)
	f, g := full.Result(), folded.Result()
	if f.Err != "" || g.Err != "" || f.ConsumeErrors != 0 || g.ConsumeErrors != 0 {
		t.Fatalf("full %+v\nfolded %+v", f, g)
	}
	type sum struct {
		task nativeperf.TaskKey
		kind nativeperf.IntervalKind
	}
	sums := func(c Correlation) (out map[sum]uint64, corrections []nativeperf.Interval) {
		out = map[sum]uint64{}
		for _, iv := range c.Intervals {
			if iv.Correction {
				iv.SwitchOutCallchain = nil
				corrections = append(corrections, iv)
				continue
			}
			out[sum{iv.Task, iv.Kind}] += uint64(iv.End - iv.Start)
		}
		return out, corrections
	}
	fs, fc := sums(f)
	gs, gc := sums(g)
	if len(fc) == 0 || !reflect.DeepEqual(fc, gc) {
		t.Fatalf("the corrections differ: full %+v folded %+v", fc, gc)
	}
	if !reflect.DeepEqual(fs, gs) || fs[sum{key, nativeperf.IntervalBlocked}] != 30*40_000_000 || fs[sum{key, nativeperf.IntervalRunnable}] != 30*15_000_000 {
		t.Fatalf("the summed durations differ: full %v folded %v", fs, gs)
	}
	if !reflect.DeepEqual(f.IntervalCounts, g.IntervalCounts) || f.IntervalCounts[nativeperf.IntervalBlocked] != 30 {
		t.Fatalf("counts of the returned intervals: full %v folded %v", f.IntervalCounts, g.IntervalCounts)
	}
	measured := 0
	for _, iv := range g.Intervals {
		if !iv.Correction {
			measured++
		}
	}
	if measured != len(gs) || len(g.Intervals) >= len(f.Intervals) || g.IntervalBytes >= f.IntervalBytes {
		t.Fatalf("not folded: %d measured intervals for %d keys, %d vs %d intervals, %d vs %d B", measured, len(gs), len(g.Intervals), len(f.Intervals), g.IntervalBytes, f.IntervalBytes)
	}
}
