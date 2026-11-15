// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// Boundary tests added for 04.05-W2: each pins one comparison, copy or reset of the scheduler correlator that the original
// suite let a mutant change without a runtime failure (mutant ids are the l4w9 battery ids K*/L*/I*, listed per test).

const corrMs uint64 = 1_000_000

func corrTask(tid uint32) TaskKey {
	k := correlationTask()
	k.TID = tid
	return k
}
func corrAt(e SanitizedEvent, cpu uint32, seq uint64) SanitizedEvent {
	e.CPU = cpu
	e.Sequence = model.Uint64(seq)
	return e
}
func corrOutTask(k TaskKey, at uint64) SanitizedEvent {
	e := correlationOut(at, false)
	e.Switch.Previous = &k
	return e
}
func corrSample(k TaskKey, at uint64) SanitizedEvent {
	e := testEvent()
	e.Domain = correlationDomain
	e.Task = k
	e.Time = model.MonoNano(at)
	e.Sequence = model.Uint64(at + 1)
	return e
}
func corrCorrections(in []Interval) (n int, reason Reason) {
	for _, i := range in {
		if i.Correction {
			n++
			reason = i.Reason
		}
	}
	return
}
func corrConsume(t *testing.T, c *Correlator, es ...SanitizedEvent) {
	t.Helper()
	for _, e := range es {
		if _, err := c.Consume(e); err != nil {
			t.Fatal(err)
		}
	}
}

// K02, K06: an event on a CPU outside the topology, or on a failed CPU, is refused.
func TestCorrelationRefusesUnknownAndFailedCPU(t *testing.T) {
	c := configuredCorrelation(t, 0, 1)
	out, err := c.Consume(corrAt(correlationOut(10, false), 5, 3))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown CPU: %v", err)
	}
	if n, _ := corrCorrections(out); n != 1 {
		t.Fatalf("unknown CPU did not revoke coverage: %+v", out)
	}
	c = configuredCorrelation(t, 0, 1)
	if _, err = c.ReportCPUFailure(1, 5); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Consume(corrAt(correlationOut(10, false), 1, 3)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("failed CPU accepted an event: %v", err)
	}
}

// K04, K05, K17, L34: evidence at or before the committed prefix, or before the epoch start, is late and drops pending evidence.
func TestCorrelationLateEvidenceBoundaries(t *testing.T) {
	c := configuredCorrelation(t, 0)
	if _, err := c.ChangeTopology(model.MonoNano(1000*corrMs), []uint32{0}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Consume(correlationOut(500*corrMs, false)); !errors.Is(err, ErrCorrelationLate) {
		t.Fatalf("event before the epoch start accepted: %v", err)
	}
	c = configuredCorrelation(t, 0)
	corrConsume(t, c, correlationOut(400*corrMs, false))
	if err := c.ReportProgress(0, model.MonoNano(300*corrMs)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Advance(model.MonoNano(200 * corrMs)); err != nil {
		t.Fatal(err)
	}
	if c.Stats().HeapEvents != 1 {
		t.Fatalf("pending event lost: %+v", c.Stats())
	}
	out, err := c.Consume(correlationIn(200 * corrMs))
	if !errors.Is(err, ErrCorrelationLate) {
		t.Fatalf("event exactly at the watermark accepted: %v", err)
	}
	if n, _ := corrCorrections(out); n != 1 {
		t.Fatalf("late evidence did not emit a correction: %+v", out)
	}
	if c.Stats().HeapEvents != 0 {
		t.Fatalf("late evidence left pending events: %+v", c.Stats())
	}
}

// K07: the heap holds exactly maxEvents events; one more is refused.
func TestCorrelationEventBudgetBoundary(t *testing.T) {
	c := NewCorrelator(DefaultConfig(1))
	if err := c.Configure(correlationDomain, []uint32{0}, 80<<10); err != nil {
		t.Fatal(err)
	}
	if c.Stats().MaxHeapEvents != 1 {
		t.Fatalf("slots %+v", c.Stats())
	}
	corrConsume(t, c, correlationOut(10, false))
	if _, err := c.Consume(correlationIn(20)); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("heap overflow: %v", err)
	}
}

// K08: Finalize refuses a pending event later than end (latest tracks the maximum, not the minimum).
func TestCorrelationFinalizeRefusesPendingBeyondEnd(t *testing.T) {
	c := configuredCorrelation(t, 0)
	corrConsume(t, c, correlationOut(100, false))
	if err := c.ReportProgress(0, 60); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Finalize(50); !errors.Is(err, ErrInvalid) {
		t.Fatalf("finalize with an event beyond end: %v", err)
	}
}

// K09, K10, K12, K13, K14, L04: the correlator owns what it keeps and clears what it releases.
func TestCorrelationOwnsAndClearsEvents(t *testing.T) {
	c := configuredCorrelation(t, 0)
	corrConsume(t, c, corrSample(correlationTask(), 5))
	if c.events[0].CPUEvent != nil {
		t.Fatal("CPU sample retained by the correlator")
	}
	c = configuredCorrelation(t, 0)
	throttle := SanitizedEvent{Kind: EventLoss, Time: 5, Sequence: 6, Domain: correlationDomain, Loss: &LossEvent{Reason: ReasonThrottle, Throttle: &ThrottleEvidence{Reason: ReasonThrottle, EventID: 1, StreamID: 1}}}
	corrConsume(t, c, throttle)
	if c.events[0].Loss.Throttle != nil {
		t.Fatal("throttle evidence retained by the correlator")
	}
	c = configuredCorrelation(t, 0)
	prev, next := correlationTask(), corrTask(9)
	sw := SanitizedEvent{Kind: EventSwitch, Time: 5, Sequence: 6, Domain: correlationDomain, Switch: &SchedulerSwitch{Previous: &prev, Next: &next, PreviousState: 1, MissingCallchain: ReasonMissingSwitchCallchain}}
	corrConsume(t, c, sw)
	prev.TID, next.TID = 77, 78
	if *c.events[0].Switch.Previous != correlationTask() || *c.events[0].Switch.Next != corrTask(9) {
		t.Fatalf("switch keys alias the caller's: %+v %+v", *c.events[0].Switch.Previous, *c.events[0].Switch.Next)
	}
	w := correlationWake(6)
	corrConsume(t, c, w)
	w.Wakeup.Target.TID = 99
	if c.events[1].Wakeup != nil && c.events[1].Wakeup.Target.TID == 99 || c.events[0].Wakeup != nil && c.events[0].Wakeup.Target.TID == 99 {
		t.Fatal("wakeup aliases the caller's")
	}
	// A popped heap slot is zeroed so the correlator does not pin its stack.
	c = configuredCorrelation(t, 0)
	corrConsume(t, c, correlationOut(5, false))
	if err := c.ReportProgress(0, model.MonoNano(300*corrMs)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Advance(model.MonoNano(10 * corrMs)); err != nil {
		t.Fatal(err)
	}
	if slot := c.events[:1][0]; slot.Switch != nil || slot.Kind != "" {
		t.Fatalf("popped heap slot not zeroed: %+v", slot)
	}
}

// K16, I35: peaks are reported.
func TestCorrelationReportsPeaks(t *testing.T) {
	c := configuredCorrelation(t, 0)
	corrConsume(t, c, corrAt(corrOutTask(corrTask(8), 10), 0, 11), corrAt(corrOutTask(corrTask(9), 20), 0, 21), corrAt(correlationWake(30), 0, 31))
	if c.Stats().PeakHeapEvents != 3 {
		t.Fatalf("heap peak %+v", c.Stats())
	}
	drainCorrelation(t, c, []uint32{0}, 100)
	if s := c.Stats(); s.PeakTaskStates != 2 || s.TaskStates != 2 || s.HeapEvents != 0 {
		t.Fatalf("task peak %+v", s)
	}
}

// L02, L03: events at one instant are ordered by CPU, then by sequence.
func TestCorrelationOrdersTiesByCPUThenSequence(t *testing.T) {
	c := configuredCorrelation(t, 0, 1)
	corrConsume(t, c, corrAt(correlationIn(10), 1, 1), corrAt(correlationOut(10, false), 0, 5))
	got := drainCorrelation(t, c, []uint32{0, 1}, 10)
	if n, _ := corrCorrections(got); n != 0 || len(got) != 1 {
		t.Fatalf("CPU tie order: %+v", got)
	}
	c = configuredCorrelation(t, 0)
	corrConsume(t, c, corrAt(correlationIn(10), 0, 2), corrAt(correlationOut(10, false), 0, 1))
	got = drainCorrelation(t, c, []uint32{0}, 10)
	if n, _ := corrCorrections(got); n != 0 || len(got) != 1 {
		t.Fatalf("sequence tie order: %+v", got)
	}
}

// L05, L06, L07, L09, L13, L15: Configure's bounds.
func TestCorrelationConfigureBounds(t *testing.T) {
	cpus := func(n int) []uint32 {
		out := make([]uint32, n)
		for i := range out {
			out[i] = uint32(i)
		}
		return out
	}
	fresh := func() *Correlator { return NewCorrelator(DefaultConfig(1)) }
	if err := fresh().Configure(correlationDomain, cpus(1), MaxMemoryBytes+1); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("reservation above MaxMemory: %v", err)
	}
	if err := fresh().Configure(correlationDomain, cpus(1), 64<<10-1); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("reservation below the floor: %v", err)
	}
	if err := fresh().Configure(correlationDomain, cpus(1), 64<<10); err != nil {
		t.Fatalf("reservation at the floor: %v", err)
	}
	if err := fresh().Configure(ClockDomain{}, cpus(1), 4<<20); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid domain: %v", err)
	}
	if err := fresh().Configure(correlationDomain, cpus(256), 4<<20); err != nil {
		t.Fatalf("256 CPUs: %v", err)
	}
	if err := fresh().Configure(correlationDomain, cpus(257), 4<<20); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("257 CPUs: %v", err)
	}
	// 64 CPUs: base = 16 KiB + 64*256 = 32 KiB, so 64 KiB leaves no room for one 2-slot pair.
	if err := fresh().Configure(correlationDomain, cpus(64), 64<<10); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("no room for a slot: %v", err)
	}
	// 100 CPUs: the per-CPU charge shrinks the slot count from 31 to 30.
	c := fresh()
	if err := c.Configure(correlationDomain, cpus(100), 1<<20); err != nil {
		t.Fatal(err)
	}
	if s := c.Stats(); s.MaxHeapEvents != 30 || s.MaxTaskStates != 30 {
		t.Fatalf("slots %+v", s)
	}
}

// L18, L20, L45: progress proofs.
func TestCorrelationProgressProofs(t *testing.T) {
	c := configuredCorrelation(t, 0)
	if err := c.ReportProgress(0, 100); err != nil {
		t.Fatal(err)
	}
	if err := c.ReportProgress(0, 100); err != nil {
		t.Fatalf("repeating a proof: %v", err)
	}
	if err := c.ReportProgress(0, 99); !errors.Is(err, ErrInvalid) {
		t.Fatalf("regressing proof: %v", err)
	}
	// A failed CPU, even one proved earlier, holds the drain back.
	c = configuredCorrelation(t, 0, 1)
	for _, cpu := range []uint32{0, 1} {
		if err := c.ReportProgress(cpu, model.MonoNano(500*corrMs)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.ReportCPUFailure(1, model.MonoNano(5*corrMs)); err != nil {
		t.Fatal(err)
	}
	corrConsume(t, c, corrAt(correlationOut(30*corrMs, false), 0, 31))
	out, err := c.Advance(model.MonoNano(400 * corrMs))
	if err != nil || len(out) != 0 || c.Stats().HeapEvents != 1 {
		t.Fatalf("drained past a failed CPU: %+v %v %+v", out, err, c.Stats())
	}
	// Finalize needs a proof from every CPU, including through == 0 at end == 0.
	c = configuredCorrelation(t, 0)
	if _, err := c.Finalize(0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("finalize without any proof: %v", err)
	}
}

// L27, L32, L39: a bound equal to the committed watermark is allowed.
func TestCorrelationWatermarkEqualityIsAllowed(t *testing.T) {
	prepare := func() *Correlator {
		c := configuredCorrelation(t, 0)
		if err := c.ReportProgress(0, model.MonoNano(300*corrMs)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Advance(model.MonoNano(200 * corrMs)); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := prepare()
	if _, err := c.Advance(model.MonoNano(200 * corrMs)); err != nil {
		t.Fatalf("repeat Advance: %v", err)
	}
	if _, err := c.Advance(model.MonoNano(199 * corrMs)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("regressing Advance: %v", err)
	}
	c = prepare()
	if _, err := c.ChangeTopology(model.MonoNano(200*corrMs), []uint32{0}); err != nil {
		t.Fatalf("topology change at the watermark: %v", err)
	}
	if _, err := c.ChangeTopology(model.MonoNano(199*corrMs), []uint32{0}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("topology change before the watermark: %v", err)
	}
	c = prepare()
	if _, err := c.Finalize(model.MonoNano(200 * corrMs)); err != nil {
		t.Fatalf("finalize at the watermark: %v", err)
	}
	c = prepare()
	if _, err := c.Finalize(model.MonoNano(199 * corrMs)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("finalize before the watermark: %v", err)
	}
}

// L35, L37: a topology change drops pending events and the stale high-water mark.
func TestCorrelationTopologyChangeResetsPending(t *testing.T) {
	c := configuredCorrelation(t, 0)
	corrConsume(t, c, correlationOut(1000*corrMs, false))
	if _, err := c.ChangeTopology(model.MonoNano(10*corrMs), []uint32{0}); err != nil {
		t.Fatal(err)
	}
	if c.Stats().HeapEvents != 0 {
		t.Fatalf("pending events survived a topology change: %+v", c.Stats())
	}
	corrConsume(t, c, correlationOut(100*corrMs, false))
	if err := c.ReportProgress(0, model.MonoNano(200*corrMs)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Finalize(model.MonoNano(200 * corrMs)); err != nil {
		t.Fatalf("stale latest after a topology change: %v", err)
	}
}

// L43: Finalize releases every task and process.
func TestCorrelationFinalizeReleasesState(t *testing.T) {
	c := configuredCorrelation(t, 0)
	corrConsume(t, c, correlationOut(10*corrMs, false))
	if err := c.ReportProgress(0, model.MonoNano(900*corrMs)); err != nil {
		t.Fatal(err)
	}
	got, err := c.Finalize(model.MonoNano(500 * corrMs))
	if err != nil || len(got) != 1 || got[0].Kind != IntervalCensored {
		t.Fatalf("finalize: %+v %v", got, err)
	}
	if c.Stats().TaskStates != 0 || len(c.processes) != 0 {
		t.Fatalf("state survived Finalize: %+v %d", c.Stats(), len(c.processes))
	}
}

// I02: a correction covers [0, watermark) even when it is raised earlier than the watermark.
func TestCorrelationCorrectionCoversWatermark(t *testing.T) {
	c := configuredCorrelation(t, 0)
	if err := c.ReportProgress(0, model.MonoNano(300*corrMs)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Advance(model.MonoNano(200 * corrMs)); err != nil {
		t.Fatal(err)
	}
	out, err := c.ReportCPUFailure(0, 5)
	if err != nil || len(out) != 1 || !out[0].Correction || out[0].End != model.MonoNano(200*corrMs) {
		t.Fatalf("correction %+v %v", out, err)
	}
}

// I08, I23, I24, I34: process identity entries live exactly while a task of the process is outstanding.
func TestCorrelationProcessIdentityLifetime(t *testing.T) {
	regen := func(tid uint32, gen model.Uint64, at uint64) SanitizedEvent {
		k := corrTask(tid)
		k.Generation = gen
		return corrSample(k, at)
	}
	run := func(events ...SanitizedEvent) (int, Reason) {
		c := configuredCorrelation(t, 0)
		corrConsume(t, c, events...)
		got := drainCorrelation(t, c, []uint32{0}, 100)
		return corrCorrections(got)
	}
	// Same start, new generation, while a thread is outstanding: identity conflict (I08).
	if n, r := run(corrOutTask(corrTask(8), 10), regen(8, 2, 20)); n != 1 || r != ReasonGeneration {
		t.Fatalf("generation conflict %d %q", n, r)
	}
	// The only thread came back: the process entry is gone, a new generation is no conflict (I23, I34).
	if n, _ := run(corrOutTask(corrTask(8), 10), correlationIn(20), regen(8, 2, 30)); n != 0 {
		t.Fatalf("stale process entry after the last switch-in: %d", n)
	}
	// One of two threads came back: the entry stays and the conflict is still detected (I24).
	if n, r := run(corrAt(corrOutTask(corrTask(8), 10), 0, 11), corrAt(corrOutTask(corrTask(9), 12), 0, 13), corrAt(correlationIn(20), 0, 21), regen(8, 2, 30)); n != 1 || r != ReasonGeneration {
		t.Fatalf("entry dropped while a thread is outstanding: %d %q", n, r)
	}
}

// I29: a preempted task is runnable even when its recorded state is not TASK_RUNNING.
func TestCorrelationPreemptedWithNonRunningState(t *testing.T) {
	c := configuredCorrelation(t, 0)
	out := correlationOut(0, false)
	out.Switch.Preempted = true
	corrConsume(t, c, out, correlationIn(20))
	got := drainCorrelation(t, c, []uint32{0}, 20)
	if len(got) != 1 || got[0].Kind != IntervalRunnable {
		t.Fatalf("preempted: %+v", got)
	}
}

// I32, I41, I42: switch-out stack and its absence reason reach each emitted interval, and intervals do not share the stack.
func TestCorrelationIntervalStackAndReason(t *testing.T) {
	c := configuredCorrelation(t, 0)
	corrConsume(t, c, correlationOut(0, false), correlationWake(40), correlationIn(55))
	got := drainCorrelation(t, c, []uint32{0}, 55)
	if len(got) != 2 || got[0].MissingCallchain != ReasonMissingSwitchCallchain || got[1].MissingCallchain != ReasonMissingSwitchCallchain {
		t.Fatalf("missing-callchain reason dropped: %+v", got)
	}
	c = configuredCorrelation(t, 0)
	out := correlationOut(0, false)
	out.Switch.MissingCallchain = ""
	out.Switch.SwitchOutCallchain = []CallchainEntry{{IP: 123}}
	corrConsume(t, c, out, correlationWake(40), correlationIn(55))
	got = drainCorrelation(t, c, []uint32{0}, 55)
	if len(got) != 2 || len(got[0].SwitchOutCallchain) != 1 || len(got[1].SwitchOutCallchain) != 1 {
		t.Fatalf("stacks: %+v", got)
	}
	got[0].SwitchOutCallchain[0].IP = 7
	if got[1].SwitchOutCallchain[0].IP != 123 {
		t.Fatal("intervals share one switch-out stack")
	}
}

// I36, I37, I38: Finalize emits censored intervals in task-key order.
func TestCorrelationFinalizeOrdersTasksByKey(t *testing.T) {
	key := func(ns, tgid, tid uint32) TaskKey {
		k := correlationTask()
		k.PIDNamespace, k.TGID, k.TID = model.Uint64(ns), tgid, tid
		return k
	}
	for name, keys := range map[string][2]TaskKey{
		"namespace": {key(1, 7, 8), key(2, 7, 8)},
		"tgid":      {key(1, 7, 8), key(1, 9, 8)},
		"tid":       {key(1, 7, 8), key(1, 7, 9)},
	} {
		// Switch-out in reverse key order so neither insertion nor time order matches the key order.
		c := configuredCorrelation(t, 0)
		corrConsume(t, c, corrAt(corrOutTask(keys[1], 10), 0, 11), corrAt(corrOutTask(keys[0], 20), 0, 21))
		if err := c.ReportProgress(0, model.MonoNano(900*corrMs)); err != nil {
			t.Fatal(err)
		}
		got, err := c.Finalize(model.MonoNano(500 * corrMs))
		if err != nil || len(got) != 2 || got[0].Task != keys[0] || got[1].Task != keys[1] {
			t.Fatalf("%s order: %+v %v", name, got, err)
		}
	}
}

// I43: a loss event revokes coverage with its own reason.
func TestCorrelationLossKeepsItsReason(t *testing.T) {
	c := configuredCorrelation(t, 0)
	corrConsume(t, c, SanitizedEvent{Kind: EventLoss, Time: 20, Sequence: 21, Domain: correlationDomain, Loss: &LossEvent{Count: 3, Reason: ReasonSampleLost}})
	got := drainCorrelation(t, c, []uint32{0}, 100)
	if n, r := corrCorrections(got); n != 1 || r != ReasonSampleLost {
		t.Fatalf("loss correction %+v", got)
	}
}

// L33: a topology change that needs exactly the reserved bytes is allowed (Configure rounds slots down, so equality is reachable).
func TestCorrelationTopologyChangeAtExactReservation(t *testing.T) {
	c := NewCorrelator(DefaultConfig(1))
	// One CPU: base 16 KiB + 256 B; 2 slots * 2 * 16 KiB = 64 KiB; reservation 82176 B is consumed exactly.
	if err := c.Configure(correlationDomain, []uint32{0}, 82176); err != nil {
		t.Fatal(err)
	}
	if c.Stats().MaxHeapEvents != 2 {
		t.Fatalf("slots %+v", c.Stats())
	}
	if _, err := c.ChangeTopology(10, []uint32{0}); err != nil {
		t.Fatalf("topology change at exactly the reservation: %v", err)
	}
	if _, err := c.ChangeTopology(20, []uint32{0, 1}); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("topology change above the reservation: %v", err)
	}
}
