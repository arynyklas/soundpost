// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/model"
	"reflect"
	"testing"
)

var correlationDomain = ClockDomain{HostID: "host", BootID: "boot"}

func correlationTask() TaskKey {
	return TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}
}
func correlationOut(at uint64, runnable bool) SanitizedEvent {
	k := correlationTask()
	state := uint64(1)
	if runnable {
		state = 0
	}
	return SanitizedEvent{Kind: EventSwitch, Time: model.MonoNano(at), Sequence: model.Uint64(at + 1), Domain: correlationDomain, Switch: &SchedulerSwitch{Previous: &k, PreviousState: model.Uint64(state), MissingCallchain: ReasonMissingSwitchCallchain}}
}
func correlationIn(at uint64) SanitizedEvent {
	k := correlationTask()
	return SanitizedEvent{Kind: EventSwitch, Time: model.MonoNano(at), Sequence: model.Uint64(at + 1), Domain: correlationDomain, Switch: &SchedulerSwitch{Next: &k}}
}
func correlationWake(at uint64) SanitizedEvent {
	k := correlationTask()
	return SanitizedEvent{Kind: EventWakeup, Time: model.MonoNano(at), Sequence: model.Uint64(at + 1), Domain: correlationDomain, Task: k, Wakeup: &SchedulerWakeup{Target: k, TargetCPU: 0}}
}
func configuredCorrelation(t *testing.T, cpus ...uint32) *Correlator {
	t.Helper()
	c := NewCorrelator(DefaultConfig(1))
	if err := c.Configure(correlationDomain, cpus, 4<<20); err != nil {
		t.Fatal(err)
	}
	return c
}
func feedCorrelation(t *testing.T, c *Correlator, events ...SanitizedEvent) []Interval {
	t.Helper()
	var out []Interval
	for _, e := range events {
		got, err := c.Consume(e)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, got...)
	}
	return out
}
func drainCorrelation(t *testing.T, c *Correlator, cpus []uint32, at uint64) []Interval {
	t.Helper()
	for _, cpu := range cpus {
		if err := c.ReportProgress(cpu, model.MonoNano(at+100000000)); err != nil {
			t.Fatal(err)
		}
	}
	out, err := c.Advance(model.MonoNano(at))
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range out {
		if err := i.Validate(); err != nil {
			t.Fatalf("invalid interval %+v: %v", i, err)
		}
	}
	return out
}
func TestBlockedThenRunqueue(t *testing.T) {
	c := configuredCorrelation(t, 0)
	feedCorrelation(t, c, correlationOut(0, false), correlationWake(40000000), correlationIn(55000000))
	got := drainCorrelation(t, c, []uint32{0}, 55000000)
	if len(got) != 2 || got[0].Kind != IntervalBlocked || got[0].Measure.Value != 40000000 || got[1].Kind != IntervalRunnable || got[1].Measure.Value != 15000000 {
		t.Fatalf("incorrect split: %+v", got)
	}
}
func TestPreemptedRunnable(t *testing.T) {
	for _, preempted := range []bool{false, true} {
		c := configuredCorrelation(t, 0)
		out := correlationOut(0, true)
		out.Switch.Preempted = preempted
		feedCorrelation(t, c, out, correlationIn(20000000))
		got := drainCorrelation(t, c, []uint32{0}, 20000000)
		if len(got) != 1 || got[0].Kind != IntervalRunnable || got[0].Measure.Value != 20000000 {
			t.Fatalf("preempted=%v: %+v", preempted, got)
		}
	}
}
func TestCorrelationMissingWakeAndRepeatedWake(t *testing.T) {
	c := configuredCorrelation(t, 0)
	feedCorrelation(t, c, correlationOut(0, false), correlationIn(55000000))
	got := drainCorrelation(t, c, []uint32{0}, 55000000)
	if len(got) != 1 || got[0].Kind != IntervalUnknown || got[0].Measure.Value != 55000000 {
		t.Fatalf("invented blocked: %+v", got)
	}
	c = configuredCorrelation(t, 0)
	feedCorrelation(t, c, correlationOut(0, false), correlationWake(40000000), correlationWake(45000000), correlationIn(55000000))
	got = drainCorrelation(t, c, []uint32{0}, 55000000)
	if len(got) != 2 || got[0].Measure.Value != 40000000 || got[1].Measure.Value != 15000000 {
		t.Fatalf("repeated wake counted twice: %+v", got)
	}
}
func TestCorrelationSessionIsolation(t *testing.T) {
	a, b := configuredCorrelation(t, 0), configuredCorrelation(t, 0)
	feedCorrelation(t, a, correlationOut(0, false), correlationWake(40), correlationIn(55))
	feedCorrelation(t, b, correlationOut(0, true), correlationIn(55))
	ga, gb := drainCorrelation(t, a, []uint32{0}, 55), drainCorrelation(t, b, []uint32{0}, 55)
	if len(ga) != 2 || len(gb) != 1 || gb[0].Kind != IntervalRunnable {
		t.Fatalf("shared state: %+v %+v", ga, gb)
	}
}
func TestCorrelationSwitchOutStackOwnedAndNeverBorrowed(t *testing.T) {
	c := configuredCorrelation(t, 0)
	out := correlationOut(0, false)
	out.Switch.MissingCallchain = ""
	out.Switch.SwitchOutCallchain = []CallchainEntry{{IP: 123}}
	feedCorrelation(t, c, out)
	out.Switch.SwitchOutCallchain[0].IP = 999
	sample := testEvent()
	sample.Domain = correlationDomain
	sample.Task = correlationTask()
	sample.Time = 20
	sample.Sequence = 20
	sample.CPUEvent.Callchain = []CallchainEntry{{IP: 777}}
	feedCorrelation(t, c, sample, correlationWake(40), correlationIn(55))
	got := drainCorrelation(t, c, []uint32{0}, 55)
	var duration int
	for _, i := range got {
		if i.Kind == IntervalCPU {
			if i.Measure.Unit != UnitNativeSamples || i.Measure.Value != 1 {
				t.Fatalf("CPU became elapsed time: %+v", i)
			}
			continue
		}
		duration++
		if len(i.SwitchOutCallchain) != 1 || i.SwitchOutCallchain[0].IP != 123 {
			t.Fatalf("borrowed unrelated stack: %+v", i)
		}
	}
	if duration != 2 {
		t.Fatalf("missing durations: %+v", got)
	}
}
func TestCorrelationFinalCensor(t *testing.T) {
	c := configuredCorrelation(t, 0)
	feedCorrelation(t, c, correlationOut(0, false), correlationWake(40))
	if err := c.ReportProgress(0, 55); err != nil {
		t.Fatal(err)
	}
	got, err := c.Finalize(55)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != IntervalCensored || got[0].Start != 0 || got[0].End != 55 {
		t.Fatalf("manufactured completed wait: %+v", got)
	}
	if _, err = c.Consume(correlationIn(60)); err == nil {
		t.Fatal("consumed after finalization")
	}
}
func TestCorrelationLateCorrectionDoesNotMutateReturnedMemory(t *testing.T) {
	c := configuredCorrelation(t, 0)
	feedCorrelation(t, c, correlationOut(0, false), correlationWake(40), correlationIn(55))
	first := drainCorrelation(t, c, []uint32{0}, 55)
	saved := append([]Interval(nil), first...)
	corrections, err := c.Consume(correlationWake(20))
	if err == nil {
		t.Fatal("late record not classified")
	}
	if len(corrections) != 1 || !corrections[0].Correction || corrections[0].Start != 0 || corrections[0].End < 55 || corrections[0].Task != (TaskKey{}) {
		t.Fatalf("no historical invalidation: %+v", corrections)
	}
	if !reflect.DeepEqual(saved, first) {
		t.Fatal("mutated returned memory")
	}
}
func TestCorrelationLossGenerationClockAndConflicts(t *testing.T) {
	for _, kind := range []string{"loss", "generation", "clock", "reuse", "conflict"} {
		t.Run(kind, func(t *testing.T) {
			c := configuredCorrelation(t, 0)
			events := []SanitizedEvent{correlationOut(0, false)}
			e := correlationWake(20)
			switch kind {
			case "loss":
				e = SanitizedEvent{Kind: EventLoss, Time: 20, Sequence: 21, Domain: correlationDomain, Loss: &LossEvent{Count: 1, Reason: ReasonLoss}}
			case "generation":
				e.Kind = EventGeneration
				e.Wakeup = nil
				e.Task.Generation = 2
				e.Generation = &TargetGeneration{Previous: 1, Current: 2}
			case "clock":
				e.Domain.HostID = "other"
			case "reuse":
				e.Task.ProcessStart = 2
				e.Wakeup.Target = e.Task
			case "conflict":
				e = correlationOut(20, false)
			}
			events = append(events, e, correlationIn(55))
			var got []Interval
			for _, event := range events {
				is, err := c.Consume(event)
				if err != nil && kind != "clock" {
					t.Fatal(err)
				}
				got = append(got, is...)
			}
			got = append(got, drainCorrelation(t, c, []uint32{0}, 55)...)
			correction := false
			for _, i := range got {
				if i.Correction {
					correction = true
				}
				if i.Kind == IntervalBlocked || i.Kind == IntervalRunnable {
					t.Fatalf("crossed invalidation boundary: %+v", got)
				}
			}
			if !correction {
				t.Fatalf("uncertainty disappeared: %+v", got)
			}
		})
	}
}
func TestCorrelationBudgetOverflowExplicit(t *testing.T) {
	c := NewCorrelator(DefaultConfig(1))
	if err := c.Configure(correlationDomain, []uint32{0}, 64<<10); err != nil {
		t.Fatal(err)
	}
	var overflow bool
	for n := range 10000 {
		e := correlationOut(uint64(n), false)
		out, err := c.Consume(e)
		if errors.Is(err, ErrResourceBudget) {
			overflow = true
			if len(out) != 1 || !out[0].Correction {
				t.Fatal("overflow without gap")
			}
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !overflow {
		t.Fatal("unbounded heap accepted")
	}
	s := c.Stats()
	if s.ReservedBytes > 64<<10 || s.HeapEvents != 0 {
		t.Fatalf("budget not bounded: %+v", s)
	}
}

func TestCorrelationTaskBudgetDoesNotGrowAcrossAdvances(t *testing.T) {
	c := NewCorrelator(DefaultConfig(1))
	if err := c.Configure(correlationDomain, []uint32{0}, 64<<10); err != nil {
		t.Fatal(err)
	}
	feedCorrelation(t, c, correlationOut(0, false))
	drainCorrelation(t, c, []uint32{0}, 0)
	other := correlationOut(200000000, false)
	other.Switch.Previous.TID = 9
	feedCorrelation(t, c, other)
	got := drainCorrelation(t, c, []uint32{0}, 200000000)
	if len(got) != 1 || !got[0].Correction || c.Stats().TaskStates != 0 {
		t.Fatalf("task overflow silently retained certainty: %+v %+v", got, c.Stats())
	}
}

func TestCorrelationLossRevokesPreviouslyReturnedDurations(t *testing.T) {
	c := configuredCorrelation(t, 0)
	feedCorrelation(t, c, correlationOut(0, true), correlationIn(20))
	prior := drainCorrelation(t, c, []uint32{0}, 20)
	loss := SanitizedEvent{Kind: EventLoss, Time: 200000000, Sequence: 23, Domain: correlationDomain, Loss: &LossEvent{Count: 1, Reason: ReasonLoss}}
	feedCorrelation(t, c, loss)
	gaps := drainCorrelation(t, c, []uint32{0}, 200000000)
	if len(prior) != 1 || len(gaps) != 1 || !gaps[0].Correction || gaps[0].Start > prior[0].Start || gaps[0].End < prior[0].End {
		t.Fatalf("historical certainty survives unknown loss range: %+v %+v", prior, gaps)
	}
}

func TestCorrelationCPUIdentityReuseInvalidatesWait(t *testing.T) {
	c := configuredCorrelation(t, 0)
	sample := testEvent()
	sample.Domain = correlationDomain
	sample.Task = correlationTask()
	sample.Task.ProcessStart = 2
	sample.Time = 20
	sample.Sequence = 21
	feedCorrelation(t, c, correlationOut(0, false), sample, correlationIn(55))
	got := drainCorrelation(t, c, []uint32{0}, 55)
	var correction bool
	for _, i := range got {
		correction = correction || i.Correction
		if i.Kind == IntervalBlocked || i.Kind == IntervalRunnable || i.Kind == IntervalUnknown && !i.Correction {
			t.Fatalf("joined reused PID: %+v", got)
		}
	}
	if !correction {
		t.Fatalf("CPU reuse not invalidated: %+v", got)
	}
}

func TestCorrelationMissingSwitchOutIsCoverageGap(t *testing.T) {
	c := configuredCorrelation(t, 0)
	feedCorrelation(t, c, correlationIn(55))
	got := drainCorrelation(t, c, []uint32{0}, 55)
	if len(got) != 1 || !got[0].Correction || got[0].End != 55 {
		t.Fatalf("missing switch treated as complete zero activity: %+v", got)
	}
}

func TestCorrelationIntervalCorrectionAndStackValidation(t *testing.T) {
	gap := Interval{Kind: IntervalUnknown, Domain: correlationDomain, Start: 1, End: 9007199254740993, Measure: Measure{Unit: UnitNanoseconds, Value: 9007199254740992}, Reason: ReasonLoss, Correction: true}
	if err := gap.Validate(); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(gap)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Interval
	if err = json.Unmarshal(wire, &decoded); err != nil || !reflect.DeepEqual(decoded, gap) {
		t.Fatalf("correction canonical roundtrip: %s %v", wire, err)
	}
	for _, mutate := range []func(*Interval){func(i *Interval) { i.Kind = IntervalBlocked }, func(i *Interval) { i.Reason = "" }, func(i *Interval) { i.Measure.Unit = UnitNativeSamples }, func(i *Interval) { i.Task = TaskKey{TID: 2} }, func(i *Interval) { i.SwitchOutCallchain = []CallchainEntry{{IP: 1}} }} {
		bad := gap
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatalf("invalid correction accepted: %+v", bad)
		}
	}
	interval := Interval{Kind: IntervalBlocked, Task: correlationTask(), Domain: correlationDomain, Start: 0, End: 1, Measure: Measure{Unit: UnitNanoseconds, Value: 1}, SwitchOutCallchain: []CallchainEntry{{Context: ContextUser}, {IP: 4096}}}
	if err := interval.Validate(); err != nil {
		t.Fatal(err)
	}
	interval.SwitchOutCallchain[1].IP = model.Uint64(^uint64(511))
	if interval.Validate() == nil {
		t.Fatal("context sentinel accepted as address")
	}
	interval.SwitchOutCallchain = nil
	interval.MissingCallchain = ReasonMissingSwitchCallchain
	if err := interval.Validate(); err != nil {
		t.Fatal(err)
	}
	interval.Kind = IntervalCPU
	interval.End = interval.Start
	interval.Measure = Measure{Unit: UnitNativeSamples, Value: 1}
	if interval.Validate() == nil {
		t.Fatal("CPU sample given switch-out stack metadata")
	}
}

func TestCorrelationProcessReuseAcrossDifferentTIDInvalidatesWait(t *testing.T) {
	c := configuredCorrelation(t, 0)
	sample := testEvent()
	sample.Domain = correlationDomain
	sample.Task = correlationTask()
	sample.Task.TID = 9
	sample.Task.ProcessStart = 2
	sample.Time = 20
	sample.Sequence = 21
	feedCorrelation(t, c, correlationOut(0, false), sample, correlationWake(40), correlationIn(55))
	got := drainCorrelation(t, c, []uint32{0}, 55)
	var correction bool
	for _, i := range got {
		correction = correction || i.Correction
		if i.Kind == IntervalBlocked || i.Kind == IntervalRunnable {
			t.Fatalf("joined reused process through different thread: %+v", got)
		}
	}
	if !correction {
		t.Fatal("missing process reuse correction")
	}
}
