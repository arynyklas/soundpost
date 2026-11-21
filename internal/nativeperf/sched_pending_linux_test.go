//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// 04.02-C16 mutation battery re-run (mut0402, G042 G043 G046 G048): the scheduler stream's anti-starvation hand-off. A CPU
// sample drained while an older scheduler event waits is held; the older scheduler event leaves first, the held sample
// right after it, and each leaves exactly once. A sample held before Stop that lies past the stop instant is dropped, one
// at the instant is kept. A progress proof is not made more often than schedulerProgressInterval.

func pendingFixture(end model.MonoNano, pending *SanitizedEvent, samples ...KernelRecordView) *schedulerSource {
	task := TaskKey{BootID: "boot", PIDNamespace: 5, TGID: 70, TID: 71, ProcessStart: 1, Generation: 1}
	data := make([]byte, 256)
	total := 0
	for _, v := range samples {
		copy(data[total:], v.first)
		total += len(v.first)
	}
	ring := ringWithMeta(data, 0, uint64(total))
	ring.task, ring.method, ring.maxFrames = task, MethodSoftwareCPUClock, 128
	return &schedulerSource{done: make(chan struct{}), cpus: []uint32{0}, cpu: &cpuSource{domain: correlationDomain, rings: []*Ring{ring}}, stopped: true, end: end, pendingEvent: pending}
}

func TestSchedulerHoldsANewerCPUSampleBehindTheOlderSchedulerEventAndReleasesEachOnce(t *testing.T) {
	pending := correlationOut(10, false)
	s := pendingFixture(1<<40, &pending, cpuRecord(0x1000))
	first, e := s.NextItem(context.Background())
	if e != nil || first.Event == nil || first.Event.Kind != EventSwitch || first.Event.Time != 10 {
		t.Fatalf("the older scheduler event goes first: %+v %v", first.Event, e)
	}
	if s.pendingEvent != nil || s.pendingCPU == nil || s.pendingCPU.Time != 123456 {
		t.Fatalf("after it: pending scheduler event %v, held sample %v", s.pendingEvent, s.pendingCPU)
	}
	second, e := s.NextItem(context.Background())
	if e != nil || second.Event == nil || second.Event.Kind != EventCPU || second.Event.Time != 123456 {
		t.Fatalf("the held sample goes right after: %+v %v", second.Event, e)
	}
	if s.pendingCPU != nil || s.pendingEvent != nil {
		t.Fatalf("both hand-offs are spent: held %v pending %v", s.pendingCPU, s.pendingEvent)
	}
	third, e := s.NextItem(context.Background())
	if e != nil || third.Event != nil || third.Proof == nil || !third.Proof.Final {
		t.Fatalf("nothing is repeated: the stream ends with the final proof: %+v %v", third, e)
	}
	if _, e = s.NextItem(context.Background()); !errors.Is(e, ErrSourceComplete) {
		t.Fatal(e)
	}
}

// A CPU sample at exactly the instant of the waiting scheduler event is not newer than it: it leaves first and the scheduler
// event stays pending (G082).
func TestSchedulerSampleAtTheInstantOfTheWaitingEventIsNotHeldBehindIt(t *testing.T) {
	pending := correlationOut(123456, false)
	s := pendingFixture(1<<40, &pending, cpuRecord(0x1000))
	first, e := s.NextItem(context.Background())
	if e != nil || first.Event == nil || first.Event.Kind != EventCPU {
		t.Fatalf("the sample at the same instant goes first: %+v %v", first.Event, e)
	}
	if s.pendingCPU != nil || s.pendingEvent == nil {
		t.Fatalf("nothing is held, the scheduler event still waits: held %v pending %v", s.pendingCPU, s.pendingEvent)
	}
	second, e := s.NextItem(context.Background())
	if e != nil || second.Event == nil || second.Event.Kind != EventSwitch || second.Event.Time != 123456 {
		t.Fatalf("then the scheduler event: %+v %v", second.Event, e)
	}
}

func TestSchedulerHeldSampleIsDroppedPastTheStopInstantAndKeptAtIt(t *testing.T) {
	held := func(at model.MonoNano) *SanitizedEvent {
		e := SanitizedEvent{Kind: EventLoss, Time: at, Loss: &LossEvent{Count: 1, Reason: ReasonLoss}}
		return &e
	}
	// Stop came after the sample was held: the sample is newer than the instant the capture ended at.
	past := pendingFixture(100, nil)
	past.pendingCPU = held(101)
	item, e := past.NextItem(context.Background())
	if e != nil || item.Event != nil || item.Proof == nil || !item.Proof.Final || past.pendingCPU != nil {
		t.Fatalf("a held sample one past the stop instant: %+v %v (held %v)", item, e, past.pendingCPU)
	}
	at := pendingFixture(100, nil)
	at.pendingCPU = held(100)
	item, e = at.NextItem(context.Background())
	if e != nil || item.Event == nil || item.Event.Time != 100 {
		t.Fatalf("a held sample exactly at the stop instant is still the capture's: %+v %v", item, e)
	}
}

func TestSchedulerProgressProofIsNotMadeInsideTheProgressInterval(t *testing.T) {
	source := func(lastProgressAt time.Time) *schedulerSource {
		return &schedulerSource{done: make(chan struct{}), cpus: []uint32{0}, start: 1, lastProgressAt: lastProgressAt, cpu: &cpuSource{domain: correlationDomain, lastCheck: time.Now()}}
	}
	// A proof was made a moment ago: this pass waits for data instead of making another.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Millisecond)
	defer cancel()
	busy := source(time.Now())
	if item, e := busy.NextItem(ctx); item.Proof != nil || item.Event != nil || e == nil {
		t.Fatalf("a progress proof inside the interval: %+v %v", item, e)
	}
	// A pass that began before the capture did proves nothing about it (G084).
	early := source(time.Now().Add(-time.Second))
	early.start = model.MonoNano(1 << 62)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Millisecond)
	defer cancel2()
	if item, e := early.NextItem(ctx2); item.Proof != nil || item.Event != nil || e == nil {
		t.Fatalf("a progress proof through an instant before the capture's start: %+v %v", item, e)
	}
	// The interval has passed: the idle pass proves the prefix through its own start.
	due := source(time.Now().Add(-time.Second))
	item, e := due.NextItem(context.Background())
	if e != nil || item.Proof == nil || !item.Proof.Progress || item.Proof.Final || item.Proof.Through <= 1 {
		t.Fatalf("a progress proof after the interval: %+v %v", item, e)
	}
}
