// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
)

func scopeTask(tid uint32) TaskKey {
	return TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: tid, ProcessStart: 1, Generation: 1}
}

// scopeSwitch is one sched_switch on CPU 0: previous (nil = idle) leaves the CPU
// preempted/runnable (state 0) or sleeping, next (nil = idle) takes it.
func scopeSwitch(at uint64, prev, next *TaskKey, sleeping bool) SanitizedEvent {
	s := &SchedulerSwitch{Previous: prev, Next: next}
	if prev != nil {
		s.MissingCallchain = ReasonMissingSwitchCallchain
		state := uint64(0)
		if sleeping {
			state = 1
		}
		s.PreviousState = model.Uint64(state)
	}
	return SanitizedEvent{Kind: EventSwitch, Time: model.MonoNano(at), Sequence: model.Uint64(at + 1), Domain: correlationDomain, Switch: s}
}

func scopeWake(at uint64, target TaskKey) SanitizedEvent {
	return SanitizedEvent{Kind: EventWakeup, Time: model.MonoNano(at), Sequence: model.Uint64(at + 1), Domain: correlationDomain, Task: target, Wakeup: &SchedulerWakeup{Target: target, TargetCPU: 0}}
}

func scopeCorrections(intervals []Interval) (domainWide int, perTask map[TaskKey]int) {
	perTask = map[TaskKey]int{}
	for _, i := range intervals {
		if !i.Correction {
			continue
		}
		if i.Task == (TaskKey{}) {
			domainWide++
		} else {
			perTask[i.Task]++
		}
	}
	return
}

// A task whose switch-out was never observed (it was already off the CPU when the
// capture began) lacks a baseline FOR ITSELF. Its first switch-in must leave a
// coverage gap for that task only: every other task's recorded wait is still
// evidence-complete and must close with its measured blocked/runnable split.
func TestMissingBaselineOfOneTaskDoesNotRevokeAnotherTasksCoverage(t *testing.T) {
	a, b := scopeTask(8), scopeTask(9)
	c := configuredCorrelation(t, 0)
	// a sleeps from 0, is woken at 40 and runs again at 55; b, which the capture
	// never saw leave the CPU, first appears switching in at 20.
	feedCorrelation(t, c,
		scopeSwitch(0, &a, nil, true),
		scopeSwitch(20, nil, &b, false),
		scopeWake(40, a),
		scopeSwitch(55, nil, &a, false))
	got := drainCorrelation(t, c, []uint32{0}, 55)
	domainWide, perTask := scopeCorrections(got)
	if domainWide != 0 {
		t.Fatalf("one task's missing baseline revoked the whole domain: %+v", got)
	}
	if perTask[b] != 1 || len(perTask) != 1 {
		t.Fatalf("the gap must be b's alone: %v in %+v", perTask, got)
	}
	var blocked, runnable uint64
	for _, i := range got {
		if i.Correction || i.Task != a {
			continue
		}
		switch i.Kind {
		case IntervalBlocked:
			blocked += uint64(i.End - i.Start)
		case IntervalRunnable:
			runnable += uint64(i.End - i.Start)
		}
	}
	if blocked != 40 || runnable != 15 {
		t.Fatalf("a's split was lost to b's gap: blocked %d runnable %d in %+v", blocked, runnable, got)
	}
	for _, i := range got {
		if i.Correction && i.Task == b && (i.Start != 0 || i.End != 20) {
			t.Fatalf("b's gap must cover everything before its first sighting: %+v", i)
		}
	}
}

// Three tasks taking turns on one CPU: when the first sightings of two of them are
// treated as domain-wide losses, each revocation clears the baseline of the task
// that just left the CPU, so every following switch-in is a "missing baseline"
// again and the cascade never ends (one revocation per switch for the whole run).
func TestMissingBaselinesDoNotCascadeThroughTasksTakingTurns(t *testing.T) {
	keys := []TaskKey{scopeTask(10), scopeTask(11), scopeTask(12)}
	c := configuredCorrelation(t, 0)
	const switches = 60
	var events []SanitizedEvent
	for i := range switches {
		prev, next := keys[i%3], keys[(i+1)%3]
		events = append(events, scopeSwitch(uint64(10*(i+1)), &prev, &next, false))
	}
	feedCorrelation(t, c, events...)
	got := drainCorrelation(t, c, []uint32{0}, 10*switches)
	domainWide, perTask := scopeCorrections(got)
	if domainWide != 0 {
		t.Fatalf("%d domain-wide revocations for tasks that were merely first seen", domainWide)
	}
	// keys[1] and keys[2] were off the CPU before the capture: one gap each.
	if len(perTask) != 2 || perTask[keys[1]] != 1 || perTask[keys[2]] != 1 {
		t.Fatalf("gaps must be exactly one per unseen task: %v", perTask)
	}
	runnable := 0
	for _, i := range got {
		if !i.Correction && i.Kind == IntervalRunnable {
			runnable++
			if i.End-i.Start != 20 {
				t.Fatalf("a task waits two switches behind the other two: %+v", i)
			}
		}
	}
	// switch i (from the third on) closes the wait of keys[(i+1)%3] that opened two switches earlier.
	if runnable != switches-2 {
		t.Fatalf("want %d complete runnable intervals, got %d", switches-2, runnable)
	}
}

// Explicit evidence of loss still revokes everything: scoping applies only to a
// missing baseline, never to a reported loss.
func TestMissingBaselineScopeKeepsExplicitLossDomainWide(t *testing.T) {
	a := scopeTask(8)
	c := configuredCorrelation(t, 0)
	loss := SanitizedEvent{Kind: EventLoss, Time: 30, Sequence: 31, Domain: correlationDomain, Loss: &LossEvent{Count: 1, Reason: ReasonLoss}}
	feedCorrelation(t, c, scopeSwitch(0, &a, nil, true), loss, scopeSwitch(55, nil, &a, false))
	got := drainCorrelation(t, c, []uint32{0}, 55)
	domainWide, _ := scopeCorrections(got)
	if domainWide == 0 {
		t.Fatalf("explicit loss no longer revokes the domain: %+v", got)
	}
	for _, i := range got {
		if !i.Correction && (i.Kind == IntervalBlocked || i.Kind == IntervalRunnable) {
			t.Fatalf("a wait that crossed a loss was reported as measured: %+v", i)
		}
	}
}
