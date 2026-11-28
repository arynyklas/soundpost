//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf

import (
	"errors"
	"os"
	"testing"
	"time"
)

// Inside the 10 ms identity cadence a thread of the target can exit and its TID be handed to another process; the
// kernel's scheduler record carries only the raw pid, so the label would be the original task's. An event naming a
// task is therefore published only after that task's own perf event says its thread is still there (the event
// reports POLLHUP from the moment the task exits, which is before its TID can be reused), not against the cadence
// (review of 1b1a47c).
func TestSchedulerPublishRefusesARecycledTIDInsideTheCadence(t *testing.T) {
	target, err := ResolveLocalTarget(os.Getpid())
	if err != nil {
		t.Skip("local target unresolved")
	}
	a := AuthorizedTargets{targets: []Target{target}, mode: ModeCPUOffCPU}
	threads, err := snapshotCPUThreads(a, correlationDomain)
	if err != nil || len(threads) == 0 {
		t.Skip("no thread snapshot")
	}
	exited := map[TaskKey]bool{}
	asked := 0
	source := func() *schedulerSource {
		cpu := &cpuSource{targets: a, threads: threads, domain: correlationDomain, lastCheck: time.Now(),
			gone: func(k TaskKey) (bool, error) { asked++; return exited[k], nil }}
		return &schedulerSource{done: make(chan struct{}), cpus: []uint32{0}, cpu: cpu}
	}
	switchTo := func(k TaskKey) SanitizedEvent {
		return SanitizedEvent{Kind: EventSwitch, Switch: &SchedulerSwitch{Next: &k}}
	}
	wake := func(k TaskKey) SanitizedEvent {
		return SanitizedEvent{Kind: EventWakeup, Task: k, Wakeup: &SchedulerWakeup{Target: k}}
	}
	// the genuine thread publishes inside the cadence, one question per named task
	good := source()
	if item, e := good.publish(switchTo(threads[0].task)); e != nil || item.Event == nil {
		t.Fatalf("a live thread was refused: %v", e)
	}
	if asked != 1 {
		t.Fatalf("one named task asked %d times", asked)
	}
	// the thread exited (its TID may already belong to someone else): refused although the last check was just now
	exited[threads[0].task] = true
	for name, ev := range map[string]SanitizedEvent{"switch": switchTo(threads[0].task), "wakeup": wake(threads[0].task)} {
		s := source()
		if item, e := s.publish(ev); !errors.Is(e, ErrThreadCoverageChanged) || item.Event != nil || s.terminal == nil {
			t.Fatalf("%s of an exited thread inside the cadence was published: %+v %v", name, item, e)
		}
	}
	// a failed question is a refusal too, never a publication
	failing := source()
	failing.cpu.gone = func(TaskKey) (bool, error) { return false, ErrAcquisitionFailed }
	if item, e := failing.publish(switchTo(threads[0].task)); e == nil || item.Event != nil {
		t.Fatalf("an unanswerable question published: %+v %v", item, e)
	}
	// a task the snapshot never recorded cannot be vouched for
	stranger := threads[0].task
	stranger.TID = 4194303
	exited[threads[0].task] = false
	unknown := source()
	unknown.cpu.gone = nil
	if item, e := unknown.publish(switchTo(stranger)); !errors.Is(e, ErrThreadCoverageChanged) || item.Event != nil {
		t.Fatalf("an unknown TID was published: %+v %v", item, e)
	}
}

// A failed identity check leaves the time of the last successful one: a consumer can revoke [verified, end).
func TestSchedulerRecordsWhenItsIdentityWasLastVerified(t *testing.T) {
	target, err := ResolveLocalTarget(os.Getpid())
	if err != nil {
		t.Skip("local target unresolved")
	}
	a := AuthorizedTargets{targets: []Target{target}, mode: ModeCPUOffCPU}
	threads, err := snapshotCPUThreads(a, correlationDomain)
	if err != nil {
		t.Skip("no thread snapshot")
	}
	c := &cpuSource{targets: a, threads: threads, domain: correlationDomain}
	if !c.provenAt.IsZero() {
		t.Fatal("verified before any check")
	}
	if e := c.checkIdentity(); e != nil {
		t.Skip(e)
	}
	if c.provenAt.IsZero() || time.Since(c.provenAt) > time.Second {
		t.Fatalf("provenAt %v", c.provenAt)
	}
}
