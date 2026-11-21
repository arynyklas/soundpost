//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf

import (
	"testing"
	"time"
)

// The identity of the target (its process and every thread, from /proc) is revalidated on a cadence while the
// scheduler stream is published, not before every single event: a target with 16 threads (Bun) emits thousands of
// events a second, a full /proc snapshot per event could not keep up, the rings overran and the capture lost its
// coverage. A source with no live targets fails the revalidation, which shows exactly when it runs.
func TestSchedulerPublishRevalidatesIdentityOnACadenceNotPerEvent(t *testing.T) {
	event := func() SanitizedEvent {
		return SanitizedEvent{Kind: EventLoss, Loss: &LossEvent{Count: 1, Reason: ReasonLoss}}
	}
	source := func(lastCheck time.Time) *schedulerSource {
		return &schedulerSource{done: make(chan struct{}), cpus: []uint32{0}, cpu: &cpuSource{domain: correlationDomain, lastCheck: lastCheck}}
	}
	// checked a moment ago: the next events go out without another snapshot
	fresh := source(time.Now())
	for i := range 50 {
		if item, e := fresh.publish(event()); e != nil || item.Event == nil || uint64(item.Event.Sequence) != uint64(i+1) {
			t.Fatalf("event %d right after a successful check was held up: %+v %v", i, item, e)
		}
	}
	// the last check is older than the cadence: the identity is revalidated before the event leaves, and a target
	// that no longer verifies ends the stream with the identity error and publishes nothing
	stale := source(time.Now().Add(-time.Second))
	if item, e := stale.publish(event()); e == nil || item.Event != nil || stale.terminal == nil {
		t.Fatalf("an event left behind a stale identity check that no longer verifies: %+v %v", item, e)
	}
	// the cadence is bounded: one event after it has passed is checked, one just inside it is not
	if schedulerIdentityInterval <= 0 || schedulerIdentityInterval > 20*time.Millisecond {
		t.Fatalf("identity cadence %v", schedulerIdentityInterval)
	}
	edge := source(time.Now().Add(-schedulerIdentityInterval - time.Millisecond))
	if _, e := edge.publish(event()); e == nil {
		t.Fatal("an event past the cadence was not revalidated")
	}
	inside := source(time.Now().Add(-schedulerIdentityInterval / 2))
	if _, e := inside.publish(event()); e != nil {
		t.Fatalf("an event inside the cadence was revalidated: %v", e)
	}
	// a stopped source (the final drain) does not revalidate at all: Stop did it
	stopped := source(time.Now().Add(-time.Hour))
	stopped.stopped = true
	if _, e := stopped.publish(event()); e != nil {
		t.Fatal(e)
	}
}
