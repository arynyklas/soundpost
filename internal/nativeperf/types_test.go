// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"encoding/json"
	"runtime"
	"soundpost/internal/model"
	"testing"
)

func testEvent() SanitizedEvent {
	return SanitizedEvent{Kind: EventCPU, Time: 1, CPU: 0, Sequence: 1, Domain: ClockDomain{BootID: "boot", HostID: "host"}, Task: TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 1, TID: 1, ProcessStart: 1, Generation: 1}, CPUEvent: &CPUSample{IP: 4096, Callchain: []CallchainEntry{{IP: 4096}}, Method: MethodSoftwareCPUClock, Unit: UnitCPUClockNanoseconds, RequestedHz: 99, Period: 10000000}}
}
func TestTypedNativeEventsRejectContent(t *testing.T) {
	e := testEvent()
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*SanitizedEvent){func(e *SanitizedEvent) { e.Kind = "command" }, func(e *SanitizedEvent) { e.Task.Generation = 0 }, func(e *SanitizedEvent) { e.Domain.BootID = "other" }, func(e *SanitizedEvent) { e.Wakeup = &SchedulerWakeup{Target: e.Task} }, func(e *SanitizedEvent) { e.Sequence = 0 }} {
		bad := testEvent()
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid event accepted")
		}
	}
	b, _ := json.Marshal(e)
	for _, field := range []string{`"command":"secret"`, `"stack_bytes":"AA=="`, `"registers":[1]`} {
		raw := append([]byte(nil), b[:len(b)-1]...)
		raw = append(raw, []byte(","+field+"}")...)
		var dst SanitizedEvent
		if json.Unmarshal(raw, &dst) == nil {
			t.Fatal("content field accepted")
		}
	}
}
func TestUnitsCannotBeAdded(t *testing.T) {
	if _, err := (Measure{Unit: UnitEngineSamples, Value: 1}).Add(Measure{Unit: UnitNanoseconds, Value: 1}); err == nil {
		t.Fatal("incompatible units added")
	}
	if got, err := (Measure{Unit: UnitNanoseconds, Value: 1}).Add(Measure{Unit: UnitNanoseconds, Value: 2}); err != nil || got.Value != 3 {
		t.Fatal(got, err)
	}
}
func TestUnsupportedPlatformIsNotEmptySuccess(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux runtime test")
	}
	c, err := Probe(context.Background(), nil)
	if err == nil || c.CPU != Unsupported || c.OffCPU != Unsupported {
		t.Fatal(c, err)
	}
	s, err := Open(context.Background(), nil, DefaultConfig(model.Revision(1)))
	if err == nil || s != nil {
		t.Fatal("fake session", s, err)
	}
}
func TestConfigBounds(t *testing.T) {
	c := DefaultConfig(1)
	if c.Validate() != nil {
		t.Fatal(c)
	}
	c.MaxMemory++
	if c.Validate() == nil {
		t.Fatal("memory budget widened")
	}
}
