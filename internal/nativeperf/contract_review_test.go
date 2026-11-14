// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/model"
	"reflect"
	"testing"
)

// These tests catch lossy model wire tags, fabricated foreign identities,
// unsupported measurement claims, and conflation of resource/identity refusals.
func TestNativeCanonicalDecimalRoundTrip(t *testing.T) {
	const exact uint64 = 9007199254740993
	e := testEvent()
	e.Time = model.MonoNano(exact)
	e.Task.ProcessStart = model.MonoNano(exact)
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"time":"9007199254740993"`)) {
		t.Fatalf("noncanonical wire: %s", b)
	}
	var got SanitizedEvent
	if err = json.Unmarshal(b, &got); err != nil || !reflect.DeepEqual(e, got) {
		t.Fatalf("event roundtrip: %v %s", err, b)
	}
	for _, bad := range []string{`9007199254740993`, `"09007199254740993"`, `"+9007199254740993"`, `"9.007199254740993e15"`, `"18446744073709551616"`} {
		raw := bytes.Replace(b, []byte(`"time":"9007199254740993"`), []byte(`"time":`+bad), 1)
		if json.Unmarshal(raw, &got) == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	for _, value := range []uint64{0, 1, 9007199254740993, ^uint64(0)} {
		e.Time = model.MonoNano(value)
		b, _ = json.Marshal(e)
		if err = json.Unmarshal(b, &got); err != nil || uint64(got.Time) != value {
			t.Fatalf("boundary %d: %v", value, err)
		}
	}
	cfg := DefaultConfig(model.Revision(exact))
	b, _ = json.Marshal(cfg)
	var decoded Config
	if err = json.Unmarshal(b, &decoded); err != nil || decoded.PolicyRevision != model.Revision(exact) || decoded.Validate() != nil {
		t.Fatalf("config roundtrip %v %s", err, b)
	}
	target := Target{PIDNamespace: model.Uint64(exact), TGID: 1, ProcessStart: model.MonoNano(exact)}
	b, _ = json.Marshal(target)
	var rt Target
	if err = json.Unmarshal(b, &rt); err != nil || !reflect.DeepEqual(target, rt) {
		t.Fatal("target roundtrip", err)
	}
	chunk := ProfileChunk{ProfileID: model.ID{1}, PolicyRevision: model.Revision(exact)}
	b, err = json.Marshal(chunk)
	if err != nil {
		t.Fatal(err)
	}
	var rc ProfileChunk
	if err = json.Unmarshal(b, &rc); err != nil || rc.PolicyRevision != chunk.PolicyRevision {
		t.Fatal("chunk revision", err)
	}
}
func TestAuthorizedNullableSchedulerParticipants(t *testing.T) {
	e := testEvent()
	key := e.Task
	e.Task = TaskKey{}
	e.CPUEvent = nil
	e.Kind = EventSwitch
	e.Switch = &SchedulerSwitch{Previous: &key, MissingCallchain: ReasonMissingSwitchCallchain}
	if err := e.Validate(); err != nil {
		t.Fatal("authorized to idle", err)
	}
	e.Switch = &SchedulerSwitch{Next: &key}
	if err := e.Validate(); err != nil {
		t.Fatal("foreign to authorized", err)
	}
	e.Switch = &SchedulerSwitch{}
	if e.Validate() == nil {
		t.Fatal("unrelated switch accepted")
	}
	e.Switch = &SchedulerSwitch{Previous: &TaskKey{}}
	if e.Validate() == nil {
		t.Fatal("fabricated participant accepted")
	}
}
func TestLossAndProcessMappingNeedNoInventedThread(t *testing.T) {
	e := testEvent()
	key := e.Task
	e.Task = TaskKey{}
	e.CPUEvent = nil
	e.Kind = EventLoss
	e.Loss = &LossEvent{Count: 1, Reason: ReasonLoss}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	e.Kind = EventMapping
	e.Loss = nil
	e.Mapping = &MappingUpdate{Start: 4096, End: 8192, BuildID: "ab12", Process: ProcessKey{BootID: key.BootID, PIDNamespace: key.PIDNamespace, TGID: key.TGID, ProcessStart: key.ProcessStart, Generation: key.Generation}}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	e.Mapping.Process.Generation = 0
	if e.Validate() == nil {
		t.Fatal("mapping identity missing")
	}
}
func TestNativeSampleEvidence(t *testing.T) {
	e := testEvent()
	for _, mutate := range []func(*CPUSample){func(s *CPUSample) { s.Method = "timer" }, func(s *CPUSample) { s.Unit = UnitEngineSamples }, func(s *CPUSample) { s.Period = 0 }, func(s *CPUSample) { s.RequestedHz = 0 }, func(s *CPUSample) { s.Callchain = []CallchainEntry{{IP: model.Uint64(^uint64(511))}} }, func(s *CPUSample) { s.Truncated = ReasonPlatform }} {
		bad := *e.CPUEvent
		mutate(&bad)
		e.CPUEvent = &bad
		if e.Validate() == nil {
			t.Fatal("invalid native sampling evidence accepted")
		}
		e = testEvent()
	}
	e.CPUEvent.Callchain = []CallchainEntry{{Context: ContextUser}, {IP: 4096}}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
}
func TestCapabilitiesRejectUnmeasuredCounts(t *testing.T) {
	c := Capabilities{CPU: Unsupported, OffCPU: Unsupported, RunqueueSplit: Unsupported, Permissions: Permissions{CPUEventOpen: Unsupported, SchedulerEventOpen: Unsupported}, FrameCoverage: Coverage{Reasons: []Reason{ReasonUnmeasured}}, ThreadCoverage: Coverage{Reasons: []Reason{ReasonUnmeasured}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.FrameCoverage.Observed = 1
	if c.Validate() == nil {
		t.Fatal("unmeasured observations accepted")
	}
	c.FrameCoverage = Coverage{Measured: true, Observed: 2, Eligible: 1}
	if c.Validate() == nil {
		t.Fatal("observed exceeds eligible")
	}
}
func TestNativeTypedRefusals(t *testing.T) {
	if !errors.Is(validateTargets(make([]Target, 65)), ErrTooManyTargets) {
		t.Fatal("target cap untyped")
	}
	if !errors.Is((Target{}).Validate(), ErrTargetIdentity) {
		t.Fatal("identity untyped")
	}
	cfg := DefaultConfig(1)
	if !errors.Is(cfg.CheckResources(1000, 4096, 0, 256), ErrResourceBudget) {
		t.Fatal("resource refusal untyped")
	}
}
func TestIntervalDomainAndUnitValidation(t *testing.T) {
	e := testEvent()
	i := Interval{Kind: IntervalBlocked, Task: e.Task, Domain: e.Domain, Start: 0, End: 10, Measure: Measure{Unit: UnitNanoseconds, Value: 10}}
	if err := i.Validate(); err != nil {
		t.Fatal(err)
	}
	i.Measure.Unit = UnitNativeSamples
	if i.Validate() == nil {
		t.Fatal("duration has sample unit")
	}
	i.Measure = Measure{Unit: UnitNanoseconds, Value: 10}
	i.Task.BootID = "other"
	if i.Validate() == nil {
		t.Fatal("domain mismatch")
	}
}

func TestThrottleIsNotInventedLostSamples(t *testing.T) {
	e := testEvent()
	e.Kind = EventLoss
	e.Task = TaskKey{}
	e.CPUEvent = nil
	e.Loss = &LossEvent{Reason: ReasonThrottle, Throttle: &ThrottleEvidence{Reason: ReasonThrottle, EventID: 1, StreamID: 2}}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	e.Loss.Count = 1
	if e.Validate() == nil {
		t.Fatal("throttle treated as lost sample count")
	}
	e.Loss.Count = 0
	e.Loss.Throttle = nil
	if e.Validate() == nil {
		t.Fatal("missing throttle evidence accepted")
	}
	e.Loss = &LossEvent{Count: 1, Reason: ReasonSampleLost}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
}
