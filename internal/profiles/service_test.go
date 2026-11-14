// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package profiles

import (
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
)

// Doubles cover only missing/corrupt pages; real scoped backend behavior is
// authored in appcore native-profile integration tests.
type deniedScope struct{}

func (deniedScope) Revalidate(context.Context, auth.Scope) error { return model.Fail(model.Forbidden) }

type panicScanner struct{}

func (panicScanner) ScanProfile(context.Context, auth.Scope, model.ID, Window) (ProfileIterator, error) {
	panic("scope denial touched storage")
}

type unavailableLinks struct{}

func (unavailableLinks) Resolve(_ context.Context, _ auth.Scope, refs []Reference) ([]ResolvedReference, error) {
	out := make([]ResolvedReference, len(refs))
	for i := range out {
		out[i] = ResolvedReference{Available: false}
	}
	return out, nil
}
func TestProfileDeniedScopeNeverTouchesScanner(t *testing.T) {
	s := NewService(panicScanner{}, deniedScope{}, unavailableLinks{})
	if _, err := s.Read(context.Background(), auth.Scope{}, model.ID{1}, Window{Start: 0, End: 1, MaxSamples: 1}); err == nil {
		t.Fatal("forged scope read profile")
	}
}
func TestProfileAssemblyPreservesSeparateUnitsAndRejectsCorrection(t *testing.T) {
	task := model.ProfileNativeTask{BootID: "boot", PIDNamespace: 1, TGID: 1, TID: 1, ProcessStart: 1, Generation: 1}
	c := model.ProfileChunk{Profile: model.ID{1}, Process: model.ID{2}, Capability: model.ID{3}, NativeCapabilities: []model.ID{{3}, {4}, {5}}, Method: "native_cpu", Units: "samples", NativeDomain: &model.ProfileNativeDomain{HostID: "host", BootID: "boot"}, Sequence: 1, PolicyRevision: 1, Clock: model.TraceClock{Wall: 10}, Frames: []model.ProfileFrame{{Reason: "frame_unresolved"}}, Stacks: []model.ProfileStack{{Frames: []uint32{0}}}, Samples: []model.ProfileSample{{At: 2, Stack: 0, Count: 1, Thread: 1, Native: &model.ProfileNativeSample{Task: task, Method: "hardware_cycles", Unit: "hardware_cycles", RequestedHz: 99, Period: 987}}}, Intervals: []model.ProfileInterval{{Start: 0, End: 4, Stack: 0, Kind: "blocked", Thread: 1, NativeTask: &task, Unit: "nanoseconds"}}}
	v := ProfileView{}
	if err := appendChunk(&v, c, 0, 8); err != nil {
		t.Fatal(err)
	}
	if v.BlockedNano == nil || *v.BlockedNano != 4 || len(v.Samples) != 1 || v.Samples[0].Native.Period != 987 || v.Units != "samples" {
		t.Fatal("CPU observations/periods/scheduler time conflated")
	}
	c.Intervals[0].Correction = true
	if err := appendChunk(&ProfileView{}, c, 0, 8); err == nil {
		t.Fatal("persisted correction added as measured time")
	}
}
func TestProfilePageMissingCapabilityIsIncomplete(t *testing.T) {
	p := ProfilePage{Chunks: []model.ProfileChunk{{Capability: model.ID{1}, NativeDomain: &model.ProfileNativeDomain{HostID: "host", BootID: "boot"}, NativeCapabilities: []model.ID{{1}, {2}, {3}}}}, Complete: true}
	if capabilitiesComplete(p) {
		t.Fatal("missing scheduler capability became supported/complete")
	}
	for i, method := range []string{"native_cpu", "native_offcpu", "native_runqueue_split"} {
		p.Capabilities = append(p.Capabilities, CapabilityRecord{ID: model.ID{byte(i + 1)}, Value: model.Capability{Runtime: "native_linux", Signal: model.Profile, Method: method}})
	}
	if !capabilitiesComplete(p) {
		t.Fatal("present exact capabilities not found")
	}
	p.Capabilities[2].Value.Method = "native_cpu"
	if capabilitiesComplete(p) {
		t.Fatal("duplicate CPU support substituted for runqueue evidence")
	}
}
func TestProfileUnobservedSchedulerIsNotZero(t *testing.T) {
	c := model.ProfileChunk{Profile: model.ID{1}, Process: model.ID{2}, Method: "native_cpu", Units: "samples", Frames: []model.ProfileFrame{{Reason: "frame_unresolved"}}, Stacks: []model.ProfileStack{{Frames: []uint32{0}}}, Samples: []model.ProfileSample{{Count: 1, Stack: 0}}}
	v := ProfileView{}
	if e := appendChunk(&v, c, 0, 8); e != nil {
		t.Fatal(e)
	}
	if v.BlockedNano != nil || v.RunnableNano != nil || v.UnknownNano != nil {
		t.Fatal("absent scheduler evidence was reported as measured zero")
	}
}
func TestProfileReadKeepsZeroCountThrottleWithoutSchedulerTime(t *testing.T) {
	task := model.ProfileNativeTask{BootID: "boot", PIDNamespace: 1, TGID: 1, TID: 1, ProcessStart: 1, Generation: 1}
	c := model.ProfileChunk{Profile: model.ID{1}, Process: model.ID{2}, Capability: model.ID{3}, NativeCapabilities: []model.ID{{3}, {4}, {5}}, PolicyRevision: 1, Sequence: 1, NativeDomain: &model.ProfileNativeDomain{HostID: "host", BootID: "boot"}, Method: "native_cpu", Units: "samples", Clock: model.TraceClock{Wall: 100}, Frames: []model.ProfileFrame{{Reason: "frame_unresolved"}}, Stacks: []model.ProfileStack{{Frames: []uint32{0}}}, Samples: []model.ProfileSample{{At: 2, Count: 1, Thread: 1, Native: &model.ProfileNativeSample{Task: task, Method: "software_cpu_clock", Unit: "cpu_clock_nanoseconds", RequestedHz: 99, Period: 3}}}, NativeLoss: []model.ProfileNativeLoss{{At: 1, Reason: "throttled", ThrottleEventID: 7, ThrottleStreamID: 9}, {At: 5, Reason: "unthrottled", ThrottleEventID: 7, ThrottleStreamID: 9}}}
	clipped, e := clipChunk(c, Window{Start: 100, End: 103})
	if e != nil {
		t.Fatal(e)
	}
	v := ProfileView{}
	if e = appendChunk(&v, clipped, 0, 8); e != nil {
		t.Fatal(e)
	}
	if len(v.NativeLoss) != 1 || v.NativeLoss[0].Reason != "throttled" || v.NativeLoss[0].Count != 0 || v.BlockedNano != nil || v.RunnableNano != nil || v.UnknownNano != nil {
		t.Fatal("throttle transition dropped, counted or turned into elapsed time")
	}
}
