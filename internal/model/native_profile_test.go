// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func nativeProfileFixture() ProfileChunk {
	return ProfileChunk{Profile: ID{1}, Process: ID{2}, Capability: ID{3}, Clock: TraceClock{Domain: ClockDomain{Host: ID{6}, Boot: ID{7}, Runtime: ID{8}}}, Method: "native_cpu", Units: "samples", Frames: []ProfileFrame{{Reason: "frame_unresolved"}}, Stacks: []ProfileStack{{Frames: []uint32{0}}}, NativeDomain: &ProfileNativeDomain{HostID: "host", BootID: "boot"}, NativeCapabilities: []ID{{3}, {4}, {5}}, PolicyRevision: 1, Sequence: 1, Samples: []ProfileSample{{At: 1, Stack: 0, Count: 1, Thread: 8, Native: &ProfileNativeSample{Task: ProfileNativeTask{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}, Method: "software_cpu_clock", Unit: "cpu_clock_nanoseconds", RequestedHz: 99, Period: 9007199254740993}}}}
}
func TestNativeProfilePeriodsCanonicalAndDistinctUnits(t *testing.T) {
	c := nativeProfileFixture()
	if e := validateNativeProfile(&c); e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(b), `"period":"9007199254740993"`) {
		t.Fatal("native period rounded or numeric")
	}
	var decoded ProfileChunk
	if e = StrictJSON(b, &decoded); e != nil || decoded.Samples[0].Native.Period != 9007199254740993 {
		t.Fatal("native canonical period changed")
	}
	decoded.Samples[0].Native.Unit = "nanoseconds"
	if validateNativeProfile(&decoded) == nil {
		t.Fatal("scheduler time confused with CPU-clock period")
	}
}
func TestNativeProfileRejectsUnprovenOrPrivateMetadata(t *testing.T) {
	cases := []func(*ProfileChunk){func(c *ProfileChunk) { c.NativeCapabilities = c.NativeCapabilities[:2] }, func(c *ProfileChunk) { c.NativeCapabilities[2] = c.NativeCapabilities[1] }, func(c *ProfileChunk) { c.Samples[0].Native.Task.Generation = 0 }, func(c *ProfileChunk) { c.Samples[0].Native.Task.BootID = "other" }, func(c *ProfileChunk) { c.Samples[0].Native.Period = 0 }, func(c *ProfileChunk) { c.Samples[0].Native.RequestedHz = 100 }, func(c *ProfileChunk) { c.Samples[0].Native.ThrottleReason = "throttled" }, func(c *ProfileChunk) { c.Frames[0].Offset = 4096 }, func(c *ProfileChunk) { c.Frames[0].Module = "/private/executable" }, func(c *ProfileChunk) {
		c.Frames[0].Module = strings.Repeat("a", 64)
		c.Frames[0].Function = "private/source.go"
	}, func(c *ProfileChunk) {
		c.Frames[0].Module = strings.Repeat("a", 64)
		c.Frames[0].Artifact = "private/source.map"
	}, func(c *ProfileChunk) { c.Method = "native_offcpu"; c.Units = "nanoseconds" }, func(c *ProfileChunk) {
		k := c.Samples[0].Native.Task
		c.Intervals = []ProfileInterval{{NativeTask: &k, Thread: 8, Unit: "nanoseconds", Kind: "unknown_offcpu", Reason: "records_lost", Correction: true}}
	}}
	for i, mutate := range cases {
		c := nativeProfileFixture()
		mutate(&c)
		if validateNativeProfile(&c) == nil {
			t.Fatalf("unsafe native variant %d accepted", i)
		}
	}
	c := nativeProfileFixture()
	c.Frames[0] = ProfileFrame{Module: strings.Repeat("a", 64), Function: "safe::symbol@version", Reason: "artifact_unavailable"}
	if e := validateNativeProfile(&c); e != nil {
		t.Fatal("approved bounded native symbol rejected", e)
	}
}
func TestNativeProfileLegacyRuntimeMetadataAbsentRemainsValid(t *testing.T) {
	c := ProfileChunk{Method: "runtime_cpu", Units: "samples"}
	if e := validateNativeProfile(&c); e != nil {
		t.Fatal(e)
	}
	c.Sequence = 1
	if validateNativeProfile(&c) == nil {
		t.Fatal("orphan native generation metadata accepted")
	}
}
func TestNativeProfileLossTransitionsNeverBecomeDurationsOrCounts(t *testing.T) {
	c := nativeProfileFixture()
	c.NativeLoss = []ProfileNativeLoss{{At: 1, Reason: "throttled", ThrottleEventID: 7, ThrottleStreamID: 9}, {At: 2, Reason: "samples_lost", Count: 5}, {At: 3, Reason: "unthrottled", ThrottleEventID: 7, ThrottleStreamID: 9}}
	if e := validateNativeProfile(&c); e != nil {
		t.Fatal(e)
	}
	c.NativeLoss[0].Count = 1
	if validateNativeProfile(&c) == nil {
		t.Fatal("throttle transition fabricated lost sample count")
	}
	c.NativeLoss[0].Count = 0
	c.NativeLoss[1].ThrottleStreamID = 9
	if validateNativeProfile(&c) == nil {
		t.Fatal("loss counter borrowed throttle stream identity")
	}
	c.NativeLoss = make([]ProfileNativeLoss, 257)
	for i := range c.NativeLoss {
		c.NativeLoss[i] = ProfileNativeLoss{Reason: "records_lost", Count: 1}
	}
	if validateNativeProfile(&c) == nil {
		t.Fatal("unbounded native loss metadata accepted")
	}
}
func TestNativeProfileDecimalAliasesAndMissingZeroFieldsReject(t *testing.T) {
	c := nativeProfileFixture()
	c.NativeLoss = []ProfileNativeLoss{{At: 0, CPU: 0, Count: 0, Reason: "throttled", ThrottleEventID: 7, ThrottleStreamID: 9}}
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	var positive ProfileChunk
	if e = StrictJSON(raw, &positive); e != nil {
		t.Fatal("canonical native baseline failed", e)
	}
	cases := [][2]string{{`"pid_namespace":"1"`, `"pid_namespace":"01"`}, {`"generation":"1"`, `"generation":"01"`}, {`"period":"9007199254740993"`, `"period":"09007199254740993"`}, {`"sequence":"1"`, `"sequence":"01"`}, {`"count":"1"`, `"count":"01"`}, {`"thread":"8"`, `"thread":"08"`}, {`"count":"0"`, `"count":"00"`}, {`"throttle_event_id":"7"`, `"throttle_event_id":"07"`}, {`"at_ns":"0",`, ``}, {`"cpu":0,`, ``}, {`"count":"0",`, ``}}
	for i, pair := range cases {
		changed := strings.Replace(string(raw), pair[0], pair[1], 1)
		if changed == string(raw) {
			t.Fatalf("native alias fixture %d did not alter input", i)
		}
		var value ProfileChunk
		if StrictJSON([]byte(changed), &value) == nil {
			t.Fatalf("native decimal alias/missing zero field %d accepted", i)
		}
	}
}
