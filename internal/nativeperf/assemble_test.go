// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"encoding/json"
	"soundpost/internal/model"
	"strings"
	"testing"
)

func assemblyTask() (ClockDomain, TaskKey) {
	d := ClockDomain{HostID: "host", BootID: "boot"}
	return d, TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}
}
func assemblyInterval(d ClockDomain, k TaskKey, start, end model.MonoNano, kind IntervalKind) Interval {
	return Interval{Domain: d, Task: k, Start: start, End: end, Kind: kind, Measure: Measure{UnitNanoseconds, model.Uint64(end - start)}, MissingCallchain: ReasonMissingSwitchCallchain}
}

// Removing replacement-before-aggregation would count invalidated blocked mass.
func TestAssembleCorrectionsUnionSplitNonadditive(t *testing.T) {
	d, k := assemblyTask()
	other := k
	other.TID = 9
	in := []Interval{assemblyInterval(d, k, 0, 100, IntervalBlocked), assemblyInterval(d, other, 0, 100, IntervalRunnable), {Domain: d, Task: k, Start: 20, End: 50, Kind: IntervalUnknown, Measure: Measure{UnitNanoseconds, 30}, Reason: ReasonLoss, Correction: true}, {Domain: d, Task: k, Start: 40, End: 80, Kind: IntervalUnknown, Measure: Measure{UnitNanoseconds, 40}, Reason: ReasonLoss, Correction: true}, {Domain: d, Start: 90, End: 100, Kind: IntervalUnknown, Measure: Measure{UnitNanoseconds, 10}, Reason: ReasonClock, Correction: true}}
	out, err := replaceSchedulerCoverage(in, d)
	if err != nil {
		t.Fatal(err)
	}
	var blocked, runnable, correction uint64
	for _, i := range out {
		if i.Correction {
			correction += uint64(i.Measure.Value)
			continue
		}
		if i.Kind == IntervalBlocked {
			blocked += uint64(i.Measure.Value)
		}
		if i.Kind == IntervalRunnable {
			runnable += uint64(i.Measure.Value)
		}
	}
	if blocked != 30 || runnable != 90 || correction != 70 {
		t.Fatalf("surviving mass blocked=%d runnable=%d coverage=%d", blocked, runnable, correction)
	}
	if in[0].Start != 0 || in[0].End != 100 {
		t.Fatal("mutated caller evidence")
	}
}
func TestAssembleRejectsForeignCorrectionDomain(t *testing.T) {
	d, k := assemblyTask()
	i := assemblyInterval(d, k, 0, 10, IntervalBlocked)
	foreign := d
	foreign.BootID = "other"
	_, err := replaceSchedulerCoverage([]Interval{i, {Domain: foreign, Start: 0, End: 10, Kind: IntervalUnknown, Measure: Measure{UnitNanoseconds, 10}, Reason: ReasonLoss, Correction: true}}, d)
	if err == nil {
		t.Fatal("foreign clock accepted")
	}
}
func TestAssemblePreservesNativePeriodWithoutDoubleCounting(t *testing.T) {
	d, k := assemblyTask()
	sample := SanitizedEvent{Kind: EventCPU, Domain: d, Task: k, Sequence: 1, Time: 10, CPUEvent: &CPUSample{IP: 4096, Callchain: []CallchainEntry{{IP: 4096}}, Method: MethodSoftwareCPUClock, Unit: UnitCPUClockNanoseconds, RequestedHz: 99, Period: 901, Truncated: ReasonTruncated}}
	cap := assemblyCapability()
	limits := assemblyLimits(d)
	c, err := AssembleProfile(context.Background(), []SanitizedEvent{sample}, []Interval{{Domain: d, Task: k, Kind: IntervalCPU, Start: 10, End: 10, Measure: Measure{UnitNativeSamples, 1}}}, cap, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Samples) != 1 || c.Samples[0].Count != 1 || c.Samples[0].Native == nil || c.Samples[0].Native.Period != 901 || c.Samples[0].Native.Unit != "cpu_clock_nanoseconds" || len(c.Intervals) != 0 {
		t.Fatalf("lost/confounded native evidence: %+v", c)
	}
	if len(c.Frames) == 0 || len(c.Stacks) == 0 || len(c.Stacks[0].Frames) == 0 {
		t.Fatal("missing safe unresolved stack")
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "4096") {
		t.Fatal("raw instruction address exported")
	}
	if _, err = AssembleProfile(context.Background(), []SanitizedEvent{sample, sample}, nil, cap, limits); err == nil {
		t.Fatal("duplicate source sequence admitted")
	}
}
func assemblyCapability() Capabilities {
	return Capabilities{CPU: Supported, OffCPU: Denied, RunqueueSplit: Denied, Permissions: Permissions{CPUEventOpen: Supported, SchedulerEventOpen: Denied}, FrameCoverage: Coverage{Reasons: []Reason{ReasonUnmeasured}}, ThreadCoverage: Coverage{Reasons: []Reason{ReasonUnmeasured}}}
}
func assemblyLimits(d ClockDomain) ProfileLimits {
	return ProfileLimits{Profile: model.ID{1}, Process: model.ID{2}, Capability: model.ID{3}, Domain: d, PolicyRevision: 1, Sequence: 1, Start: 1, End: 1000, Clock: model.TraceClock{Wall: 1, Domain: model.ClockDomain{Host: model.ID{4}, Boot: model.ID{5}, Runtime: model.ID{6}}}, MaxBytes: 8 << 20, MaxSamples: 1024, MaxIntervals: 1024, MaxFrames: 4096, MaxStacks: 4096}
}
func TestAssembleBoundsOutputRatherThanDroppingEvidence(t *testing.T) {
	d, k := assemblyTask()
	l := assemblyLimits(d)
	l.MaxIntervals = 1
	cap := assemblyCapability()
	cap.OffCPU = Supported
	_, err := AssembleProfile(context.Background(), nil, []Interval{assemblyInterval(d, k, 0, 10, IntervalBlocked), assemblyInterval(d, k, 20, 30, IntervalRunnable)}, cap, l)
	if err == nil {
		t.Fatal("output budget silently truncated")
	}
}

func TestAssembleNeverResolvesDelayedIPAgainstCurrentSnapshot(t *testing.T) {
	d, k := assemblyTask()
	l := assemblyLimits(d)
	l.Mappings = []MappingTable{{process: ProcessKey{BootID: k.BootID, PIDNamespace: k.PIDNamespace, TGID: k.TGID, ProcessStart: k.ProcessStart, Generation: k.Generation}, entries: []mappingEntry{{start: 4096, end: 8192, offset: 16384, module: SafeModule{ID: strings.Repeat("a", 64), BuildID: "aabb"}}}}}
	sample := SanitizedEvent{Kind: EventCPU, Domain: d, Task: k, Sequence: 1, Time: 10, CPUEvent: &CPUSample{IP: 4096, Callchain: []CallchainEntry{{IP: 4096}}, Method: MethodSoftwareCPUClock, Unit: UnitCPUClockNanoseconds, RequestedHz: 99, Period: 901}}
	c, e := AssembleProfile(context.Background(), []SanitizedEvent{sample}, nil, assemblyCapability(), l)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Frames) == 0 || c.Frames[0].Module != "" || c.Frames[0].Offset != 0 || c.Frames[0].Reason != "frame_unresolved" {
		t.Fatal("current mapping snapshot fabricated historical address attribution")
	}
}
func TestAssembleSplitChunksRetainReferencesAndSingleLoss(t *testing.T) {
	d, k := assemblyTask()
	events := make([]SanitizedEvent, 0, 128)
	chain := make([]CallchainEntry, 128)
	for i := range chain {
		chain[i] = CallchainEntry{IP: model.Uint64(4096 + i*8)}
	}
	for i := range 128 {
		events = append(events, SanitizedEvent{Kind: EventCPU, Domain: d, Task: k, Sequence: model.Uint64(i + 1), Time: model.MonoNano(i + 1), CPUEvent: &CPUSample{IP: 4096, Callchain: chain, Method: MethodSoftwareCPUClock, Unit: UnitCPUClockNanoseconds, RequestedHz: 99, Period: model.Uint64(i + 1)}})
	}
	l := assemblyLimits(d)
	l.Complete = true
	c, e := AssembleProfile(context.Background(), events, nil, assemblyCapability(), l)
	if e != nil {
		t.Fatal(e)
	}
	c.Loss = 7
	chunks, e := splitProfile(c)
	if e != nil || len(chunks) < 2 {
		t.Fatalf("bounded chunks missing: %v", e)
	}
	var samples int
	var loss uint64
	for i, chunk := range chunks {
		samples += len(chunk.Samples)
		loss += uint64(chunk.Loss)
		if chunk.Sequence != model.Uint64(i+1) || chunk.Complete != (i == len(chunks)-1) {
			t.Fatal("missing chunk indistinguishable from complete capture")
		}
		for _, s := range chunk.Samples {
			if int(s.Stack) >= len(chunk.Stacks) {
				t.Fatal("invalid stack reference")
			}
			for _, f := range chunk.Stacks[s.Stack].Frames {
				if int(f) >= len(chunk.Frames) {
					t.Fatal("invalid frame reference")
				}
			}
		}
	}
	if samples != 128 || loss != 7 {
		t.Fatal("chunking dropped or duplicated evidence")
	}
}
func TestAssembleStandaloneThrottleAndSampleLossRemainTyped(t *testing.T) {
	d, k := assemblyTask()
	events := []SanitizedEvent{{Kind: EventCPU, Domain: d, Task: k, Sequence: 1, Time: 10, CPUEvent: &CPUSample{IP: 4096, Callchain: []CallchainEntry{{IP: 4096}}, Method: MethodSoftwareCPUClock, Unit: UnitCPUClockNanoseconds, RequestedHz: 99, Period: 901}}, {Kind: EventLoss, Domain: d, Sequence: 2, Time: 11, Loss: &LossEvent{Reason: ReasonThrottle, Throttle: &ThrottleEvidence{Reason: ReasonThrottle, EventID: 7, StreamID: 9}}}, {Kind: EventLoss, Domain: d, Sequence: 3, Time: 12, Loss: &LossEvent{Reason: ReasonSampleLost, Count: 5}}, {Kind: EventLoss, Domain: d, Sequence: 4, Time: 13, Loss: &LossEvent{Reason: ReasonUnthrottle, Throttle: &ThrottleEvidence{Reason: ReasonUnthrottle, EventID: 7, StreamID: 9}}}}
	c, e := AssembleProfile(context.Background(), events, nil, assemblyCapability(), assemblyLimits(d))
	if e != nil {
		t.Fatal(e)
	}
	if c.Loss != 5 || len(c.NativeLoss) != 3 || c.NativeLoss[0].Count != 0 || c.NativeLoss[0].ThrottleEventID != 7 || c.NativeLoss[1].Reason != "samples_lost" || c.NativeLoss[2].Reason != "unthrottled" || len(c.Intervals) != 0 {
		t.Fatal("standalone throttle/loss erased or invented duration")
	}
	chunks, e := splitProfile(c)
	if e != nil {
		t.Fatal(e)
	}
	var markers int
	var lost uint64
	for _, part := range chunks {
		markers += len(part.NativeLoss)
		lost += uint64(part.Loss)
	}
	if markers != 3 || lost != 5 {
		t.Fatal("loss transitions duplicated or dropped by chunking")
	}
}
