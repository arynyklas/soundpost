// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
// This independently authored synthetic oracle does not qualify kernel accuracy.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
	"math/rand/v2"
	"os"
	"reflect"
)

type summary struct {
	Seed                                                                                                 int64 `json:"seed"`
	Events                                                                                               int   `json:"events"`
	BlockedIntervals, RunnableIntervals, UnknownIntervals, CensoredIntervals, Corrections, NativeSamples uint64
	EmittedUnknownIntervals, EmittedCensoredIntervals                                                    uint64
	BlockedNS, RunnableNS, UnknownNS, CensoredNS                                                         uint64
	ReservedBytes                                                                                        uint64 `json:"reserved_bytes"`
	MaxHeapEvents, MaxTaskStates                                                                         int
	Qualification                                                                                        string `json:"qualification"`
}
type expectedInterval struct {
	kind       nativeperf.IntervalKind
	start, end uint64
	correction bool
}

func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
func main() {
	seed := flag.Int64("seed", 451, "deterministic event permutation seed")
	count := flag.Int("events", 100000, "exact sanitized event count")
	window := flag.Int("reorder-ms", 100, "fixed acquisition reorder window")
	loss := flag.Bool("inject-loss", false, "inject dropped wake evidence and explicit record-loss events")
	flag.Parse()
	if *count < 1 || *count > 1000000 || *window != 100 {
		fail(fmt.Errorf("events must be 1..1000000 and reorder-ms must be 100"))
	}
	domain := nativeperf.ClockDomain{HostID: "fixture-host", BootID: "fixture-boot"}
	key := nativeperf.TaskKey{BootID: domain.BootID, PIDNamespace: 1, TGID: 1, TID: 2, ProcessStart: 1, Generation: 1}
	newCorrelator := func() *nativeperf.Correlator {
		c := nativeperf.NewCorrelator(nativeperf.DefaultConfig(1))
		if err := c.Configure(domain, []uint32{0, 1}, 4<<20); err != nil {
			fail(err)
		}
		return c
	}
	ordered, reordered := newCorrelator(), newCorrelator()
	random := rand.New(rand.NewPCG(uint64(*seed), 451))
	actual := summary{Seed: *seed, Events: *count, ReservedBytes: 4 << 20, Qualification: "synthetic_algorithm_only_not_native_kernel_accuracy"}
	reference := actual
	proofs := make(map[*nativeperf.Correlator]uint64, 2)
	sequence := uint64(0)
	var last uint64
	event := func(kind nativeperf.EventKind, at uint64, cpu uint32) nativeperf.SanitizedEvent {
		sequence++
		return nativeperf.SanitizedEvent{Kind: kind, Time: model.MonoNano(at), CPU: cpu, Sequence: model.Uint64(sequence), Domain: domain}
	}
	record := func(s *summary, is []nativeperf.Interval) {
		for _, i := range is {
			switch {
			case i.Correction:
				s.Corrections++
				s.BlockedIntervals = 0
				s.RunnableIntervals = 0
				s.UnknownIntervals = 0
				s.CensoredIntervals = 0
				s.BlockedNS = 0
				s.RunnableNS = 0
				s.UnknownNS = 0
				s.CensoredNS = 0
			case i.Kind == nativeperf.IntervalBlocked:
				s.BlockedIntervals++
				s.BlockedNS += uint64(i.Measure.Value)
			case i.Kind == nativeperf.IntervalRunnable:
				s.RunnableIntervals++
				s.RunnableNS += uint64(i.Measure.Value)
			case i.Kind == nativeperf.IntervalUnknown:
				s.UnknownIntervals++
				s.EmittedUnknownIntervals++
				s.UnknownNS += uint64(i.Measure.Value)
			case i.Kind == nativeperf.IntervalCensored:
				s.CensoredIntervals++
				s.EmittedCensoredIntervals++
				s.CensoredNS += uint64(i.Measure.Value)
			case i.Kind == nativeperf.IntervalCPU:
				s.NativeSamples++
			default:
				fail(fmt.Errorf("unexpected interval kind"))
			}
		}
	}
	check := func(got []nativeperf.Interval, want []expectedInterval) {
		if len(got) != len(want) {
			fail(fmt.Errorf("oracle interval count: got %d want %d", len(got), len(want)))
		}
		for n, i := range got {
			w := want[n]
			if err := i.Validate(); err != nil {
				fail(err)
			}
			if i.Kind != w.kind || uint64(i.Start) != w.start || uint64(i.End) != w.end || i.Correction != w.correction {
				fail(fmt.Errorf("independent oracle mismatch: got %+v want %+v", i, w))
			}
			if !i.Correction && i.Task != key {
				fail(fmt.Errorf("identity mismatch"))
			}
		}
	}
	drain := func(c *nativeperf.Correlator, end uint64, final bool) []nativeperf.Interval {
		through := end + 100000000
		if final {
			through = end
		}
		if proofs[c] > through {
			through = proofs[c]
		}
		for _, cpu := range []uint32{0, 1} {
			if err := c.ReportProgress(cpu, model.MonoNano(through)); err != nil {
				fail(err)
			}
		}
		proofs[c] = through
		var out []nativeperf.Interval
		var err error
		if final {
			out, err = c.Finalize(model.MonoNano(end))
		} else {
			out, err = c.Advance(model.MonoNano(end))
		}
		if err != nil {
			fail(err)
		}
		s := c.Stats()
		if s.PeakHeapEvents > s.MaxHeapEvents || s.PeakTaskStates > s.MaxTaskStates {
			fail(fmt.Errorf("peak resource bound violated"))
		}
		if s.PeakHeapEvents > actual.MaxHeapEvents {
			actual.MaxHeapEvents = s.PeakHeapEvents
		}
		if s.PeakTaskStates > actual.MaxTaskStates {
			actual.MaxTaskStates = s.PeakTaskStates
		}
		return out
	}
	feed := func(c *nativeperf.Correlator, events []nativeperf.SanitizedEvent) {
		for _, e := range events {
			out, err := c.Consume(e)
			if err != nil || len(out) != 0 {
				fail(fmt.Errorf("unexpected intake output/error: %v %+v", err, out))
			}
			s := c.Stats()
			if s.ReservedBytes > 4<<20 || s.HeapEvents > s.MaxHeapEvents || s.TaskStates > s.MaxTaskStates {
				fail(fmt.Errorf("resource bound violated"))
			}
			if s.HeapEvents > actual.MaxHeapEvents {
				actual.MaxHeapEvents = s.HeapEvents
			}
			if s.TaskStates > actual.MaxTaskStates {
				actual.MaxTaskStates = s.TaskStates
			}
		}
	}
	// The reference is specified by generated workload phases, not by replaying
	// scheduler transitions or calling the correlator to derive expected durations.
	for cycle := range *count / 3 {
		start := uint64(cycle) * 250000000
		wake := start + 40000000
		end := start + 55000000
		last = end
		mode := cycle % 3
		explicitLoss := *loss && cycle%17 == 0
		missingWake := *loss && cycle%19 == 0 && !explicitLoss
		out := event(nativeperf.EventSwitch, start, 0)
		state := uint64(1)
		if mode == 0 {
			state = 0
		}
		out.Switch = &nativeperf.SchedulerSwitch{Previous: &key, PreviousState: model.Uint64(state), MissingCallchain: nativeperf.ReasonMissingSwitchCallchain}
		middle := event(nativeperf.EventWakeup, wake, 1)
		middle.Task = key
		middle.Wakeup = &nativeperf.SchedulerWakeup{Target: key, TargetCPU: 1}
		in := event(nativeperf.EventSwitch, end, 1)
		in.Switch = &nativeperf.SchedulerSwitch{Next: &key}
		var want []expectedInterval
		switch {
		case explicitLoss:
			middle.Kind = nativeperf.EventLoss
			middle.Task = nativeperf.TaskKey{}
			middle.Wakeup = nil
			middle.Loss = &nativeperf.LossEvent{Count: 1, Reason: nativeperf.ReasonLoss}
			want = []expectedInterval{{nativeperf.IntervalUnknown, 0, wake, true}, {nativeperf.IntervalUnknown, 0, end, true}}
			reference.Corrections += 2
			reference.BlockedIntervals = 0
			reference.RunnableIntervals = 0
			reference.UnknownIntervals = 0
			reference.CensoredIntervals = 0
			reference.BlockedNS = 0
			reference.RunnableNS = 0
			reference.UnknownNS = 0
			reference.CensoredNS = 0
		case missingWake && mode != 0:
			middle.Kind = nativeperf.EventCPU
			middle.Wakeup = nil
			middle.CPUEvent = &nativeperf.CPUSample{IP: 4096, Callchain: []nativeperf.CallchainEntry{{IP: 4096}}, Method: nativeperf.MethodSoftwareCPUClock, Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: 100}
			want = []expectedInterval{{nativeperf.IntervalCPU, wake, wake, false}, {nativeperf.IntervalUnknown, start, end, false}}
			reference.NativeSamples++
			reference.UnknownIntervals++
			reference.EmittedUnknownIntervals++
			reference.UnknownNS += 55000000
		case mode == 0:
			want = []expectedInterval{{nativeperf.IntervalRunnable, start, end, false}}
			reference.RunnableIntervals++
			reference.RunnableNS += 55000000
		default:
			want = []expectedInterval{{nativeperf.IntervalBlocked, start, wake, false}, {nativeperf.IntervalRunnable, wake, end, false}}
			reference.BlockedIntervals++
			reference.BlockedNS += 40000000
			reference.RunnableIntervals++
			reference.RunnableNS += 15000000
		}
		events := []nativeperf.SanitizedEvent{out, middle, in}
		feed(ordered, events)
		permutation := append([]nativeperf.SanitizedEvent(nil), events...)
		random.Shuffle(len(permutation), func(i, j int) { permutation[i], permutation[j] = permutation[j], permutation[i] })
		feed(reordered, permutation)
		a, b := drain(ordered, end, false), drain(reordered, end, false)
		if !reflect.DeepEqual(a, b) {
			fail(fmt.Errorf("ordered/reordered output differs at cycle %d", cycle))
		}
		check(b, want)
		record(&actual, b)
	}
	// Exact remainder is an open sleeping interval (and, for remainder 2, its wake).
	// Finalization must censor the whole wait, never manufacture a switch-in.
	remainder := *count % 3
	if remainder != 0 {
		start := uint64(*count/3) * 250000000
		last = start + 55000000
		out := event(nativeperf.EventSwitch, start, 0)
		out.Switch = &nativeperf.SchedulerSwitch{Previous: &key, PreviousState: 1, MissingCallchain: nativeperf.ReasonMissingSwitchCallchain}
		events := []nativeperf.SanitizedEvent{out}
		if remainder == 2 {
			wake := event(nativeperf.EventWakeup, start+40000000, 1)
			wake.Task = key
			wake.Wakeup = &nativeperf.SchedulerWakeup{Target: key, TargetCPU: 1}
			events = append(events, wake)
		}
		feed(ordered, events)
		feed(reordered, events)
		reference.CensoredIntervals++
		reference.EmittedCensoredIntervals++
		reference.CensoredNS += 55000000
	}
	a, b := drain(ordered, last, true), drain(reordered, last, true)
	if !reflect.DeepEqual(a, b) {
		fail(fmt.Errorf("final ordered/reordered mismatch"))
	}
	if remainder != 0 {
		check(b, []expectedInterval{{nativeperf.IntervalCensored, last - 55000000, last, false}})
	} else if len(b) != 0 {
		fail(fmt.Errorf("unexpected final interval"))
	}
	record(&actual, b)
	reference.MaxHeapEvents = actual.MaxHeapEvents
	reference.MaxTaskStates = actual.MaxTaskStates
	if !reflect.DeepEqual(actual, reference) {
		fail(fmt.Errorf("independent aggregate oracle mismatch: got %+v want %+v", actual, reference))
	}
	// Independent closed-form checkpoint for the requested public fixture: 33,333
	// three-record cycles, loss every seventeenth cycle, missing non-runnable wake
	// every nineteenth non-loss cycle, and one final censored switch-out. The last
	// loss is cycle 33,320, so only the following twelve complete cycles survive
	// the intentionally broad historical corrections.
	if *seed == 451 && *count == 100000 && *loss {
		if actual.BlockedIntervals != 7 || actual.RunnableIntervals != 11 || actual.UnknownIntervals != 1 || actual.CensoredIntervals != 1 || actual.Corrections != 3922 || actual.NativeSamples != 1101 || actual.EmittedUnknownIntervals != 1101 || actual.EmittedCensoredIntervals != 1 || actual.BlockedNS != 280000000 || actual.RunnableNS != 325000000 || actual.UnknownNS != 55000000 || actual.CensoredNS != 55000000 || actual.MaxHeapEvents != 3 || actual.MaxTaskStates != 1 {
			fail(fmt.Errorf("seed451 closed-form checkpoint mismatch: %+v", actual))
		}
	}
	if sequence != uint64(*count) {
		fail(fmt.Errorf("event count mismatch"))
	}
	if err := json.NewEncoder(os.Stdout).Encode(actual); err != nil {
		fail(err)
	}
}
