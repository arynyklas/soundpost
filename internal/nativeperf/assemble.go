// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math"
	"sort"
	"soundpost/internal/model"
)

// WorkingReservation is an exclusive portion of the acquisition's aggregate
// budget, not an additional pool. Production factories reserve before allocation.
type WorkingReservation interface {
	Bytes() uint64
	Close() error
}
type ProfileLimits struct {
	Profile, Process, Capability                   model.ID
	Domain                                         ClockDomain
	PolicyRevision                                 model.Revision
	Sequence                                       uint64
	Start, End                                     model.UnixNano
	Clock                                          model.TraceClock
	Complete                                       bool
	MaxBytes                                       uint64
	MaxSamples, MaxIntervals, MaxFrames, MaxStacks uint32
	Mappings                                       []MappingTable
}

func (l ProfileLimits) validate() error {
	if l.Profile == (model.ID{}) || l.Process == (model.ID{}) || l.Capability == (model.ID{}) || !l.Domain.valid() || l.Clock.Domain.Host == (model.ID{}) || l.Clock.Domain.Boot == (model.ID{}) || l.Clock.Domain.Runtime == (model.ID{}) || l.PolicyRevision == 0 || l.Sequence == 0 || l.End < l.Start || l.MaxBytes == 0 || l.MaxBytes > 8<<20 || l.MaxSamples == 0 || l.MaxSamples > 8192 || l.MaxIntervals == 0 || l.MaxIntervals > 8192 || l.MaxFrames == 0 || l.MaxFrames > 4096 || l.MaxStacks == 0 || l.MaxStacks > 4096 || len(l.Mappings) > 64 {
		return ErrInvalid
	}
	return nil
}
func nativeTask(k TaskKey) model.ProfileNativeTask {
	return model.ProfileNativeTask{BootID: k.BootID, PIDNamespace: k.PIDNamespace, TGID: k.TGID, TID: k.TID, ProcessStart: k.ProcessStart, Generation: k.Generation}
}
func nativeCapabilityIDs(primary model.ID) []model.ID {
	ids := []model.ID{primary}
	for _, method := range []string{"native_offcpu", "native_runqueue_split"} {
		h := sha256.New()
		h.Write([]byte("soundpost-native-capability-v1\x00"))
		h.Write(primary[:])
		h.Write([]byte(method))
		var id model.ID
		copy(id[:], h.Sum(nil))
		ids = append(ids, id)
	}
	return ids
}

// replaceSchedulerCoverage consumes NONADDITIVE corrections before aggregation.
// Global and task-specific coverage is unioned; a global gap dominates task gaps.
// Corrections returned here are coverage markers only, never measured mass.
func replaceSchedulerCoverage(input []Interval, domain ClockDomain) ([]Interval, error) {
	if len(input) > 8192 {
		return nil, ErrResourceBudget
	}
	gaps := map[TaskKey][]Interval{}
	for _, i := range input {
		if i.Validate() != nil || i.Domain != domain {
			return nil, ErrInvalid
		}
		if i.Correction && i.End > i.Start {
			gaps[i.Task] = append(gaps[i.Task], i)
		}
	}
	union := func(in []Interval) []Interval {
		sort.Slice(in, func(i, j int) bool {
			if in[i].Start != in[j].Start {
				return in[i].Start < in[j].Start
			}
			return in[i].End < in[j].End
		})
		var out []Interval
		for _, g := range in {
			if len(out) > 0 && g.Start <= out[len(out)-1].End {
				p := &out[len(out)-1]
				if g.End > p.End {
					p.End = g.End
					p.Measure.Value = model.Uint64(p.End - p.Start)
				}
				if p.Reason != g.Reason {
					p.Reason = ReasonLoss
				}
			} else {
				out = append(out, g)
			}
		}
		return out
	}
	for key, gs := range gaps {
		gaps[key] = union(gs)
	}
	// Subtract global gaps from task-specific correction markers too, so the
	// exported coverage does not redundantly overlap at the same task identity.
	global := gaps[TaskKey{}]
	subtract := func(i Interval, gs []Interval) []Interval {
		var out []Interval
		at := i.Start
		for _, g := range gs {
			if g.End <= at || g.Start >= i.End {
				continue
			}
			if g.Start > at {
				p := i
				p.Start = at
				p.End = g.Start
				p.Measure.Value = model.Uint64(p.End - p.Start)
				out = append(out, p)
			}
			if g.End > at {
				at = g.End
			}
			if at >= i.End {
				break
			}
		}
		if at < i.End {
			p := i
			p.Start = at
			p.Measure.Value = model.Uint64(p.End - p.Start)
			out = append(out, p)
		}
		return out
	}
	var out []Interval
	for _, i := range input {
		if i.Correction {
			continue
		}
		if i.Kind == IntervalCPU {
			out = append(out, i)
			continue
		}
		gs := append([]Interval(nil), global...)
		gs = append(gs, gaps[i.Task]...)
		gs = union(gs)
		pieces := subtract(i, gs)
		for _, p := range pieces {
			p.SwitchOutCallchain = append([]CallchainEntry(nil), p.SwitchOutCallchain...)
			out = append(out, p)
		}
		if len(out) > 8192 {
			return nil, ErrResourceBudget
		}
	}
	out = append(out, global...)
	keys := make([]TaskKey, 0, len(gaps))
	for key := range gaps {
		if key != (TaskKey{}) {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.TGID != b.TGID {
			return a.TGID < b.TGID
		}
		if a.TID != b.TID {
			return a.TID < b.TID
		}
		if a.Generation != b.Generation {
			return a.Generation < b.Generation
		}
		if a.PIDNamespace != b.PIDNamespace {
			return a.PIDNamespace < b.PIDNamespace
		}
		return a.ProcessStart < b.ProcessStart
	})
	for _, key := range keys {
		for _, g := range gaps[key] {
			out = append(out, subtract(g, global)...)
		}
		if len(out) > 8192 {
			return nil, ErrResourceBudget
		}
	}
	return out, nil
}

// AssembleProfile accepts only genuine sanitized CPU observations and finalized
// scheduler evidence. Native IntervalCPU is deliberately not a second sample.
// Historical VA ownership is not proved by a current proc snapshot. Until fixed
// map-mutation controls are available this integration emits unresolved frames.
// No ambient artifact lookup, host symbols or raw address fallback is allowed.
func AssembleProfile(ctx context.Context, events []SanitizedEvent, intervals []Interval, capability Capabilities, l ProfileLimits) (model.ProfileChunk, error) {
	if err := l.validate(); err != nil {
		return model.ProfileChunk{}, err
	}
	if capability.Validate() != nil {
		return model.ProfileChunk{}, ErrInvalid
	}
	if len(events) > 8192 || len(intervals) > 8192 {
		return model.ProfileChunk{}, ErrResourceBudget
	}
	c := model.ProfileChunk{Profile: l.Profile, Process: l.Process, Capability: l.Capability, Method: "native_cpu", Units: "samples", Start: l.Start, End: l.End, Clock: l.Clock, NativeDomain: &model.ProfileNativeDomain{HostID: l.Domain.HostID, BootID: l.Domain.BootID}, PolicyRevision: l.PolicyRevision, Sequence: model.Uint64(l.Sequence), Complete: l.Complete, Frames: []model.ProfileFrame{}, Stacks: []model.ProfileStack{}, Samples: []model.ProfileSample{}, Intervals: []model.ProfileInterval{}}
	c.NativeCapabilities = nativeCapabilityIDs(l.Capability)
	frames := map[model.ProfileFrame]uint32{}
	stacks := map[string]uint32{}
	charged := uint64(4096) + uint64(len(events)+len(intervals))*(32<<10)
	charge := func(n uint64) error {
		if n > l.MaxBytes-charged {
			return ErrResourceBudget
		}
		charged += n
		return nil
	}
	if charged > l.MaxBytes {
		return model.ProfileChunk{}, ErrResourceBudget
	}
	intern := func(resolved []ResolvedFrame) (uint32, error) {
		if len(resolved) == 0 {
			resolved = []ResolvedFrame{{Reason: FrameMissing}}
		}
		if len(resolved) > 128 {
			return 0, ErrResourceBudget
		}
		refs := make([]uint32, 0, len(resolved))
		key := make([]byte, 4*len(resolved))
		for i, f := range resolved {
			row := model.ProfileFrame{Function: f.Symbol, Reason: string(f.Reason)}
			if f.Module != nil {
				row.Module = f.Module.ID
				row.Offset = f.Offset
			}
			index, exists := frames[row]
			if !exists {
				if uint32(len(c.Frames)) >= l.MaxFrames {
					return 0, ErrResourceBudget
				}
				if err := charge(uint64(256 + len(row.Module) + len(row.Function) + len(row.Reason))); err != nil {
					return 0, err
				}
				index = uint32(len(c.Frames))
				frames[row] = index
				c.Frames = append(c.Frames, row)
			}
			refs = append(refs, index)
			binary.LittleEndian.PutUint32(key[i*4:], index)
		}
		text := string(key)
		if index, ok := stacks[text]; ok {
			return index, nil
		}
		if uint32(len(c.Stacks)) >= l.MaxStacks {
			return 0, ErrResourceBudget
		}
		if err := charge(uint64(128 + len(key)*4)); err != nil {
			return 0, err
		}
		index := uint32(len(c.Stacks))
		stacks[text] = index
		c.Stacks = append(c.Stacks, model.ProfileStack{Frames: refs})
		return index, nil
	}
	mapping := func(k TaskKey) MappingTable {
		p := ProcessKey{BootID: k.BootID, PIDNamespace: k.PIDNamespace, TGID: k.TGID, ProcessStart: k.ProcessStart, Generation: k.Generation}
		for _, m := range l.Mappings {
			if sameFrameProcess(k, m.process) {
				return MappingTable{process: p, policy: SymbolPolicy{FramePointersAbsent: m.policy.FramePointersAbsent}}
			}
		}
		return MappingTable{process: p}
	}
	sequences := map[uint64]bool{}
	for _, event := range events {
		if err := ctx.Err(); err != nil {
			return model.ProfileChunk{}, err
		}
		if event.Validate() != nil || event.Domain != l.Domain || sequences[uint64(event.Sequence)] {
			return model.ProfileChunk{}, ErrInvalid
		}
		sequences[uint64(event.Sequence)] = true
		switch event.Kind {
		case EventCPU:
			if capability.CPU != Supported || uint32(len(c.Samples)) >= l.MaxSamples {
				return model.ProfileChunk{}, ErrResourceBudget
			}
			observation, err := ResolveCPUObservation(ctx, event.Task, *event.CPUEvent, mapping(event.Task), nil)
			if err != nil {
				return model.ProfileChunk{}, err
			}
			stack, err := intern(observation.Frames)
			if err != nil {
				return model.ProfileChunk{}, err
			}
			if err = charge(1024); err != nil {
				return model.ProfileChunk{}, err
			}
			n := &model.ProfileNativeSample{Task: nativeTask(event.Task), Method: string(observation.Method), Unit: string(observation.Unit), RequestedHz: observation.RequestedHz, Period: observation.Period, Truncation: string(observation.AcquisitionCoverage), Coverage: string(observation.Coverage)}
			if observation.Throttle != nil {
				n.ThrottleReason = string(observation.Throttle.Reason)
				n.ThrottleEventID = observation.Throttle.EventID
				n.ThrottleStreamID = observation.Throttle.StreamID
			}
			c.Samples = append(c.Samples, model.ProfileSample{At: event.Time, Stack: stack, Count: 1, Thread: model.Uint64(event.Task.TID), Native: n})
			c.Truncated = c.Truncated || n.Truncation != "" || n.Coverage != ""
		case EventLoss:
			if c.Loss > math.MaxUint64-event.Loss.Count {
				return model.ProfileChunk{}, ErrInvalid
			}
			if len(c.NativeLoss) >= 256 {
				return model.ProfileChunk{}, ErrResourceBudget
			}
			if err := charge(512); err != nil {
				return model.ProfileChunk{}, err
			}
			evidence := model.ProfileNativeLoss{At: event.Time, CPU: event.CPU, Count: event.Loss.Count, Reason: string(event.Loss.Reason)}
			if event.Loss.Throttle != nil {
				evidence.ThrottleEventID = event.Loss.Throttle.EventID
				evidence.ThrottleStreamID = event.Loss.Throttle.StreamID
			}
			c.NativeLoss = append(c.NativeLoss, evidence)
			c.Loss += event.Loss.Count
			c.Truncated = true
		case EventGeneration:
			c.Truncated = true
			c.Complete = false
		}
	}
	replaced, err := replaceSchedulerCoverage(intervals, l.Domain)
	if err != nil {
		return model.ProfileChunk{}, err
	}
	for _, i := range replaced {
		if err = ctx.Err(); err != nil {
			return model.ProfileChunk{}, err
		}
		if i.Correction {
			c.Complete = false
			c.Truncated = true
			continue
		}
		if i.Kind == IntervalCPU {
			continue
		}
		if capability.OffCPU != Supported {
			return model.ProfileChunk{}, ErrInvalid
		}
		if uint32(len(c.Intervals)) >= l.MaxIntervals {
			return model.ProfileChunk{}, ErrResourceBudget
		}
		addresses := make([]AddressFrame, 0, len(i.SwitchOutCallchain))
		mode := ContextUser
		for _, entry := range i.SwitchOutCallchain {
			if entry.Context != "" {
				mode = entry.Context
				continue
			}
			if mode == ContextUser {
				addresses = append(addresses, AddressFrame{Task: i.Task, IP: uint64(entry.IP)})
			}
		}
		resolved, e := ResolveFrames(ctx, addresses, mapping(i.Task), nil)
		if e != nil {
			return model.ProfileChunk{}, e
		}
		stack, e := intern(resolved)
		if e != nil {
			return model.ProfileChunk{}, e
		}
		if e = charge(1024); e != nil {
			return model.ProfileChunk{}, e
		}
		kind := "unknown_offcpu"
		switch i.Kind {
		case IntervalBlocked:
			kind = "blocked"
		case IntervalRunnable:
			kind = "runnable"
		}
		task := nativeTask(i.Task)
		reason := i.Reason
		if reason == "" && i.MissingCallchain != "" {
			reason = i.MissingCallchain
		}
		c.Intervals = append(c.Intervals, model.ProfileInterval{Start: i.Start, End: i.End, Stack: stack, Kind: kind, Thread: model.Uint64(i.Task.TID), Censored: i.Kind == IntervalCensored, NativeTask: &task, Unit: "nanoseconds", Reason: string(reason)})
	}
	if len(c.Samples) == 0 && len(c.Intervals) > 0 {
		c.Method = "native_offcpu"
		c.Units = "nanoseconds"
	}
	if len(c.Samples) == 0 && len(c.Intervals) == 0 {
		return model.ProfileChunk{}, ErrInvalid
	}
	encoded, e := json.Marshal(c)
	if e != nil {
		return model.ProfileChunk{}, e
	}
	if uint64(len(encoded)) > l.MaxBytes {
		return model.ProfileChunk{}, ErrResourceBudget
	}
	return c, nil
}
