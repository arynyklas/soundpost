// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"sort"
	"soundpost/internal/model"
)

type correlationProcess struct {
	namespace uint64
	tgid      uint32
}
type correlationProcessState struct {
	start      model.MonoNano
	generation uint64
	tasks      int
}

func correlationPID(k TaskKey) correlationProcess { return correlationProcess{k.PIDNamespace, k.TGID} }

type correlationTaskState struct {
	start, wake          model.MonoNano
	out, runnable, woken bool
	chain                []CallchainEntry
	missing              Reason
}

// CorrelationStats reports fixed resource reservations and bounded cardinalities,
// not a runtime RSS/overhead qualification. The reservation is conservative and
// includes one outstanding returned batch; the caller must drain/export outputs
// before retaining another, or separately reserve those retained bytes.
type CorrelationStats struct {
	ReservedBytes                                        uint64
	HeapEvents, TaskStates, MaxHeapEvents, MaxTaskStates int
	PeakHeapEvents, PeakTaskStates                       int
}

func (c *Correlator) Stats() CorrelationStats {
	if c == nil {
		return CorrelationStats{}
	}
	return CorrelationStats{ReservedBytes: c.reserved, HeapEvents: len(c.events), TaskStates: len(c.tasks), MaxHeapEvents: c.maxEvents, MaxTaskStates: c.maxTasks, PeakHeapEvents: c.peakHeap, PeakTaskStates: c.peakTasks}
}
func (c *Correlator) interval(key TaskKey, start, end model.MonoNano, kind IntervalKind, reason Reason, state *correlationTaskState) Interval {
	i := Interval{Task: key, Domain: c.domain, Start: start, End: end, Kind: kind, Reason: reason, Measure: Measure{Unit: UnitNanoseconds, Value: uint64(end - start)}}
	if state != nil {
		i.SwitchOutCallchain = append([]CallchainEntry(nil), state.chain...)
		i.MissingCallchain = state.missing
	}
	return i
}

// invalidate never edits a previously returned interval. Its domain-wide
// correction REPLACES completeness over [0,end), it is NOT additive elapsed time.
// An assembler must mark every overlapping scheduler interval unknown (including
// an interval straddling an edge) and union corrections, before presenting totals.
// Broad historical invalidation is deliberate: there is no unbounded event or
// emitted-interval history from which to prove a narrower affected region. CPU
// observations remain independently typed; this gap revokes scheduler coverage.
func (c *Correlator) invalidate(at model.MonoNano, reason Reason) []Interval {
	end := at
	if c.haveWatermark && c.watermark > end {
		end = c.watermark
	}
	if c.processed > end {
		end = c.processed
	}
	clear(c.tasks)
	clear(c.processes)
	return []Interval{{Domain: c.domain, Kind: IntervalUnknown, Start: 0, End: end, Measure: Measure{Unit: UnitNanoseconds, Value: uint64(end)}, Reason: reason, Correction: true}}
}
func (c *Correlator) sortedTasks() []TaskKey {
	keys := make([]TaskKey, 0, len(c.tasks))
	for k := range c.tasks {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.PIDNamespace != b.PIDNamespace {
			return a.PIDNamespace < b.PIDNamespace
		}
		if a.TGID != b.TGID {
			return a.TGID < b.TGID
		}
		if a.TID != b.TID {
			return a.TID < b.TID
		}
		if a.ProcessStart != b.ProcessStart {
			return a.ProcessStart < b.ProcessStart
		}
		return a.Generation < b.Generation
	})
	return keys
}
func (c *Correlator) identityConflict(key TaskKey) bool {
	process, ok := c.processes[correlationPID(key)]
	return ok && (process.start != key.ProcessStart || process.generation != key.Generation)
}
func (c *Correlator) apply(e SanitizedEvent) []Interval {
	switch e.Kind {
	case EventLoss:
		return c.invalidate(e.Time, e.Loss.Reason)
	case EventGeneration:
		return c.invalidate(e.Time, ReasonGeneration)
	case EventCPU:
		var out []Interval
		if c.identityConflict(e.Task) {
			out = c.invalidate(e.Time, ReasonGeneration)
		}
		return append(out, Interval{Kind: IntervalCPU, Task: e.Task, Domain: c.domain, Start: e.Time, End: e.Time, Measure: Measure{Unit: UnitNativeSamples, Value: 1}})
	case EventMapping:
		// Mapping cannot close/decorate a wait, but a new process identity revokes it.
		p := e.Mapping.Process
		if c.identityConflict(TaskKey{PIDNamespace: p.PIDNamespace, TGID: p.TGID, ProcessStart: p.ProcessStart, Generation: p.Generation}) {
			return c.invalidate(e.Time, ReasonGeneration)
		}
		return nil
	case EventWakeup:
		key := e.Wakeup.Target
		if c.identityConflict(key) {
			return c.invalidate(e.Time, ReasonGeneration)
		}
		state := c.tasks[key]
		if state == nil || !state.out || state.runnable || state.woken {
			return nil
		}
		state.wake = e.Time
		state.woken = true
		return nil
	case EventSwitch:
		s := e.Switch
		if s.Previous != nil && s.Next != nil && *s.Previous == *s.Next {
			return c.invalidate(e.Time, ReasonLoss)
		}
		for _, key := range []*TaskKey{s.Previous, s.Next} {
			if key != nil && c.identityConflict(*key) {
				return c.invalidate(e.Time, ReasonGeneration)
			}
		}
		if s.Previous != nil {
			if state := c.tasks[*s.Previous]; state != nil && state.out {
				return c.invalidate(e.Time, ReasonLoss)
			}
		}
		var out []Interval
		if s.Next != nil {
			key := *s.Next
			if state := c.tasks[key]; state != nil && state.out {
				if e.Time < state.start || state.woken && (state.wake < state.start || state.wake > e.Time) {
					return c.invalidate(e.Time, ReasonClock)
				}
				if state.runnable {
					out = append(out, c.interval(key, state.start, e.Time, IntervalRunnable, "", state))
				} else if state.woken {
					out = append(out, c.interval(key, state.start, state.wake, IntervalBlocked, "", state), c.interval(key, state.wake, e.Time, IntervalRunnable, "", state))
				} else {
					out = append(out, c.interval(key, state.start, e.Time, IntervalUnknown, ReasonUnmeasured, state))
				}
				delete(c.tasks, key)
				id := correlationPID(key)
				process := c.processes[id]
				process.tasks--
				if process.tasks == 0 {
					delete(c.processes, id)
				} else {
					c.processes[id] = process
				}
			} else {
				// A switch-in without a retained switch-out proves a missing baseline,
				// not zero off-CPU activity. Revoke coverage through this new boundary.
				out = append(out, c.invalidate(e.Time, ReasonLoss)...)
			}
		}
		if s.Previous != nil {
			if len(c.tasks) >= c.maxTasks {
				out = append(out, c.invalidate(e.Time, ReasonLoss)...)
				return out
			}
			key := *s.Previous
			c.tasks[key] = &correlationTaskState{start: e.Time, out: true, runnable: s.Preempted || s.PreviousState == 0, chain: s.SwitchOutCallchain, missing: s.MissingCallchain}
			id := correlationPID(key)
			process := c.processes[id]
			process.start = key.ProcessStart
			process.generation = key.Generation
			process.tasks++
			c.processes[id] = process
			if len(c.tasks) > c.peakTasks {
				c.peakTasks = len(c.tasks)
			}
		}
		return out
	}
	return nil
}
