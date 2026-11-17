// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"container/heap"
	"github.com/arynyklas/soundpost/internal/model"
)

// The charge covers what the correlator itself holds per slot: the owned event with its maximum 128-entry switch
// stack, heap capacity and allocator/map slack, or a task state with its own stack in its map entries (measured worst
// case about 3.4 KiB each, TestCorrelatorPhysicalWorstCaseFitsItsReservation, so 8 KiB is about 2.4x). Interval
// stacks the correlator returns transfer to the caller, who accounts them separately (see Correlator).
const correlationSlotBytes uint64 = 8 << 10
const correlationBaseBytes uint64 = 16 << 10
const correlationCPUBytes uint64 = 256
const correlationMaxCPUs = 256

type correlationCPU struct {
	through        model.MonoNano
	proved, failed bool
}
type correlationHeap []SanitizedEvent

func (h correlationHeap) Len() int { return len(h) }
func (h correlationHeap) Less(i, j int) bool {
	a, b := h[i], h[j]
	if a.Time != b.Time {
		return a.Time < b.Time
	}
	if a.CPU != b.CPU {
		return a.CPU < b.CPU
	}
	return a.Sequence < b.Sequence
}
func (h correlationHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *correlationHeap) Push(v any)   { *h = append(*h, v.(SanitizedEvent)) }
func (h *correlationHeap) Pop() any {
	old := *h
	n := len(old) - 1
	e := old[n]
	old[n] = SanitizedEvent{}
	*h = old[:n]
	return e
}

// Configure binds the acquisition clock and the FULL scheduler CPU topology,
// not merely CPUs seen in authorized events. remainingBytes must be an exclusive
// reservation AFTER rings, socket/decoder buffers, mappings and exporter memory
// have been charged against cfg.MaxMemory. This method never guesses that budget
// or host topology. Reserve it for this correlator until final outputs are handed
// off. Invalid configuration is retryable; successful configuration is one-shot.
func (c *Correlator) Configure(domain ClockDomain, cpus []uint32, remainingBytes uint64) error {
	if c != nil && c.initErr != nil {
		return c.initErr
	}
	if c == nil || c.configured {
		return ErrInvalid
	}
	if !domain.valid() {
		return ErrInvalid
	}
	if remainingBytes > c.cfg.MaxMemory || remainingBytes < 64<<10 {
		return ErrResourceBudget
	}
	topology, err := correlationTopology(cpus)
	if err != nil {
		return err
	}
	base := correlationBaseBytes + uint64(len(cpus))*correlationCPUBytes
	if remainingBytes <= base+2*correlationSlotBytes {
		return ErrResourceBudget
	}
	slots := int((remainingBytes - base) / (2 * correlationSlotBytes))
	c.domain = domain
	c.cpus = topology
	c.maxEvents = slots
	c.maxTasks = slots
	c.reserved = remainingBytes
	c.events = make(correlationHeap, 0, slots)
	c.tasks = make(map[TaskKey]*correlationTaskState)
	c.processes = make(map[correlationProcess]correlationProcessState)
	c.configured = true
	return nil
}
func correlationTopology(cpus []uint32) (map[uint32]*correlationCPU, error) {
	if len(cpus) == 0 {
		return nil, ErrInvalid
	}
	if len(cpus) > correlationMaxCPUs {
		return nil, ErrResourceBudget
	}
	result := make(map[uint32]*correlationCPU, len(cpus))
	for _, cpu := range cpus {
		if _, ok := result[cpu]; ok {
			return nil, ErrInvalid
		}
		result[cpu] = &correlationCPU{}
	}
	return result, nil
}

// ReportProgress is a drained-prefix proof, NOT the timestamp of a last sample
// or a wall-clock tick. The acquisition owner promises every scheduler stream
// (switch AND wakeup, including idle/foreign records) on this active CPU has been
// read through through in this boot clock; all admitted records <= through have
// already been Consume'd and any losses reported. CPUs without authorized events
// still need this proof. A failed/missing CPU cannot make progress. The bounded
// reorder margin is applied only by Advance. A violated proof is handled as late
// evidence, with an explicit historical correction, never silently trusted.
func (c *Correlator) ReportProgress(cpu uint32, through model.MonoNano) error {
	if !c.ready() {
		return ErrInvalid
	}
	p, ok := c.cpus[cpu]
	if !ok || p.failed || p.proved && through < p.through {
		return ErrInvalid
	}
	p.through = through
	p.proved = true
	return nil
}
func (c *Correlator) safeThrough(final bool) (model.MonoNano, bool) {
	var minimum model.MonoNano
	first := true
	for _, p := range c.cpus {
		if !p.proved || p.failed {
			return 0, false
		}
		if first || p.through < minimum {
			minimum = p.through
			first = false
		}
	}
	if first {
		return 0, false
	}
	if final {
		return minimum, true
	}
	window := model.MonoNano(c.cfg.ReorderWindow)
	if minimum < window {
		return 0, false
	}
	return minimum - window, true
}

// Advance drains <= min(requested, every-active-CPU drained proof - 100ms).
// No Consume timestamp advances the watermark. Returning no intervals can mean
// a stalled CPU, not zero activity. Already committed bounds never regress.
func (c *Correlator) Advance(requested model.MonoNano) ([]Interval, error) {
	if !c.ready() {
		return nil, ErrInvalid
	}
	safe, ok := c.safeThrough(false)
	if !ok {
		return nil, nil
	}
	if requested < safe {
		safe = requested
	}
	if c.haveWatermark && safe < c.watermark {
		return nil, ErrInvalid
	}
	return c.drain(safe), nil
}
func (c *Correlator) drain(through model.MonoNano) []Interval {
	var out []Interval
	for len(c.events) > 0 && c.events[0].Time <= through {
		e := heap.Pop(&c.events).(SanitizedEvent)
		if e.Time > c.processed {
			c.processed = e.Time
		}
		out = append(out, c.apply(e)...)
	}
	c.watermark = through
	c.haveWatermark = true
	return out
}

// ChangeTopology starts a new acquisition epoch. The caller must stop/drain old
// streams, account hotplug/failure loss, and open ALL new CPU streams before
// reporting new progress. Pending events and task states are discarded with a
// domain-wide gap; no old proof is reused for a newly online or surviving CPU.
func (c *Correlator) ChangeTopology(at model.MonoNano, cpus []uint32) ([]Interval, error) {
	if !c.ready() || c.haveWatermark && at < c.watermark {
		return nil, ErrInvalid
	}
	topology, err := correlationTopology(cpus)
	if err != nil {
		return nil, err
	}
	if uint64(len(cpus))*correlationCPUBytes+correlationBaseBytes+uint64(c.maxEvents+c.maxTasks)*correlationSlotBytes > c.reserved {
		return nil, ErrResourceBudget
	}
	out := c.invalidate(at, ReasonLoss)
	c.clearHeap()
	c.cpus = topology
	c.epochStart = at
	return out, nil
}

// ReportCPUFailure freezes the CPU until an explicit ChangeTopology; removing a
// failed CPU from a minimum calculation would falsely declare complete coverage.
func (c *Correlator) ReportCPUFailure(cpu uint32, at model.MonoNano) ([]Interval, error) {
	if !c.ready() {
		return nil, ErrInvalid
	}
	p, ok := c.cpus[cpu]
	if !ok {
		return nil, ErrInvalid
	}
	p.failed = true
	out := c.invalidate(at, ReasonLoss)
	c.clearHeap()
	return out, nil
}

// RevokeFrom is the consumer side of a stream that ended on an identity error: the acquisition proved its identity last at
// `from` (see IdentityError.ProvenThrough, 0 when it never did), so everything published after it is unproven. It returns one
// domain-wide correction over [start, end) where end is the latest evidence the correlator holds and start is `from`, or the
// earliest instant the correlator can no longer vouch for when that is older: a wait still open at `from` and an event still
// buffered from before it are dropped with the rest, so the proven prefix and the correction leave no hole. Intervals returned
// earlier are never edited (the correction replaces their completeness where it overlaps them, see invalidate). The stream is
// over: the correlator takes no further event, and Finalize refuses (a revoked capture has no complete end).
func (c *Correlator) RevokeFrom(from model.MonoNano) ([]Interval, error) {
	if !c.ready() {
		return nil, ErrInvalid
	}
	start, end := from, from
	if len(c.events) > 0 && c.events[0].Time < start {
		start = c.events[0].Time
	}
	for _, state := range c.tasks {
		if state.out && state.start < start {
			start = state.start
		}
	}
	for _, at := range []model.MonoNano{c.latest, c.watermark, c.processed} {
		if at > end {
			end = at
		}
	}
	clear(c.tasks)
	clear(c.processes)
	c.clearHeap()
	c.closed = true
	return []Interval{{Domain: c.domain, Kind: IntervalUnknown, Start: start, End: end, Measure: Measure{Unit: UnitNanoseconds, Value: model.Uint64(end - start)}, Reason: ReasonGeneration, Correction: true}}, nil
}
func (c *Correlator) clearHeap() {
	for i := range c.events {
		c.events[i] = SanitizedEvent{}
	}
	c.events = c.events[:0]
	c.latest = c.processed
}

// Finalize requires stronger end-of-acquisition proof: every stream has stopped
// and has been drained through end, with losses delivered. No 100ms subtraction
// is needed for a quiescent prefix. It is not a timeout/Close convenience. Every
// still-open interval is censored as a whole, including waits with an observed
// wake; no synthetic switch-in or completed blocking duration is manufactured.
func (c *Correlator) Finalize(end model.MonoNano) ([]Interval, error) {
	if !c.ready() {
		return nil, ErrInvalid
	}
	safe, ok := c.safeThrough(true)
	if !ok || safe < end || c.haveWatermark && end < c.watermark || len(c.events) > 0 && c.latest > end {
		return nil, ErrInvalid
	}
	out := c.drain(end)
	for _, key := range c.sortedTasks() {
		state := c.tasks[key]
		if state.out {
			out = append(out, c.interval(key, state.start, end, IntervalCensored, ReasonUnmeasured, state))
		}
	}
	clear(c.tasks)
	clear(c.processes)
	c.clearHeap()
	c.closed = true
	return out, nil
}
