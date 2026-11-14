// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"container/heap"
	"errors"
	"github.com/arynyklas/soundpost/internal/model"
)

var ErrCorrelationLate = errors.New("native correlation record outside committed prefix")
var ErrCorrelationClock = errors.New("native correlation clock mismatch")

// Correlator is single-owner, scope/session-bound state; it is not goroutine-safe.
// Configure supplies explicit topology and a reservation from the aggregate
// 64MiB acquisition/export budget. No CPU or progress is learned from samples.
// A returned correction must be consumed even when Consume also returns an error.
// The caller owns returned intervals and may keep them immutable indefinitely if
// it separately accounts that storage; the correlator retains no borrowed output.
type Correlator struct {
	cfg                                      Config
	initErr                                  error
	configured, closed                       bool
	domain                                   ClockDomain
	cpus                                     map[uint32]*correlationCPU
	tasks                                    map[TaskKey]*correlationTaskState
	processes                                map[correlationProcess]correlationProcessState
	events                                   correlationHeap
	maxEvents, maxTasks                      int
	peakHeap, peakTasks                      int
	reserved                                 uint64
	watermark, processed, latest, epochStart model.MonoNano
	haveWatermark                            bool
}

func NewCorrelator(cfg Config) *Correlator { return &Correlator{cfg: cfg, initErr: cfg.Validate()} }
func (c *Correlator) ready() bool          { return c != nil && c.initErr == nil && c.configured && !c.closed }

// Consume validates and owns only the event metadata needed for correlation.
// It buffers until explicit drained-prefix proofs permit Advance; timestamps of
// observed events alone never prove progress of idle, missing or failed CPUs.
// Invalid clock/topology/late evidence revokes historical scheduler coverage and
// drops pending evidence, rather than leaving previously exported false certainty.
func (c *Correlator) Consume(e SanitizedEvent) ([]Interval, error) {
	if c != nil && c.initErr != nil {
		return nil, c.initErr
	}
	if !c.ready() {
		return nil, ErrInvalid
	}
	if err := e.Validate(); err != nil {
		out := c.invalidate(e.Time, ReasonLoss)
		c.clearHeap()
		return out, err
	}
	if e.Domain != c.domain {
		out := c.invalidate(c.processed, ReasonClock)
		c.clearHeap()
		return out, ErrCorrelationClock
	}
	if _, ok := c.cpus[e.CPU]; !ok {
		out := c.invalidate(e.Time, ReasonLoss)
		c.clearHeap()
		return out, ErrInvalid
	}
	if e.Wakeup != nil {
		if target, ok := c.cpus[e.Wakeup.TargetCPU]; !ok || target.failed {
			out := c.invalidate(e.Time, ReasonLoss)
			c.clearHeap()
			return out, ErrInvalid
		}
	}
	if e.Time < c.epochStart || c.haveWatermark && e.Time <= c.watermark {
		out := c.invalidate(e.Time, ReasonLoss)
		c.clearHeap()
		return out, ErrCorrelationLate
	}
	if c.cpus[e.CPU].failed {
		out := c.invalidate(e.Time, ReasonLoss)
		c.clearHeap()
		return out, ErrInvalid
	}
	if len(c.events) >= c.maxEvents {
		out := c.invalidate(e.Time, ReasonLoss)
		c.clearHeap()
		return out, ErrResourceBudget
	}
	e = ownCorrelationEvent(e)
	heap.Push(&c.events, e)
	if e.Time > c.latest {
		c.latest = e.Time
	}
	if len(c.events) > c.peakHeap {
		c.peakHeap = len(c.events)
	}
	return nil, nil
}
func ownCorrelationEvent(e SanitizedEvent) SanitizedEvent {
	// CPU observations produce native_samples=1, never scheduler elapsed time or a
	// later wait's stack. Mapping updates belong to the separate mapping owner.
	e.CPUEvent = nil
	if e.Mapping != nil {
		e.Mapping = &MappingUpdate{Process: e.Mapping.Process}
	}
	if e.Switch != nil {
		s := *e.Switch
		if s.Previous != nil {
			key := *s.Previous
			s.Previous = &key
		}
		if s.Next != nil {
			key := *s.Next
			s.Next = &key
		}
		s.SwitchOutCallchain = append([]CallchainEntry(nil), s.SwitchOutCallchain...)
		e.Switch = &s
	}
	if e.Wakeup != nil {
		w := *e.Wakeup
		e.Wakeup = &w
	}
	if e.Loss != nil {
		loss := *e.Loss
		loss.Throttle = nil
		e.Loss = &loss
	}
	if e.Generation != nil {
		generation := *e.Generation
		e.Generation = &generation
	}
	return e
}
