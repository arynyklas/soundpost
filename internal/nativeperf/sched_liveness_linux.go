//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"encoding/binary"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// CPU hotplug under a scheduler capture. The scheduler tracepoint events are per CPU (one set per online CPU), so the
// capture's coverage claim, every progress proof "all streams of all listed CPUs are drained through T", is only true
// while all of those events keep counting. Two things end that, and both are detected here and end the stream with the
// closed code topology_changed carrying the last instant the topology was proven (IdentityError.ProvenThrough, which a
// consumer turns into Correlator.RevokeFrom; the CPU samples before it stay valid, they are task-scoped and unaffected):
//
//   - the online set differs from the one the capture opened with (a CPU left, or one joined that has no events);
//   - a CPU went offline and came back between two identity checks. The set is then identical, but the kernel removed
//     every per-CPU event of that CPU when it went offline (perf_event_exit_cpu_context detaches them and leaves them
//     OFF; they are not re-attached when the CPU returns), so the CPU's scheduler records silently stop while the
//     proofs go on claiming complete coverage. Measured on 6.1.0-54 with a stopped target pinned to the cycled CPU: after
//     one 85 ms cycle the target ran again and no scheduler record of it arrived in 2.5 s, 240 more progress proofs, no error;
//     TestHotplugKernelLeavesPerCPUEventsOffAfterACycle measures the kernel premise again on whatever host runs it.
//
// The second is seen through the event's own enabled time (PERF_FORMAT_TOTAL_TIME_ENABLED, read(2) on the event fd): it
// grows with the wall clock while the event counts and stops when the kernel turns it off. An event whose enabled time
// grew by less than the time that provably passed since the previous read was off for part of it.

// perfFormatTotalTimeEnabled is PERF_FORMAT_TOTAL_TIME_ENABLED: read(2) returns {count, time_enabled}.
const perfFormatTotalTimeEnabled = 1

const (
	// schedulerLivenessInterval is the least wall time between two rounds of enabled-time reads: one read per scheduler
	// event, three per online CPU, so the cost is bounded by the CPU count and independent of the event rate.
	schedulerLivenessInterval = 100 * time.Millisecond
	// enabledSlack is what the enabled time may fall short of the elapsed time before it counts as a stop: the event
	// clock and CLOCK_MONOTONIC differ in rate by parts per million, and the two reads are not at one instant.
	enabledSlack = time.Millisecond
)

// enabledKept says whether an event's enabled time kept up with the wall clock between two reads. prevAt is the event
// clock instant after the previous round of reads (the capture start for the first), nowBefore the instant before this
// round: their difference is a lower bound of the time between the two reads of any one event, so an event that was
// counting the whole time has grown by at least that. The first read of an event compares against zero and the capture
// start: it was enabled before the start was taken, so its enabled time is at least the time since the start.
func enabledKept(prev, now uint64, prevAt, nowBefore model.MonoNano) bool {
	if now < prev {
		return false
	}
	if nowBefore <= prevAt {
		return true
	}
	elapsed := uint64(nowBefore - prevAt)
	slack := uint64(enabledSlack) + elapsed/1024
	return now-prev+slack >= elapsed
}

// enabledTime reads how long the kernel has had this event enabled, in nanoseconds.
func (r *Ring) enabledTime() (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.fd == nil {
		return 0, ErrAcquisitionClosed
	}
	var buf [16]byte
	n, e := r.fd.Read(buf[:])
	if e != nil || n != len(buf) {
		return 0, ErrAcquisitionFailed
	}
	return binary.NativeEndian.Uint64(buf[8:]), nil
}

// schedulerLiveness is the per-event enabled-time ledger of a running scheduler capture.
type schedulerLiveness struct {
	armed   bool
	at      time.Time      // wall time of the last completed round (throttle)
	prevAt  model.MonoNano // event clock after the last completed round
	enabled []uint64       // enabled time of every scheduler event at the last round
	// proven is the instant before the last completed round: every scheduler event was counting through it.
	proven model.MonoNano
}

// arm starts the ledger at the capture start: every event was enabled before it.
func (l *schedulerLiveness) arm(start model.MonoNano, events int) {
	*l = schedulerLiveness{armed: true, at: time.Now(), prevAt: start, enabled: make([]uint64, events), proven: start}
}

// provenThrough is the last instant the whole topology was proven: the online set was the capture's, and every
// scheduler event was counting. Zero when nothing was proven yet.
func (s *schedulerSource) provenThrough() model.MonoNano {
	if s.topologyProven == 0 || !s.live.armed {
		return 0
	}
	return min(s.topologyProven, s.live.proven)
}

func (s *schedulerSource) topologyError() error {
	return &IdentityError{Err: ErrTopologyChanged, ProvenThrough: s.provenThrough()}
}

// verifyTopology compares the online CPU set with the one the capture opened with, and, when due (or forced), reads the
// enabled time of every scheduler event.
func (s *schedulerSource) verifyTopology(force bool) error {
	before, e := schedulerNow()
	if e != nil {
		return e
	}
	online := s.onlineCPUs
	if online == nil {
		online = schedulerCPUs
	}
	cpus, e := online()
	if e != nil {
		return e
	}
	if !sameCPUs(cpus, s.cpus) {
		return s.topologyError()
	}
	s.topologyProven = before
	if !s.live.armed || !force && time.Since(s.live.at) < schedulerLivenessInterval {
		return nil
	}
	return s.verifyLive(before)
}

func sameCPUs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// verifyLive reads every scheduler event's enabled time and ends the capture on one that stopped.
func (s *schedulerSource) verifyLive(before model.MonoNano) error {
	l := &s.live
	read := s.enabledOf
	if read == nil {
		read = func(r *Ring) (uint64, error) { return r.enabledTime() }
	}
	next := make([]uint64, len(s.rings))
	for i, sr := range s.rings {
		enabled, e := read(sr.ring)
		if e != nil {
			return &IdentityError{Err: e, ProvenThrough: s.provenThrough()}
		}
		if !enabledKept(l.enabled[i], enabled, l.prevAt, before) {
			return s.topologyError()
		}
		next[i] = enabled
	}
	after, e := schedulerNow()
	if e != nil {
		return e
	}
	l.enabled, l.prevAt, l.proven, l.at = next, after, before, time.Now()
	return nil
}
