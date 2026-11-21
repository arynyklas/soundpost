// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0

// Package realcapture takes a REAL native capture for the acceptance and end-to-end evidence: it starts a controlled workload (the
// compiled fixtures/nativeperf/cpu/loop.c for CPU samples, fixtures/nativeperf/export/workloads/cpu_wait.c for CPU plus scheduler evidence),
// authorizes that one process with a signed start, runs the in-process native helper over a private
// socket (the same Helper, signed-start, peer-credential and ProfileSource acquisition path the production collector uses: perf_event_open
// software CPU-clock samples, no root when perf_event_paranoid <= 1 and the target is the caller's own uid; the scheduler tracepoints need
// tracefs and CAP_PERFMON) and returns the sanitized events and, for a scheduler capture, the blocked/runnable intervals the per-session
// Correlator built from the real switch and wakeup events.
//
// A host that cannot capture reports *CannotCapture with the helper's or the probe's reason; there is no synthetic substitute.
package realcapture

import (
	"fmt"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// MaxEvents is the most events one capture returns: AssembleProfile charges every event 32 KiB of its 8 MiB working set.
const MaxEvents = 240

// SchedulerItems is when a scheduler capture asks the helper to stop: the assembler charges every kept event and interval 32 KiB of its
// 8 MiB working set (at most 255 together), and the intervals still in flight at the stop are bounded by the proofs already received.
const SchedulerItems = 160

// SchedulerStats are counts of what a scheduler capture's stream produced: the evidence the blocked/runnable intervals stand on.
type SchedulerStats struct {
	SwitchEvents   int  `json:"switch_events"`
	WakeupEvents   int  `json:"wakeup_events"`
	LossEvents     int  `json:"loss_events"`
	ProgressProofs int  `json:"progress_proofs"`
	CPUs           int  `json:"cpus"`
	ConsumeErrors  int  `json:"consume_errors"`
	Blocked        int  `json:"blocked_intervals"`
	Runnable       int  `json:"runnable_intervals"`
	Unknown        int  `json:"unknown_intervals"`
	Censored       int  `json:"censored_intervals"`
	Corrections    int  `json:"coverage_corrections"`
	FinalProof     bool `json:"final_proof_received"`
}

// Request describes one capture.
type Request struct {
	// Workload is the compiled loop.c or cpu_wait.c (see BuildWorkload): a non-PIE executable with symbols and a GNU build ID.
	Workload string
	// Seconds is the longest capture; it also ends after MaxEvents events (a scheduler capture: after SchedulerItems events and intervals).
	Seconds int
	// HotSymbol is the workload function the CPU samples must land in; empty is soundpost_hot_loop (loop.c).
	HotSymbol string
	// Scheduler also captures the scheduler tracepoints (nativeperf.ModeCPUOffCPU) and correlates them per session into intervals.
	Scheduler bool
}

// Result is what the kernel and the probe reported for one capture. It is JSON-serializable (a capture can be taken in a child process
// and read back, see fixtures/nativeperf/e2eprofile -events-out), except Mappings, which only an in-process capture carries.
type Result struct {
	Events       []nativeperf.SanitizedEvent `json:"events"`
	Capabilities nativeperf.Capabilities     `json:"capabilities"`
	// FirstMono is the monotonic reading just before the capture request: the clock pair of a profile maps it to a wall time.
	FirstMono model.MonoNano `json:"first_mono_ns"`
	// Mappings are the frame mappings the acquisition derived (nativeperf.ProfileLimits.Mappings). A capture read back from a child process
	// has none: the profile then assembles with the default symbol policy, which is what the workload (built with frame pointers) has.
	Mappings []nativeperf.MappingTable `json:"-"`
	// CPUSamples counts the CPU events; HotSamples those whose IP lies in the workload's hot symbol.
	CPUSamples int    `json:"cpu_samples"`
	HotSamples int    `json:"hot_loop_samples"`
	Threads    int    `json:"threads"`
	Loss       uint64 `json:"loss"`
	Period     uint64 `json:"period"`
	// Intervals are the blocked/runnable/unknown intervals and coverage corrections of a scheduler capture (nil otherwise); Scheduler counts
	// what the stream produced. An in-process capture only, like Mappings.
	Intervals []nativeperf.Interval `json:"-"`
	Scheduler SchedulerStats        `json:"-"`
}

// CannotCapture means this host cannot take the capture at all (no compiler, not Linux, the CPU event is not openable): not a defect of the
// capture path, and never answered with substitute data.
type CannotCapture struct{ Reason string }

func (e *CannotCapture) Error() string {
	return "this host cannot capture native CPU profiles: " + e.Reason
}

func cannot(format string, args ...any) error {
	return &CannotCapture{Reason: fmt.Sprintf(format, args...)}
}
