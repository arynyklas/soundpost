// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0

// Package realcapture takes a REAL native CPU capture for the acceptance and end-to-end evidence: it starts a controlled CPU workload (the
// compiled fixtures/nativeperf/cpu/loop.c), authorizes that one process with a signed start, runs the in-process native helper over a private
// socket (the same Helper, signed-start, peer-credential and ProfileSource acquisition path the production collector uses: perf_event_open
// software CPU-clock samples, no root when perf_event_paranoid <= 1 and the target is the caller's own uid) and returns the sanitized events.
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

// Request describes one capture.
type Request struct {
	// Workload is the compiled loop.c (see BuildWorkload): a non-PIE executable with symbols and a GNU build ID.
	Workload string
	// Seconds is the longest capture; it also ends after MaxEvents events.
	Seconds int
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
	// CPUSamples counts the CPU events; HotSamples those whose IP lies in the workload's soundpost_hot_loop symbol.
	CPUSamples int    `json:"cpu_samples"`
	HotSamples int    `json:"hot_loop_samples"`
	Threads    int    `json:"threads"`
	Loss       uint64 `json:"loss"`
	Period     uint64 `json:"period"`
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
