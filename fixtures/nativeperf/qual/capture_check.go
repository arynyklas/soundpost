// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"errors"
	"fmt"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// Rejections of a capture that cannot support release qualification.
var (
	ErrStagedPending    = errors.New("capture path is staged: acquisition_pending")
	ErrEmptySession     = errors.New("capture session succeeded but produced no events")
	ErrSyntheticSamples = errors.New("capture samples are synthetic or not from the target")
	ErrNoopSampler      = errors.New("capture sampler is a no-op: no real CPU samples for the observed on-CPU time")
	ErrUnverifiable     = errors.New("capture cannot be verified: required target evidence is missing")
)

// CaptureEvidence is what a Linux capture path returned for a target whose
// real behavior the verifier knows independently.
type CaptureEvidence struct {
	OpenError          error
	Events             []nativeperf.SanitizedEvent
	TargetTGID         uint32
	WorkloadCPUSeconds float64              // on-CPU time recorded by the workload itself
	InExecutable       func(ip uint64) bool // true when ip lies in an executable mapping of the target
	KnownThread        func(tid uint32) bool
}

// CheckCapture decides whether a capture may count toward release qualification.
// It rejects a staged acquisition_pending path, a successful session with no
// events, synthetic samples and a no-op sampler. A genuine permission denial is
// returned wrapped but never classified as one of those four: it stays a
// distinct failed/unqualified row for the caller.
func CheckCapture(ev CaptureEvidence) error {
	if ev.OpenError != nil {
		var ce *nativeperf.CapabilityError
		if errors.Is(ev.OpenError, nativeperf.ErrAcquisitionPending) || (errors.As(ev.OpenError, &ce) && ce.Reason == nativeperf.ReasonAcquisition) {
			return ErrStagedPending
		}
		return fmt.Errorf("capture did not open: %w", ev.OpenError)
	}
	if len(ev.Events) == 0 {
		return ErrEmptySession
	}
	if ev.InExecutable == nil || ev.KnownThread == nil || ev.TargetTGID == 0 {
		return ErrUnverifiable
	}
	var cpu []nativeperf.SanitizedEvent
	for _, e := range ev.Events {
		if e.Kind == nativeperf.EventCPU && e.CPUEvent != nil {
			cpu = append(cpu, e)
		}
	}
	if len(cpu) == 0 {
		return ErrNoopSampler
	}
	// 99 Hz over the target's own recorded on-CPU time: under a quarter of that
	// (or fewer than two samples) is a sampler that does not sample.
	if expected := 99 * ev.WorkloadCPUSeconds; len(cpu) < 2 || (expected >= 20 && float64(len(cpu)) < expected/4) {
		return fmt.Errorf("%w: %d samples for ~%.0f expected", ErrNoopSampler, len(cpu), expected)
	}
	return checkGenuine(ev, cpu)
}

func checkGenuine(ev CaptureEvidence, cpu []nativeperf.SanitizedEvent) error {
	synthetic := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrSyntheticSamples, fmt.Sprintf(format, args...))
	}
	last := map[uint32]uint64{}
	gaps := map[uint32][]uint64{}
	distinct := map[string]bool{}
	inside := 0
	var lastSeq uint64
	for _, e := range cpu {
		if e.Task.TGID != ev.TargetTGID {
			return synthetic("sample from process %d, target is %d", e.Task.TGID, ev.TargetTGID)
		}
		if !ev.KnownThread(e.Task.TID) {
			return synthetic("sample from thread %d which is not a target thread", e.Task.TID)
		}
		if uint64(e.Sequence) <= lastSeq {
			return synthetic("sequence %d does not increase", e.Sequence)
		}
		lastSeq = uint64(e.Sequence)
		t := uint64(e.Time)
		if prev, ok := last[e.Task.TID]; ok {
			if t < prev {
				return synthetic("time goes backwards on thread %d", e.Task.TID)
			}
			gaps[e.Task.TID] = append(gaps[e.Task.TID], t-prev)
		}
		last[e.Task.TID] = t
		if ev.InExecutable(uint64(e.CPUEvent.IP)) {
			inside++
		}
		distinct[fmt.Sprint(e.CPUEvent.IP, e.CPUEvent.Callchain)] = true
	}
	if len(cpu) >= 10 && len(distinct) == 1 {
		return synthetic("all %d samples carry the same instruction pointer and callchain", len(cpu))
	}
	if inside*10 < len(cpu)*9 {
		return synthetic("only %d of %d sample addresses lie in an executable mapping of the target", inside, len(cpu))
	}
	for tid, g := range gaps {
		if len(g) < 8 {
			continue
		}
		same := true
		for _, v := range g[1:] {
			same = same && v == g[0]
		}
		if same {
			return synthetic("thread %d has a perfectly constant %d ns cadence", tid, g[0])
		}
	}
	return nil
}
