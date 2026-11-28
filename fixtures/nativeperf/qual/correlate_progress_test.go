//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// longCapture is a pinned, repeatedly sleeping and preempted task: every 5 ms it
// switches out sleeping, is woken 1 ms later and runs again 1 ms after the wake
// (1 ms blocked + 1 ms runnable per cycle), 3 events per cycle.
func longCapture(cycles int, progress bool) (CaptureResult, uint64) {
	domain := nativeperf.ClockDomain{HostID: "host-a", BootID: "boot-a"}
	key := nativeperf.TaskKey{BootID: "boot-a", PIDNamespace: 1, TGID: 7, TID: 7, ProcessStart: 1, Generation: 1}
	base := uint64(10_000_000_000)
	res := CaptureResult{Proofs: []nativeperf.AcquisitionProof{{Domain: domain, CPUs: []uint32{0, 1}, Through: model.MonoNano(base - 1)}}, ProofAt: []int{0}}
	for i := range cycles {
		at := base + uint64(i)*5_000_000
		for _, ev := range schedEvents(domain, key, at) {
			ev.Sequence = model.Uint64(len(res.Events) + 1)
			res.Events = append(res.Events, ev)
		}
		// the events above end at +55 ms in the shared builder; rewrite them to the 1 + 1 ms cycle
		n := len(res.Events)
		res.Events[n-2].Time = model.MonoNano(at + 1_000_000)
		res.Events[n-1].Time = model.MonoNano(at + 2_000_000)
		if progress {
			res.Proofs = append(res.Proofs, nativeperf.AcquisitionProof{Domain: domain, CPUs: []uint32{0, 1}, Through: model.MonoNano(at + 2_000_001), Progress: true})
			res.ProofAt = append(res.ProofAt, len(res.Events))
		}
	}
	end := base + uint64(cycles)*5_000_000 + 1_000_000
	res.Proofs = append(res.Proofs, nativeperf.AcquisitionProof{Domain: domain, CPUs: []uint32{0, 1}, Through: model.MonoNano(end), Final: true})
	res.ProofAt = append(res.ProofAt, len(res.Events))
	return res, uint64(cycles)
}

func sumKinds(c Correlation) (blocked, runnable uint64) {
	for _, iv := range c.Intervals {
		if iv.Correction {
			continue
		}
		switch iv.Kind {
		case nativeperf.IntervalBlocked:
			blocked += uint64(iv.End - iv.Start)
		case nativeperf.IntervalRunnable:
			runnable += uint64(iv.End - iv.Start)
		}
	}
	return
}

// The correlator's reorder buffer is bounded (a few hundred events); a capture of
// thousands of scheduler events is only correlated exactly when the stream's
// progress proofs are applied while the events arrive.
func TestCorrelateAppliesProgressProofsSoALongCaptureFitsTheBoundedBuffer(t *testing.T) {
	res, cycles := longCapture(1000, true)
	c := Correlate(res, nativeperf.DefaultConfig(1))
	if c.Err != "" || c.ConsumeErrors != 0 || c.SwitchEvents != 2000 || c.WakeupEvents != 1000 {
		t.Fatalf("%+v", c)
	}
	blocked, runnable := sumKinds(c)
	if blocked != cycles*1_000_000 || runnable != cycles*1_000_000 {
		t.Fatalf("blocked %d ns runnable %d ns, want %d each", blocked, runnable, cycles*1_000_000)
	}
	if c.PeakHeapEvents == 0 || c.PeakHeapEvents > 400 {
		t.Fatalf("peak buffered events %d: the proofs did not keep the buffer small", c.PeakHeapEvents)
	}
}

func TestCorrelateWithoutProgressProofsOverflowsTheBoundedBufferExplicitly(t *testing.T) {
	res, _ := longCapture(1000, false)
	c := Correlate(res, nativeperf.DefaultConfig(1))
	if c.ConsumeErrors == 0 {
		t.Fatalf("3000 buffered events fit a bounded buffer: %+v", c)
	}
	blocked, runnable := sumKinds(c)
	if blocked >= 1000*1_000_000 || runnable >= 1000*1_000_000 {
		t.Fatalf("an overflowed capture reported complete totals: %d %d", blocked, runnable)
	}
}

func TestCorrelateRefusesProgressProofsWithoutAnEventPosition(t *testing.T) {
	res, _ := longCapture(4, true)
	res.ProofAt = nil
	if c := Correlate(res, nativeperf.DefaultConfig(1)); c.Err == "" {
		t.Fatalf("progress proofs applied at an unknown position: %+v", c)
	}
}
