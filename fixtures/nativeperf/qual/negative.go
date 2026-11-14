// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"context"
	"errors"
	"fmt"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// These builders make DELIBERATELY CONTAMINATED captures (the negative controls
// the acceptance runner must reject before it runs the real path). They are the
// only synthetic samples in this package and never reach a report as evidence.

const negTGID = 31337

func negEvent(seq, at uint64, tid uint32, ip uint64, chain ...uint64) nativeperf.SanitizedEvent {
	cc := []nativeperf.CallchainEntry{{Context: nativeperf.ContextUser}}
	for _, c := range chain {
		cc = append(cc, nativeperf.CallchainEntry{IP: model.Uint64(c)})
	}
	return nativeperf.SanitizedEvent{
		Kind: nativeperf.EventCPU, Time: model.MonoNano(at), CPU: 1, Sequence: model.Uint64(seq),
		Domain: nativeperf.ClockDomain{HostID: "neg-host", BootID: "neg-boot"},
		Task:   nativeperf.TaskKey{BootID: "neg-boot", PIDNamespace: 1, TGID: negTGID, TID: tid, ProcessStart: 1, Generation: 1},
		CPUEvent: &nativeperf.CPUSample{IP: model.Uint64(ip), Callchain: cc, Method: nativeperf.MethodSoftwareCPUClock,
			Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: model.Uint64(10_101_010)},
	}
}

func negEvidence(events []nativeperf.SanitizedEvent) CaptureEvidence {
	return CaptureEvidence{
		Events: events, TargetTGID: negTGID, WorkloadCPUSeconds: 5,
		InExecutable: func(ip uint64) bool { return ip >= 0x400000 && ip < 0x500000 },
		KnownThread:  func(tid uint32) bool { return tid == negTGID },
	}
}

// RunNegativeControls feeds contaminated captures to CheckCapture and reports,
// per control, whether it was rejected for the expected reason. A last entry is
// the positive control: a plausible capture that must NOT be rejected, so a
// checker that rejects everything cannot pass.
func RunNegativeControls() []NegativeControl {
	var out []NegativeControl
	record := func(name string, want error, ev CaptureEvidence) {
		err := CheckCapture(ev)
		nc := NegativeControl{Name: name, Rejected: err != nil, Behaved: errors.Is(err, want)}
		if err != nil {
			nc.Reason = err.Error()
		} else {
			nc.Reason = "accepted"
		}
		out = append(out, nc)
	}
	var staged nativeperf.Session
	_, stagedErr := staged.Next(context.Background())
	record("staged_acquisition_pending_session", ErrStagedPending, CaptureEvidence{OpenError: stagedErr})
	record("staged_acquisition_pending_capability", ErrStagedPending, CaptureEvidence{OpenError: &nativeperf.CapabilityError{Status: nativeperf.Unsupported, Reason: nativeperf.ReasonAcquisition}})
	record("successful_empty_session", ErrEmptySession, negEvidence(nil))

	var synthetic []nativeperf.SanitizedEvent
	for i := 0; i < 500; i++ {
		synthetic = append(synthetic, negEvent(uint64(i+1), uint64(1_000_000_000+i*10_101_010), negTGID, 0x401000, 0x402000, 0x403000))
	}
	record("synthetic_samples_perfect_cadence", ErrSyntheticSamples, negEvidence(synthetic))

	noop := []nativeperf.SanitizedEvent{{Kind: nativeperf.EventLoss, Time: 1, Sequence: 1, Domain: nativeperf.ClockDomain{HostID: "neg-host", BootID: "neg-boot"},
		Task: nativeperf.TaskKey{BootID: "neg-boot", PIDNamespace: 1, TGID: negTGID, TID: negTGID, ProcessStart: 1, Generation: 1},
		Loss: &nativeperf.LossEvent{Count: 1, Reason: nativeperf.ReasonLoss}}}
	record("noop_sampler_no_cpu_samples", ErrNoopSampler, negEvidence(noop))
	record("noop_sampler_trickle", ErrNoopSampler, negEvidence(synthetic[:5]))

	// positive control: jittered, varying, in-target samples must pass.
	var genuine []nativeperf.SanitizedEvent
	at := uint64(1_000_000_000)
	for i := 0; i < 600; i++ {
		at += 10_100_000 + uint64((i*7919)%2_000_003)
		genuine = append(genuine, negEvent(uint64(i+1), at, negTGID, 0x401000+uint64((i*37)%64), 0x402000+uint64(i%5), 0x403000))
	}
	err := CheckCapture(negEvidence(genuine))
	out = append(out, NegativeControl{Name: "positive_control_plausible_capture_accepted", Rejected: err != nil, Behaved: err == nil, Reason: fmt.Sprint(err)})
	return out
}
