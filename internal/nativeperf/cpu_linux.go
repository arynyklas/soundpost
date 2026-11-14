//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import "github.com/arynyklas/soundpost/internal/model"

type DecodeContext struct {
	Method    SamplingMethod
	MaxFrames uint16
}

func safeUserIP(ip uint64) bool { return ip != 0 && ip < 1<<56 }
func callchainMarker(ip uint64) (CallchainContext, bool) {
	switch ip {
	case ^uint64(31):
		return ContextHypervisor, true
	case ^uint64(127):
		return ContextKernel, true
	case ^uint64(511):
		return ContextUser, true
	case ^uint64(2047):
		return ContextGuest, true
	case ^uint64(2175):
		return ContextGuestKernel, true
	case ^uint64(2559):
		return ContextGuestUser, true
	}
	return "", false
}
func decodeCPUSample(v KernelRecordView, c DecodeContext) (CPUSample, error) {
	if !v.valid() || v.u32(0) != perfRecordSample || v.len() < 56 || v.u16(4)&7 != 2 || c.MaxFrames == 0 || c.MaxFrames > 128 {
		return CPUSample{}, ErrRingMalformed
	}
	s := CPUSample{IP: model.Uint64(v.u64(8)), Method: c.Method, RequestedHz: 99, Period: model.Uint64(v.u64(40))}
	switch c.Method {
	case MethodSoftwareCPUClock:
		s.Unit = UnitCPUClockNanoseconds
	case MethodHardwareCycles:
		s.Unit = UnitHardwareCycles
	default:
		return CPUSample{}, ErrInvalid
	}
	if !safeUserIP(uint64(s.IP)) || s.Period == 0 || v.u32(36) != 0 {
		return CPUSample{}, ErrRingMalformed
	}
	count := v.u64(48)
	if count > uint64((v.len()-56)/8) || count*8 != uint64(v.len()-56) {
		return CPUSample{}, ErrRingMalformed
	}
	if count >= uint64(min(c.MaxFrames, 127)) {
		s.Truncated = ReasonTruncated
	}
	capacity := count
	if capacity > uint64(c.MaxFrames) {
		capacity = uint64(c.MaxFrames)
	}
	s.Callchain = make([]CallchainEntry, 0, int(capacity))
	context := ContextUser
	frames := 0
	for n := range count {
		ip := v.u64(56 + int(n)*8)
		if marker, ok := callchainMarker(ip); ok {
			context = marker
			if len(s.Callchain) < int(c.MaxFrames) {
				s.Callchain = append(s.Callchain, CallchainEntry{Context: marker})
			} else {
				s.Truncated = ReasonTruncated
			}
			continue
		}
		if ip >= 1<<63 {
			context = ""
		}
		// Even a user-context marker cannot authorize a kernel/noncanonical address.
		// Kernel, hypervisor and guest chains are never exported by this policy.
		if context != ContextUser || !safeUserIP(ip) {
			if s.Truncated != ReasonTruncated {
				s.Truncated = ReasonUnresolved
			}
			continue
		}
		if len(s.Callchain) == int(c.MaxFrames) {
			s.Truncated = ReasonTruncated
			continue
		}
		s.Callchain = append(s.Callchain, CallchainEntry{IP: model.Uint64(ip)})
		frames++
	}
	if frames == 0 && s.Truncated == "" {
		s.Truncated = ReasonMissingCallchain
	}
	return s, nil
}
func decodeCPULoss(v KernelRecordView) (LossEvent, model.MonoNano, error) {
	if !v.valid() {
		return LossEvent{}, 0, ErrRingMalformed
	}
	var loss LossEvent
	var timestamp model.MonoNano
	size := v.len()
	base := 0
	switch v.u32(0) {
	case perfRecordLost:
		base = 24
	case perfRecordLostSamples:
		base = 16
	case perfRecordThrottle, perfRecordUnthrottle:
		base = 32
	default:
		return loss, 0, ErrRingMalformed
	}
	if size != base && size != base+24 {
		return loss, 0, ErrRingMalformed
	}
	if size == base+24 {
		if v.u32(size-4) != 0 {
			return loss, 0, ErrRingMalformed
		}
		timestamp = model.MonoNano(v.u64(size - 16))
	}
	switch v.u32(0) {
	case perfRecordLost:
		loss = LossEvent{Count: model.Uint64(v.u64(16)), Reason: ReasonLoss}
	case perfRecordLostSamples:
		loss = LossEvent{Count: model.Uint64(v.u64(8)), Reason: ReasonSampleLost}
	case perfRecordThrottle, perfRecordUnthrottle:
		reason := ReasonThrottle
		if v.u32(0) == perfRecordUnthrottle {
			reason = ReasonUnthrottle
		}
		loss = LossEvent{Reason: reason, Throttle: &ThrottleEvidence{Reason: reason, EventID: model.Uint64(v.u64(16)), StreamID: model.Uint64(v.u64(24))}}
		timestamp = model.MonoNano(v.u64(8))
	default:
		return loss, 0, ErrRingMalformed
	}
	if !loss.valid() {
		return LossEvent{}, 0, ErrRingMalformed
	}
	return loss, timestamp, nil
}
func decodeCPURecord(v KernelRecordView, r *Ring) (SanitizedEvent, bool, error) {
	if !v.valid() {
		return SanitizedEvent{}, false, ErrRingMalformed
	}
	switch v.u32(0) {
	case perfRecordSample:
		s, e := decodeCPUSample(v, DecodeContext{Method: r.method, MaxFrames: r.maxFrames})
		if e != nil {
			return SanitizedEvent{}, false, e
		}
		if v.u32(16) != r.task.TGID || v.u32(20) != r.task.TID {
			return SanitizedEvent{}, false, ErrTargetIdentity
		}
		return SanitizedEvent{Kind: EventCPU, Time: model.MonoNano(v.u64(24)), CPU: v.u32(32), Task: r.task, CPUEvent: &s}, true, nil
	case perfRecordLost, perfRecordLostSamples, perfRecordThrottle, perfRecordUnthrottle:
		base := 24
		if v.u32(0) == perfRecordLostSamples {
			base = 16
		}
		if v.u32(0) == perfRecordThrottle || v.u32(0) == perfRecordUnthrottle {
			base = 32
		}
		if v.len() != base+24 {
			return SanitizedEvent{}, false, ErrRingMalformed
		}
		loss, t, e := decodeCPULoss(v)
		return SanitizedEvent{Kind: EventLoss, Time: t, CPU: v.u32(v.len() - 8), Loss: &loss}, e == nil, e
	case perfRecordComm:
		if v.len() < 41 {
			return SanitizedEvent{}, false, ErrRingMalformed
		}
		// PERF_RECORD_MISC_COMM_EXEC: refuse generation ambiguity, even same-file exec.
		// Name bytes are never copied, formatted, scanned or passed outside this view.
		if v.u16(4)&(1<<13) != 0 {
			return SanitizedEvent{}, false, ErrTargetIdentity
		}
		return SanitizedEvent{}, false, nil
	case perfRecordFork, perfRecordExit:
		if v.len() != 56 {
			return SanitizedEvent{}, false, ErrRingMalformed
		}
		return SanitizedEvent{}, false, ErrThreadCoverageChanged
	default:
		return SanitizedEvent{}, false, ErrRingMalformed
	}
}
