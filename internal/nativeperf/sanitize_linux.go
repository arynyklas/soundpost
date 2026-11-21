//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import "github.com/arynyklas/soundpost/internal/model"

// decodeScheduler reads only allowlisted numeric positions in the borrowed ring.
// TID bookkeeping identifies the waker, not the woken task, and is never exported.
func decodeScheduler(v KernelRecordView, l NumericLayout, a AuthorizedTargets) (SanitizedEvent, bool, error) {
	if !v.valid() || v.u32(0) != perfRecordSample || v.len() < 44 || v.u32(28) != 0 {
		return SanitizedEvent{}, false, ErrRingMalformed
	}
	count := v.u64(32)
	if count > 128 || count > uint64((v.len()-44)/8) {
		return SanitizedEvent{}, false, ErrRingMalformed
	}
	raw := 44 + int(count)*8
	size := int(v.u32(raw - 4))
	if size < l.rawSize || raw+size > v.len() || v.len()-(raw+size) > 7 {
		return SanitizedEvent{}, false, ErrRingMalformed
	}
	task := func(pid uint32) *TaskKey {
		if pid == 0 || pid > 1<<31-1 {
			return nil
		}
		for _, t := range a.schedulerTasks {
			if t.task.TID == pid {
				key := t.task
				return &key
			}
		}
		return nil
	}
	e := SanitizedEvent{Time: model.MonoNano(v.u64(16)), CPU: v.u32(24)}
	switch l.kind {
	case SchedulerSwitchKind:
		s := &SchedulerSwitch{Previous: task(v.u32(raw + l.prev.offset)), Next: task(v.u32(raw + l.next.offset))}
		if s.Previous == nil && s.Next == nil {
			return SanitizedEvent{}, false, nil
		}
		if s.Previous != nil {
			state := v.u64(raw + l.state.offset)
			s.PreviousState = model.Uint64(state)
			// Linux 6.1/6.6 sched_switch reports TASK_REPORT_MAX (0x100) for
			// preemption, otherwise the TASK_REPORT bitmap including TASK_REPORT_IDLE.
			s.Preempted = state == 0x100
			s.PreviousStateUnknown = (l.kernel != "6.1" && l.kernel != "6.6") || state & ^uint64(0x1ff) != 0 || state&0x100 != 0 && state != 0x100
			s.MissingCallchain = ReasonMissingSwitchCallchain
			context := ContextKernel
			limit := l.maxFrames
			if limit == 0 {
				limit = 127
			}
			truncated := count >= uint64(limit)
			unresolved := false
			for n := uint64(0); n < count; n++ {
				ip := v.u64(40 + int(n)*8)
				if marker, ok := callchainMarker(ip); ok {
					context = marker
					continue
				}
				if context == ContextUser {
					if !safeUserIP(ip) {
						unresolved = true
						continue
					}
					if len(s.SwitchOutCallchain) < int(limit) {
						s.SwitchOutCallchain = append(s.SwitchOutCallchain, CallchainEntry{IP: model.Uint64(ip)})
					} else {
						truncated = true
					}
				}
			}
			if len(s.SwitchOutCallchain) > 0 {
				s.MissingCallchain = ""
				if unresolved {
					s.MissingCallchain = ReasonUnresolved
				}
				if truncated {
					s.MissingCallchain = ReasonTruncated
				}
			}
		}
		e.Kind = EventSwitch
		e.Switch = s
	case SchedulerWakeupKind, SchedulerWakeupNewKind:
		k := task(v.u32(raw + l.pid.offset))
		if k == nil {
			return SanitizedEvent{}, false, nil
		}
		cpu := v.u32(raw + l.cpu.offset)
		if cpu > 1<<31-1 {
			return SanitizedEvent{}, false, ErrRingMalformed
		}
		e.Kind = EventWakeup
		e.Task = *k
		e.Wakeup = &SchedulerWakeup{Target: *k, TargetCPU: cpu}
	default:
		return SanitizedEvent{}, false, ErrInvalid
	}
	return e, true, nil
}
