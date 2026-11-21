// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package model

import "encoding/json"

// Native evidence never carries instruction addresses, mapped paths or stack bytes.
// Period's unit is independent of CPU observation Count and scheduler elapsed time.
type ProfileNativeDomain struct {
	HostID string `json:"host_id"`
	BootID string `json:"boot_id"`
}
type ProfileNativeTask struct {
	BootID       string   `json:"boot_id"`
	PIDNamespace Uint64   `json:"pid_namespace"`
	TGID         uint32   `json:"tgid"`
	TID          uint32   `json:"tid"`
	ProcessStart MonoNano `json:"process_start_ns"`
	Generation   Uint64   `json:"generation"`
}
type ProfileNativeSample struct {
	Task             ProfileNativeTask `json:"task"`
	Method           string            `json:"method"`
	Unit             string            `json:"unit"`
	RequestedHz      uint32            `json:"requested_hz"`
	Period           Uint64            `json:"period"`
	Truncation       string            `json:"truncation,omitempty"`
	Coverage         string            `json:"coverage,omitempty"`
	ThrottleReason   string            `json:"throttle_reason,omitempty"`
	ThrottleEventID  Uint64            `json:"throttle_event_id,omitempty"`
	ThrottleStreamID Uint64            `json:"throttle_stream_id,omitempty"`
}
type ProfileNativeLoss struct {
	At               MonoNano `json:"at_ns"`
	CPU              uint32   `json:"cpu"`
	Count            Uint64   `json:"count"`
	Reason           string   `json:"reason"`
	ThrottleEventID  Uint64   `json:"throttle_event_id,omitempty"`
	ThrottleStreamID Uint64   `json:"throttle_stream_id,omitempty"`
}

func nativeLossValid(v ProfileNativeLoss) bool {
	switch v.Reason {
	case "records_lost", "samples_lost":
		return v.Count > 0 && v.ThrottleEventID == 0 && v.ThrottleStreamID == 0
	case "throttled", "unthrottled":
		return v.Count == 0 && v.ThrottleEventID > 0 && v.ThrottleStreamID > 0
	}
	return false
}
func nativeProfileIdentity(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
func nativeProfileTask(k ProfileNativeTask, d ProfileNativeDomain) bool {
	return k.BootID == d.BootID && k.PIDNamespace != 0 && k.TGID != 0 && k.TID != 0 && k.ProcessStart != 0 && k.Generation != 0
}
func nativeProfileReason(s string) bool {
	return oneOf(s, "platform_unsupported", "permission_denied", "tracefs_unavailable", "event_unavailable", "coverage_unmeasured", "acquisition_pending", "callchain_truncated", "records_lost", "generation_changed", "clock_uncertain", "frame_unresolved", "missing_switch_callchain", "missing_callchain", "throttled", "unthrottled", "samples_lost")
}
func nativeFrameReason(s string) bool {
	return oneOf(s, "frame_unresolved", "missing_frame_pointer_or_callchain", "callchain_truncated", "build_not_approved", "deleted_executable", "generation_changed", "jit_or_anonymous_map_unavailable", "jit_map_expired", "artifact_unavailable", "artifact_denied", "invalid_elf_artifact")
}
func nativeModuleIdentity(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func nativeFunctionIdentity(s string) bool {
	if len(s) == 0 || len(s) > 256 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '$' || c == '@' || c == ':') {
			return false
		}
	}
	return true
}
func validateNativeProfile(c *ProfileChunk) error {
	d := c.NativeDomain
	if d == nil {
		if c.PolicyRevision != 0 || c.Sequence != 0 || c.Complete || len(c.NativeCapabilities) != 0 || len(c.NativeLoss) != 0 {
			return Fail(Invalid)
		}
		for _, s := range c.Samples {
			if s.Native != nil {
				return Fail(Invalid)
			}
		}
		for _, i := range c.Intervals {
			if i.NativeTask != nil || i.Unit != "" || i.Reason != "" || i.Correction {
				return Fail(Invalid)
			}
		}
		return nil
	}
	if !nativeProfileIdentity(d.HostID) || !nativeProfileIdentity(d.BootID) || c.PolicyRevision == 0 || c.Sequence == 0 || !oneOf(c.Method, "native_cpu", "native_offcpu") || c.Method == "native_cpu" && c.Units != "samples" || c.Method == "native_offcpu" && (c.Units != "nanoseconds" || len(c.Samples) != 0) {
		return Fail(Invalid)
	}
	if len(c.NativeCapabilities) != 3 {
		return Fail(Invalid)
	}
	seen := map[ID]bool{}
	for _, id := range c.NativeCapabilities {
		if id == (ID{}) || seen[id] {
			return Fail(Invalid)
		}
		seen[id] = true
	}
	if !seen[c.Capability] {
		return Fail(Invalid)
	}
	if len(c.NativeLoss) > 256 {
		return Fail(Invalid)
	}
	var lost uint64
	for _, v := range c.NativeLoss {
		if !nativeLossValid(v) || uint64(v.Count) > ^uint64(0)-lost {
			return Fail(Invalid)
		}
		lost += uint64(v.Count)
	}
	for _, f := range c.Frames {
		if f.Module == "" {
			if f.Offset != 0 || f.Function != "" || f.Artifact != "" || !nativeFrameReason(f.Reason) {
				return Fail(Invalid)
			}
		} else if !nativeModuleIdentity(f.Module) || f.Function != "" && !nativeFunctionIdentity(f.Function) || f.Reason != "" && !nativeFrameReason(f.Reason) {
			return Fail(Invalid)
		}
		if f.Artifact != "" {
			id, e := ParseID(f.Artifact)
			if e != nil || id == (ID{}) {
				return Fail(Invalid)
			}
		}
	}
	for _, s := range c.Samples {
		n := s.Native
		if n == nil || !nativeProfileTask(n.Task, *d) || s.Thread != Uint64(n.Task.TID) || s.Count != 1 || n.RequestedHz != 99 || n.Period == 0 || n.Method == "software_cpu_clock" && n.Unit != "cpu_clock_nanoseconds" || n.Method == "hardware_cycles" && n.Unit != "hardware_cycles" || !oneOf(n.Method, "software_cpu_clock", "hardware_cycles") || n.Truncation != "" && !oneOf(n.Truncation, "callchain_truncated", "frame_unresolved", "missing_callchain") || n.Coverage != "" && !nativeFrameReason(n.Coverage) {
			return Fail(Invalid)
		}
		if n.ThrottleReason == "" {
			if n.ThrottleEventID != 0 || n.ThrottleStreamID != 0 {
				return Fail(Invalid)
			}
		} else if !oneOf(n.ThrottleReason, "throttled", "unthrottled") || n.ThrottleEventID == 0 || n.ThrottleStreamID == 0 {
			return Fail(Invalid)
		}
	}
	for _, i := range c.Intervals {
		if i.Correction || i.NativeTask == nil || !nativeProfileTask(*i.NativeTask, *d) || i.Thread != Uint64(i.NativeTask.TID) || i.Unit != "nanoseconds" || i.Reason != "" && !nativeProfileReason(i.Reason) || i.Kind == "unknown_offcpu" && i.Reason == "" || i.Censored && i.Reason == "" {
			return Fail(Invalid)
		}
	}
	return nil
}

// Count/time/CPU zero are legal evidence, so presence cannot be inferred from
// decoded Go zero values. Canonical numeric grammar belongs to the leaf scalars.
func (v *ProfileNativeLoss) UnmarshalJSON(b []byte) error {
	type wire ProfileNativeLoss
	var value wire
	if err := StrictJSON(b, &value); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return Fail(Invalid)
	}
	for _, key := range []string{"at_ns", "cpu", "count", "reason"} {
		if _, ok := fields[key]; !ok {
			return Fail(Invalid)
		}
	}
	*v = ProfileNativeLoss(value)
	return nil
}
