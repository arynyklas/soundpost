// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"soundpost/internal/model"
	"strings"
)

var ErrInvalid = errors.New("invalid native record")

var (
	ErrTooManyTargets = errors.New("native target count exceeded")
	ErrResourceBudget = errors.New("native resource budget exceeded")
	ErrTargetIdentity = errors.New("invalid native target identity")
)

type Target struct {
	CgroupID        model.Uint64   `json:"cgroup_id"`
	PIDNamespace    model.Uint64   `json:"pid_namespace"`
	TGID            uint32         `json:"tgid"`
	ProcessStart    model.MonoNano `json:"process_start"`
	AllowedBuildIDs []string       `json:"allowed_build_ids,omitempty"`
}

func validBuild(s string) bool {
	if len(s) < 2 || len(s) > 128 || len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (t Target) Validate() error {
	if t.PIDNamespace == 0 || t.TGID == 0 || t.ProcessStart == 0 || len(t.AllowedBuildIDs) > 256 {
		return ErrTargetIdentity
	}
	for _, id := range t.AllowedBuildIDs {
		if !validBuild(id) {
			return ErrInvalid
		}
	}
	return nil
}

type ClockDomain struct {
	HostID string `json:"host_id"`
	BootID string `json:"boot_id"`
}

func (d ClockDomain) valid() bool { return safeIdentity(d.HostID) && safeIdentity(d.BootID) }
func safeIdentity(s string) bool {
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

type TaskKey struct {
	BootID       string         `json:"boot_id"`
	PIDNamespace model.Uint64   `json:"pid_namespace"`
	TGID         uint32         `json:"tgid"`
	TID          uint32         `json:"tid"`
	ProcessStart model.MonoNano `json:"process_start"`
	Generation   model.Uint64   `json:"generation"`
}

func (k TaskKey) valid(d ClockDomain) bool {
	return k.BootID == d.BootID && k.PIDNamespace != 0 && k.TGID != 0 && k.TID != 0 && k.ProcessStart != 0 && k.Generation != 0
}

// ProcessKey binds process-scoped mappings without inventing a thread identity.
type ProcessKey struct {
	BootID       string         `json:"boot_id"`
	PIDNamespace model.Uint64   `json:"pid_namespace"`
	TGID         uint32         `json:"tgid"`
	ProcessStart model.MonoNano `json:"process_start"`
	Generation   model.Uint64   `json:"generation"`
}

func (k ProcessKey) valid(d ClockDomain) bool {
	return k.BootID == d.BootID && k.PIDNamespace != 0 && k.TGID != 0 && k.ProcessStart != 0 && k.Generation != 0
}

type EventKind string

const (
	EventCPU        EventKind = "cpu_sample"
	EventSwitch     EventKind = "scheduler_switch"
	EventWakeup     EventKind = "scheduler_wakeup"
	EventMapping    EventKind = "mapping_update"
	EventLoss       EventKind = "loss"
	EventGeneration EventKind = "target_generation"
)

type SamplingMethod string

const (
	MethodSoftwareCPUClock SamplingMethod = "software_cpu_clock"
	MethodHardwareCycles   SamplingMethod = "hardware_cycles"
)

type CallchainContext string

const (
	ContextHypervisor  CallchainContext = "hypervisor"
	ContextKernel      CallchainContext = "kernel"
	ContextUser        CallchainContext = "user"
	ContextGuest       CallchainContext = "guest"
	ContextGuestKernel CallchainContext = "guest_kernel"
	ContextGuestUser   CallchainContext = "guest_user"
)

// A context marker is never an instruction address. The decoder translates
// documented PERF_CONTEXT sentinels into these closed markers before export.
type CallchainEntry struct {
	IP      model.Uint64     `json:"ip,omitempty"`
	Context CallchainContext `json:"context,omitempty"`
}

func (c CallchainEntry) valid() bool {
	if c.Context != "" {
		if c.IP != 0 {
			return false
		}
		switch c.Context {
		case ContextHypervisor, ContextKernel, ContextUser, ContextGuest, ContextGuestKernel, ContextGuestUser:
			return true
		}
		return false
	}
	return c.IP != 0 && uint64(c.IP) < ^uint64(4094)
}

type ThrottleEvidence struct {
	Reason   Reason       `json:"reason"`
	EventID  model.Uint64 `json:"event_id"`
	StreamID model.Uint64 `json:"stream_id"`
}

func (t ThrottleEvidence) valid() bool {
	return (t.Reason == ReasonThrottle || t.Reason == ReasonUnthrottle) && t.EventID != 0 && t.StreamID != 0
}

type CPUSample struct {
	IP          model.Uint64      `json:"ip"`
	Callchain   []CallchainEntry  `json:"callchain"`
	Method      SamplingMethod    `json:"method"`
	Unit        Unit              `json:"unit"`
	RequestedHz uint32            `json:"requested_hz"`
	Period      model.Uint64      `json:"period"`
	Truncated   Reason            `json:"truncated,omitempty"`
	Throttle    *ThrottleEvidence `json:"throttle,omitempty"`
}

func (s CPUSample) valid() bool {
	if s.IP == 0 || uint64(s.IP) >= ^uint64(4094) || len(s.Callchain) > 128 || s.RequestedHz != 99 || s.Period == 0 || !s.Truncated.callchainReason() || s.Truncated == ReasonMissingSwitchCallchain {
		return false
	}
	if s.Method == MethodSoftwareCPUClock {
		if s.Unit != UnitCPUClockNanoseconds {
			return false
		}
	} else if s.Method == MethodHardwareCycles {
		if s.Unit != UnitHardwareCycles {
			return false
		}
	} else {
		return false
	}
	if len(s.Callchain) == 0 && s.Truncated == "" {
		return false
	}
	for _, entry := range s.Callchain {
		if !entry.valid() {
			return false
		}
	}
	return s.Throttle == nil || s.Throttle.valid()
}

type SchedulerSwitch struct {
	// Nil participants are idle/foreign and intentionally have no exported identity.
	Previous             *TaskKey         `json:"previous,omitempty"`
	Next                 *TaskKey         `json:"next,omitempty"`
	PreviousState        model.Uint64     `json:"previous_state"`
	PreviousStateUnknown bool             `json:"previous_state_unknown,omitempty"`
	Preempted            bool             `json:"preempted"`
	SwitchOutCallchain   []CallchainEntry `json:"switch_out_callchain,omitempty"`
	MissingCallchain     Reason           `json:"missing_callchain,omitempty"`
}
type SchedulerWakeup struct {
	Target    TaskKey `json:"target"`
	TargetCPU uint32  `json:"target_cpu"`
}
type MappingUpdate struct {
	Process    ProcessKey   `json:"process"`
	Start      model.Uint64 `json:"start"`
	End        model.Uint64 `json:"end"`
	FileOffset model.Uint64 `json:"file_offset"`
	BuildID    string       `json:"build_id"`
}
type LossEvent struct {
	Count    model.Uint64      `json:"count"`
	Reason   Reason            `json:"reason"`
	Throttle *ThrottleEvidence `json:"throttle,omitempty"`
}

func (l LossEvent) valid() bool {
	switch l.Reason {
	case ReasonLoss, ReasonSampleLost:
		return l.Count > 0 && l.Throttle == nil
	case ReasonThrottle, ReasonUnthrottle:
		return l.Count == 0 && l.Throttle != nil && l.Throttle.valid() && l.Throttle.Reason == l.Reason
	default:
		return false
	}
}

type TargetGeneration struct {
	Previous model.Uint64 `json:"previous"`
	Current  model.Uint64 `json:"current"`
}
type SanitizedEvent struct {
	Kind       EventKind         `json:"kind"`
	Time       model.MonoNano    `json:"time"`
	CPU        uint32            `json:"cpu"`
	Sequence   model.Uint64      `json:"sequence"`
	Domain     ClockDomain       `json:"domain"`
	Task       TaskKey           `json:"task"`
	CPUEvent   *CPUSample        `json:"cpu_sample,omitempty"`
	Switch     *SchedulerSwitch  `json:"scheduler_switch,omitempty"`
	Wakeup     *SchedulerWakeup  `json:"scheduler_wakeup,omitempty"`
	Mapping    *MappingUpdate    `json:"mapping_update,omitempty"`
	Loss       *LossEvent        `json:"loss,omitempty"`
	Generation *TargetGeneration `json:"target_generation,omitempty"`
}

func (e SanitizedEvent) Validate() error {
	if e.Sequence == 0 || !e.Domain.valid() {
		return ErrInvalid
	}
	n := 0
	for _, v := range []bool{e.CPUEvent != nil, e.Switch != nil, e.Wakeup != nil, e.Mapping != nil, e.Loss != nil, e.Generation != nil} {
		if v {
			n++
		}
	}
	if n != 1 {
		return ErrInvalid
	}
	switch e.Kind {
	case EventCPU:
		if e.CPUEvent == nil || !e.Task.valid(e.Domain) || !e.CPUEvent.valid() {
			return ErrInvalid
		}
	case EventSwitch:
		if e.Switch == nil || e.Task != (TaskKey{}) || e.Switch.Previous == nil && e.Switch.Next == nil || e.Switch.Previous != nil && !e.Switch.Previous.valid(e.Domain) || e.Switch.Next != nil && !e.Switch.Next.valid(e.Domain) {
			return ErrInvalid
		}
		s := e.Switch
		if len(s.SwitchOutCallchain) > 128 || !s.MissingCallchain.callchainReason() {
			return ErrInvalid
		}
		if s.Previous == nil && (len(s.SwitchOutCallchain) != 0 || s.MissingCallchain != "" || s.PreviousState != 0 || s.Preempted || s.PreviousStateUnknown) {
			return ErrInvalid
		}
		if s.Previous != nil && len(s.SwitchOutCallchain) == 0 && s.MissingCallchain != ReasonMissingSwitchCallchain {
			return ErrInvalid
		}
		if len(s.SwitchOutCallchain) != 0 && s.MissingCallchain == ReasonMissingSwitchCallchain {
			return ErrInvalid
		}
		for _, entry := range s.SwitchOutCallchain {
			if !entry.valid() {
				return ErrInvalid
			}
		}
	case EventWakeup:
		if e.Wakeup == nil || !e.Task.valid(e.Domain) || e.Wakeup.Target != e.Task || !e.Wakeup.Target.valid(e.Domain) {
			return ErrInvalid
		}
	case EventMapping:
		if e.Mapping == nil || e.Task != (TaskKey{}) || !e.Mapping.Process.valid(e.Domain) || e.Mapping.End <= e.Mapping.Start || !validBuild(e.Mapping.BuildID) {
			return ErrInvalid
		}
	case EventLoss:
		if e.Loss == nil || e.Task != (TaskKey{}) || !e.Loss.valid() {
			return ErrInvalid
		}
	case EventGeneration:
		if e.Generation == nil || !e.Task.valid(e.Domain) || e.Generation.Current != e.Task.Generation || e.Generation.Current <= e.Generation.Previous {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func (e *SanitizedEvent) UnmarshalJSON(b []byte) error {
	if len(b) > 64<<10 {
		return ErrInvalid
	}
	type wire SanitizedEvent
	var v wire
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&v); err != nil {
		return ErrInvalid
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	out := SanitizedEvent(v)
	if err := out.Validate(); err != nil {
		return err
	}
	*e = out
	return nil
}

type Unit string

const (
	UnitEngineSamples       Unit = "engine_samples"
	UnitNativeSamples       Unit = "native_samples"
	UnitNanoseconds         Unit = "nanoseconds"
	UnitCPUClockNanoseconds Unit = "cpu_clock_nanoseconds"
	UnitHardwareCycles      Unit = "hardware_cycles"
)

type Measure struct {
	Unit  Unit         `json:"unit"`
	Value model.Uint64 `json:"value"`
}

func (m Measure) Add(n Measure) (Measure, error) {
	if m.Unit != n.Unit || !strings.Contains("|engine_samples|native_samples|nanoseconds|", "|"+string(m.Unit)+"|") || m.Value > math.MaxUint64-n.Value {
		return Measure{}, ErrInvalid
	}
	return Measure{m.Unit, m.Value + n.Value}, nil
}

type IntervalKind string

const (
	IntervalCPU      IntervalKind = "sampled_on_cpu"
	IntervalBlocked  IntervalKind = "blocked"
	IntervalRunnable IntervalKind = "runnable_delay"
	IntervalUnknown  IntervalKind = "unknown_split"
	IntervalCensored IntervalKind = "censored"
)

type Interval struct {
	Kind    IntervalKind   `json:"kind"`
	Task    TaskKey        `json:"task"`
	Domain  ClockDomain    `json:"domain"`
	Start   model.MonoNano `json:"start"`
	End     model.MonoNano `json:"end"`
	Measure Measure        `json:"measure"`
	Reason  Reason         `json:"reason,omitempty"`
	// Only the scheduler switch-out may supply this optional stack. A later CPU
	// sample cannot decorate an off-CPU interval.
	SwitchOutCallchain []CallchainEntry `json:"switch_out_callchain,omitempty"`
	MissingCallchain   Reason           `json:"missing_callchain,omitempty"`
	// Correction is NONADDITIVE coverage replacement for [Start,End), scoped to
	// this profile/session and Domain. A zero Task covers all authorized tasks.
	// Consumers must invalidate overlapping scheduler intervals and split any
	// straddling interval before aggregation; never sum this span as measured time.
	Correction bool `json:"correction,omitempty"`
}

func (i Interval) Validate() error {
	if !i.Domain.valid() || i.End < i.Start || !i.Reason.validOptional() {
		return ErrInvalid
	}
	if i.Correction {
		if i.Task != (TaskKey{}) && !i.Task.valid(i.Domain) || i.Kind != IntervalUnknown || i.Reason == "" || i.Measure.Unit != UnitNanoseconds || i.Measure.Value != model.Uint64(i.End-i.Start) || len(i.SwitchOutCallchain) != 0 || i.MissingCallchain != "" {
			return ErrInvalid
		}
		return nil
	}
	if !i.Task.valid(i.Domain) || len(i.SwitchOutCallchain) > 128 || !i.MissingCallchain.callchainReason() {
		return ErrInvalid
	}
	if len(i.SwitchOutCallchain) == 0 && i.MissingCallchain != "" && i.MissingCallchain != ReasonMissingSwitchCallchain || len(i.SwitchOutCallchain) != 0 && i.MissingCallchain == ReasonMissingSwitchCallchain {
		return ErrInvalid
	}
	for _, entry := range i.SwitchOutCallchain {
		if !entry.valid() {
			return ErrInvalid
		}
	}
	switch i.Kind {
	case IntervalCPU:
		if i.Measure.Unit != UnitNativeSamples || i.Measure.Value == 0 || len(i.SwitchOutCallchain) != 0 || i.MissingCallchain != "" {
			return ErrInvalid
		}
	case IntervalBlocked, IntervalRunnable:
		if i.Measure.Unit != UnitNanoseconds || i.Measure.Value != model.Uint64(i.End-i.Start) {
			return ErrInvalid
		}
	case IntervalUnknown, IntervalCensored:
		if i.Measure.Unit != UnitNanoseconds || i.Measure.Value != model.Uint64(i.End-i.Start) || i.Reason == "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// ProfileChunk is session assembly input, not a parallel ingest envelope; C04 owns export.
type ProfileChunk struct {
	ProfileID      model.ID         `json:"profile_id"`
	PolicyRevision model.Revision   `json:"policy_revision"`
	Domain         ClockDomain      `json:"domain"`
	Events         []SanitizedEvent `json:"events"`
	Intervals      []Interval       `json:"intervals"`
}
