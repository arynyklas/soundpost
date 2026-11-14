// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/model"
)

type Status string

const (
	Supported   Status = "supported"
	Denied      Status = "denied"
	Unsupported Status = "unsupported"
	Error       Status = "error"
)

type Reason string

const (
	ReasonPlatform               Reason = "platform_unsupported"
	ReasonPermission             Reason = "permission_denied"
	ReasonTraceFS                Reason = "tracefs_unavailable"
	ReasonEvent                  Reason = "event_unavailable"
	ReasonUnmeasured             Reason = "coverage_unmeasured"
	ReasonAcquisition            Reason = "acquisition_pending"
	ReasonTruncated              Reason = "callchain_truncated"
	ReasonLoss                   Reason = "records_lost"
	ReasonGeneration             Reason = "generation_changed"
	ReasonClock                  Reason = "clock_uncertain"
	ReasonUnresolved             Reason = "frame_unresolved"
	ReasonMissingSwitchCallchain Reason = "missing_switch_callchain"
	ReasonMissingCallchain       Reason = "missing_callchain"
	ReasonThrottle               Reason = "throttled"
	ReasonUnthrottle             Reason = "unthrottled"
	ReasonSampleLost             Reason = "samples_lost"
)

func (r Reason) valid() bool {
	switch r {
	case ReasonPlatform, ReasonPermission, ReasonTraceFS, ReasonEvent, ReasonUnmeasured, ReasonAcquisition, ReasonTruncated, ReasonLoss, ReasonGeneration, ReasonClock, ReasonUnresolved, ReasonMissingSwitchCallchain, ReasonMissingCallchain, ReasonThrottle, ReasonUnthrottle, ReasonSampleLost:
		return true
	}
	return false
}
func (r Reason) validOptional() bool { return r == "" || r.valid() }

func (r Reason) callchainReason() bool {
	return r == "" || r == ReasonTruncated || r == ReasonUnresolved || r == ReasonMissingSwitchCallchain || r == ReasonMissingCallchain
}
func (s Status) valid() bool { return s == Supported || s == Denied || s == Unsupported || s == Error }
func (c Coverage) Validate() error {
	if len(c.Reasons) > 16 || (!c.Measured && (c.Observed != 0 || c.Eligible != 0)) || c.Measured && c.Observed > c.Eligible {
		return ErrInvalid
	}
	unmeasured := false
	for _, r := range c.Reasons {
		if !r.valid() {
			return ErrInvalid
		}
		if r == ReasonUnmeasured {
			unmeasured = true
		}
	}
	if unmeasured == c.Measured {
		return ErrInvalid
	}
	return nil
}

type Coverage struct {
	Measured bool         `json:"measured"`
	Observed model.Uint64 `json:"observed"`
	Eligible model.Uint64 `json:"eligible"`
	Reasons  []Reason     `json:"reasons"`
}
type Permissions struct {
	PerfEventParanoid     *int   `json:"perf_event_paranoid,omitempty"`
	EffectiveCapabilities string `json:"effective_capabilities,omitempty"`
	CPUEventOpen          Status `json:"cpu_event_open"`
	SchedulerEventOpen    Status `json:"scheduler_event_open"`
}
type Capabilities struct {
	Kernel         string      `json:"kernel"`
	Config         string      `json:"config"`
	Arch           string      `json:"arch"`
	Permissions    Permissions `json:"permissions"`
	FrameCoverage  Coverage    `json:"frame_coverage"`
	ThreadCoverage Coverage    `json:"thread_coverage"`
	CPU            Status      `json:"cpu"`
	OffCPU         Status      `json:"off_cpu"`
	RunqueueSplit  Status      `json:"runqueue_split"`
	Reasons        []Reason    `json:"reasons"`
}

func (c Capabilities) Validate() error {
	for _, s := range []Status{c.CPU, c.OffCPU, c.RunqueueSplit, c.Permissions.CPUEventOpen, c.Permissions.SchedulerEventOpen} {
		if !s.valid() {
			return ErrInvalid
		}
	}
	if c.FrameCoverage.Validate() != nil || c.ThreadCoverage.Validate() != nil || len(c.Reasons) > 16 {
		return ErrInvalid
	}
	for _, r := range c.Reasons {
		if !r.valid() {
			return ErrInvalid
		}
	}
	if c.RunqueueSplit == Supported && c.OffCPU != Supported {
		return ErrInvalid
	}
	return nil
}

type CapabilityError struct {
	Status Status
	Reason Reason
}

func (e *CapabilityError) Error() string {
	return "native profiling: " + string(e.Status) + ": " + string(e.Reason)
}

var ErrAcquisitionPending = errors.New("native acquisition requires task04.02 authorization and task04.03 perf helper/rings")

// EventSource is the owned sanitized ring interface implemented by acquisition.
type EventSource interface {
	Next(context.Context) (SanitizedEvent, error)
	Close() error
}
type Session struct{ source EventSource }

func (s *Session) Next(ctx context.Context) (SanitizedEvent, error) {
	if err := ctx.Err(); err != nil {
		return SanitizedEvent{}, err
	}
	if s == nil || s.source == nil {
		return SanitizedEvent{}, ErrAcquisitionPending
	}
	return s.source.Next(ctx)
}
func (s *Session) Close() error {
	if s == nil || s.source == nil {
		return nil
	}
	return s.source.Close()
}
func validateTargets(targets []Target) error {
	if len(targets) == 0 {
		return ErrTargetIdentity
	}
	if len(targets) > 64 {
		return ErrTooManyTargets
	}
	for _, t := range targets {
		if err := t.Validate(); err != nil {
			return err
		}
	}
	return nil
}
