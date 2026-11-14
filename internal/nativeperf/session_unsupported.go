//go:build !linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"runtime"
)

func Probe(ctx context.Context, targets []Target) (Capabilities, error) {
	c := Capabilities{Kernel: runtime.GOOS, Config: "unmeasured", Arch: runtime.GOARCH, CPU: Unsupported, OffCPU: Unsupported, RunqueueSplit: Unsupported, Reasons: []Reason{ReasonPlatform}, FrameCoverage: Coverage{Reasons: []Reason{ReasonUnmeasured}}, ThreadCoverage: Coverage{Reasons: []Reason{ReasonUnmeasured}}, Permissions: Permissions{CPUEventOpen: Unsupported, SchedulerEventOpen: Unsupported}}
	if err := ctx.Err(); err != nil {
		return c, err
	}
	if len(targets) > 0 {
		if err := validateTargets(targets); err != nil {
			return c, err
		}
	}
	return c, &CapabilityError{Unsupported, ReasonPlatform}
}
func Open(ctx context.Context, targets []Target, cfg Config) (*Session, error) {
	_, err := Probe(ctx, targets)
	return nil, err
}
func ResolveLocalTarget(pid int) (Target, error) {
	return Target{}, &CapabilityError{Unsupported, ReasonPlatform}
}
