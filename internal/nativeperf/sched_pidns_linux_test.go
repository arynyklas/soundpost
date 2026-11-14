//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
)

// Scheduler tracepoint records carry INIT-namespace PIDs. Inside any other PID
// namespace (containers without hostPID, WSL2 distributions) the authorized
// task identities can never match, so a scheduler session would succeed and
// stay empty. Task 04.09 measured exactly that on WSL2 (200k real switch
// records, zero attributed); the engine must refuse instead.

func inInitialPIDNamespace(t *testing.T) bool {
	t.Helper()
	info, err := os.Stat("/proc/self/ns/pid")
	if err != nil {
		t.Skip("PID namespace identity unreadable")
	}
	return info.Sys().(*syscall.Stat_t).Ino == initPIDNamespaceInode
}

func TestSchedulerAcquisitionRefusedOutsideInitialPIDNamespace(t *testing.T) {
	if inInitialPIDNamespace(t) {
		t.Skip("initial PID namespace: the refusal path is not reachable here")
	}
	a := AuthorizedTargets{targets: []Target{{TGID: 1, PIDNamespace: 1, ProcessStart: 1}}, mode: ModeCPUOffCPU}
	_, err := newSchedulerAcquisition(context.Background(), a, DefaultConfig(1), &Reservation{})
	var capability *CapabilityError
	if !errors.As(err, &capability) || capability.Status != Unsupported || capability.Reason != ReasonEvent {
		t.Fatalf("scheduler acquisition outside the initial PID namespace returned %v, want unsupported/event_unavailable", err)
	}
}

func TestProbeDoesNotReportSchedulerSupportOutsideInitialPIDNamespace(t *testing.T) {
	if inInitialPIDNamespace(t) {
		t.Skip("initial PID namespace: nothing to refuse")
	}
	target, err := ResolveLocalTarget(os.Getpid())
	if err != nil {
		t.Skip("local target unresolved")
	}
	caps, _ := Probe(context.Background(), []Target{target})
	if caps.OffCPU == Supported || caps.Permissions.SchedulerEventOpen == Supported && caps.OffCPU == Supported {
		t.Fatalf("probe reported scheduler support (%v) although tracepoint PIDs cannot be attributed outside the initial PID namespace", caps.OffCPU)
	}
	if caps.OffCPU == Unsupported {
		found := false
		for _, r := range caps.Reasons {
			found = found || r == ReasonEvent
		}
		if !found {
			t.Fatalf("unsupported scheduler capability without an event_unavailable reason: %v", caps.Reasons)
		}
	}
}
