//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// These independently varied boundary inputs test classification/transport, NOT
// installation of seccomp, effective capability or LSM policies. Those real
// operator-controlled qualification rows remain explicitly not_run.
func TestPerfPermissionDimensions(t *testing.T) {
	for _, dimension := range []string{"seccomp", "host-capability", "lsm"} {
		t.Run(dimension+"-unknown-denying-layer", func(t *testing.T) {
			status, reason := probeStatus(&os.SyscallError{Syscall: "perf_event_open", Err: syscall.EPERM})
			if status != Denied || reason != ReasonPermission {
				t.Fatal(status, reason)
			}
			capability := &CapabilityError{status, reason}
			client, server := cpuSocketPair(t)
			if e := writeMessage(server, helperReply{Error: helperErrorCode(capability)}); e != nil {
				t.Fatal(e)
			}
			_, e := (&socketSource{conn: client}).Next(context.Background())
			var observed *CapabilityError
			if !errors.As(e, &observed) || observed.Status != Denied || observed.Reason != ReasonPermission {
				t.Fatal("denial lost at source boundary", e)
			}
			// CPU denial cannot fabricate denial of the independently permitted scheduler.
			c := Capabilities{CPU: Denied, OffCPU: Supported, RunqueueSplit: Unsupported, Permissions: Permissions{CPUEventOpen: Denied, SchedulerEventOpen: Supported}, FrameCoverage: Coverage{Reasons: []Reason{ReasonUnmeasured}}, ThreadCoverage: Coverage{Reasons: []Reason{ReasonUnmeasured}}, Reasons: []Reason{ReasonPermission}}
			if e = c.Validate(); e != nil {
				t.Fatal(e)
			}
			encoded, e := json.Marshal(c)
			if e != nil {
				t.Fatal(e)
			}
			if bytes.Contains(encoded, []byte(dimension)) {
				t.Fatal("EPERM guessed a denying security layer")
			}
		})
	}
	t.Run("tracefs-metadata-absent-cpu-independent", func(t *testing.T) {
		_, e := readFixedMetadata(filepath.Join(t.TempDir(), "hidden-tracefs", "format"), 65536)
		var capability *CapabilityError
		if !errors.As(e, &capability) || capability.Status != Unsupported || capability.Reason != ReasonEvent {
			t.Fatal("missing tracefs metadata mislabeled permission denial", e)
		}
		cpuStatus, _ := probeStatus(nil)
		if cpuStatus != Supported {
			t.Fatal("tracefs absence changed independent CPU permission")
		}
		client, server := cpuSocketPair(t)
		if e = writeMessage(server, helperReply{Error: helperErrorCode(capability)}); e != nil {
			t.Fatal(e)
		}
		_, e = (&socketSource{conn: client}).Next(context.Background())
		if !errors.As(e, &capability) || capability.Status != Unsupported {
			t.Fatal(e)
		}
	})
	t.Run("target-visibility-refused-before-perf", func(t *testing.T) {
		// A nonexistent proc identity is a real metadata-boundary failure, not an
		// actual PID-namespace isolation qualification or a hostPID fallback.
		target := Target{TGID: ^uint32(0), PIDNamespace: 1, ProcessStart: 1, CgroupID: 1, AllowedBuildIDs: []string{"01"}}
		handle, e := openCheckedTarget(target)
		if handle != nil || !errors.Is(e, ErrTargetIdentity) {
			t.Fatal("invisible target accepted", e)
		}
		lease, e := NewResourceBudget().Reserve(AuthorizedTargets{targets: []Target{target}, mode: ModeCPU}, DefaultConfig(1), Topology{CPUs: 1, FDLimit: 1024, PageBytes: uint64(os.Getpagesize())}, MemoryUsage{})
		if e != nil {
			t.Fatal(e)
		}
		defer lease.Close()
		source, e := NewCPUAcquisition(context.Background(), AuthorizedTargets{targets: []Target{target}, mode: ModeCPU}, DefaultConfig(1), lease)
		if source != nil || !errors.Is(e, ErrTargetIdentity) || len(lease.owned) != 0 {
			t.Fatal("target refusal opened perf resources", e)
		}
	})
}
