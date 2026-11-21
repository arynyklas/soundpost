//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"os"
	"reflect"
	"syscall"
	"testing"
)

// 04.02-C16 mutation battery re-run (mut0402, X-acq-builds-unassigned and G040): the GNU build IDs the operator approved for a
// process are the only identities a mapping announcement may carry out of a ring's decoder (Ring.builds). Both acquisitions
// have to hand every thread ring the approved builds of that thread's own process: a ring without them decodes every
// announcement as unapproved. The decoder side is tested with hand-built rings; the assignment itself is only visible on a
// real acquisition of a real target.

func realAcquisitionRig(t *testing.T, mode CaptureMode) (AuthorizedTargets, *Reservation, Config) {
	t.Helper()
	_, target, authorized := idleTarget(t)
	authorized.mode = mode
	cfg := DefaultConfig(1)
	cpus, e := OnlineCPUs()
	if e != nil {
		t.Skip(e)
	}
	var limit syscall.Rlimit
	syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit)
	ents, _ := os.ReadDir("/proc/self/fd")
	lease, e := NewResourceBudget().Reserve(authorized, cfg, Topology{CPUs: uint64(len(cpus)), FDLimit: limit.Cur, OpenFDs: uint64(len(ents)), PageBytes: uint64(os.Getpagesize()), LockBytes: perfLockBytes(uint64(len(cpus)))}, MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { lease.Close() })
	if len(target.AllowedBuildIDs) == 0 {
		t.Fatal("the idle target has no approved build ID")
	}
	return authorized, lease, cfg
}

func skipWithoutPerf(t *testing.T, e error) {
	t.Helper()
	var capability *CapabilityError
	if errors.As(e, &capability) {
		t.Skipf("native capture is not available here: %v", e)
	}
	if e != nil {
		t.Fatal(e)
	}
}

func TestCPUAcquisitionHandsEveryRingTheBuildsApprovedForItsProcess(t *testing.T) {
	authorized, lease, cfg := realAcquisitionRig(t, ModeCPU)
	src, e := NewCPUAcquisition(context.Background(), authorized, cfg, lease)
	skipWithoutPerf(t, e)
	defer src.Close()
	cs := src.(*cpuSource)
	if len(cs.rings) == 0 {
		t.Fatal("the acquisition opened no ring")
	}
	want := authorized.targets[0].AllowedBuildIDs
	for _, ring := range cs.rings {
		if !reflect.DeepEqual(ring.builds, want) {
			t.Errorf("ring of thread %d: builds %v, want the approved %v", ring.task.TID, ring.builds, want)
		}
		if len(ring.builds) > 0 && &ring.builds[0] == &authorized.targets[0].AllowedBuildIDs[0] {
			t.Errorf("ring of thread %d shares the approved build slice of the capability", ring.task.TID)
		}
	}
}

func TestSchedulerAcquisitionHandsEveryThreadRingTheBuildsApprovedForItsProcess(t *testing.T) {
	authorized, lease, cfg := realAcquisitionRig(t, ModeCPUOffCPU)
	src, e := NewNativeAcquisition(context.Background(), authorized, cfg, lease)
	skipWithoutPerf(t, e)
	defer src.Close()
	s, ok := src.(*schedulerSource)
	if !ok {
		t.Fatalf("an off-CPU acquisition is a %T", src)
	}
	if len(s.cpu.rings) == 0 {
		t.Fatal("the acquisition opened no thread ring")
	}
	want := authorized.targets[0].AllowedBuildIDs
	for _, ring := range s.cpu.rings {
		if !reflect.DeepEqual(ring.builds, want) {
			t.Errorf("thread ring of thread %d: builds %v, want the approved %v", ring.task.TID, ring.builds, want)
		}
	}
}

// approvedBuilds answers for the process it is asked about and for no other (P-X-approved-builds-any-tgid), and hands out a
// copy the ring may keep.
func TestApprovedBuildsAreTheBuildsOfTheAskedProcessOnly(t *testing.T) {
	a := AuthorizedTargets{targets: []Target{
		{TGID: 10, AllowedBuildIDs: []string{"aa", "ab"}},
		{TGID: 20, AllowedBuildIDs: []string{"bb"}},
	}}
	if got := a.approvedBuilds(10); !reflect.DeepEqual(got, []string{"aa", "ab"}) {
		t.Errorf("process 10: %v", got)
	}
	got := a.approvedBuilds(20)
	if !reflect.DeepEqual(got, []string{"bb"}) {
		t.Errorf("process 20: %v", got)
	}
	got[0] = "tampered"
	if a.targets[1].AllowedBuildIDs[0] != "bb" {
		t.Error("the ring's copy aliases the capability's build IDs")
	}
	if got := a.approvedBuilds(30); len(got) != 0 {
		t.Errorf("a process that is not a target was handed builds: %v", got)
	}
}
