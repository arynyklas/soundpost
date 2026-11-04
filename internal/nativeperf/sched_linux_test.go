//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

func TestSchedulerUnknownStateSplit(t *testing.T) {
	c := configuredCorrelation(t, 0)
	out := correlationOut(0, false)
	out.Switch.PreviousState = 1 << 40
	out.Switch.PreviousStateUnknown = true
	feedCorrelation(t, c, out, correlationWake(40000000), correlationIn(55000000))
	got := drainCorrelation(t, c, []uint32{0}, 55000000)
	if len(got) != 1 || got[0].Kind != IntervalUnknown || got[0].Measure.Value != 55000000 {
		t.Fatal(got)
	}
}
func TestSchedulerStateTables(t *testing.T) {
	for _, kernel := range []string{"6.1", "6.6"} {
		for _, state := range []uint64{0, 1, 2, 0x80, 0x100, 0x101, 0x200, 1 << 63} {
			l, e := parseTraceFormat(SchedulerSwitchKind, schedulerFormat(SchedulerSwitchKind))
			if e != nil {
				t.Fatal(e)
			}
			l.kernel = kernel
			b := make([]byte, 104)
			binary.LittleEndian.PutUint32(b, 9)
			binary.LittleEndian.PutUint16(b[6:], 104)
			binary.LittleEndian.PutUint32(b[40:], 60)
			binary.LittleEndian.PutUint32(b[68:], 7)
			binary.LittleEndian.PutUint64(b[76:], state)
			a := AuthorizedTargets{schedulerTasks: []cpuThread{{task: TaskKey{TID: 7}}}}
			ev, ok, e := decodeScheduler(KernelRecordView{first: b}, l, a)
			if e != nil || !ok {
				t.Fatal(e)
			}
			unknown := state == 0x101 || state >= 0x200
			if ev.Switch.PreviousStateUnknown != unknown || ev.Switch.Preempted != (state == 0x100) {
				t.Fatal(kernel, state, ev.Switch)
			}
		}
	}
}
func TestSchedulerFinalProofDrainsForeignPrefix(t *testing.T) {
	// No fake kernel success: an independently authored finite borrowed ring is
	// already stopped, so this tests source drain/control behavior only.
	l, e := parseTraceFormat(SchedulerWakeupKind, schedulerFormat(SchedulerWakeupKind))
	if e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 80)
	binary.LittleEndian.PutUint32(b, 9)
	binary.LittleEndian.PutUint16(b[6:], 80)
	binary.LittleEndian.PutUint32(b[40:], 36)
	binary.LittleEndian.PutUint32(b[68:], 999)
	r := &Ring{meta: make([]byte, 4096), data: b}
	binary.LittleEndian.PutUint64(r.meta[1024:], 80)
	s := &schedulerSource{done: make(chan struct{}), cpu: &cpuSource{domain: correlationDomain}, rings: []schedulerRing{{ring: r, layout: l}}, cpus: []uint32{0}, stopped: true, end: 100}
	item, e := s.NextItem(context.Background())
	if e != nil || item.Proof == nil || !item.Proof.Final || item.Proof.Through != 100 || r.tail() != 80 {
		t.Fatal(item, e, r.tail())
	}
	if _, e = s.NextItem(context.Background()); !errors.Is(e, ErrSourceComplete) {
		t.Fatal(e)
	}
	if _, e = s.Next(context.Background()); !errors.Is(e, ErrProgressRequired) {
		t.Fatal(e)
	}
}
func TestSchedulerCloseCannotFinalize(t *testing.T) {
	s := &schedulerSource{done: make(chan struct{}), cpu: &cpuSource{done: make(chan struct{})}}
	s.Close()
	if _, e := s.NextItem(context.Background()); !errors.Is(e, ErrAcquisitionClosed) {
		t.Fatal(e)
	}
}
func TestSchedulerLossCannotFinalize(t *testing.T) {
	r := &Ring{meta: make([]byte, 4096), data: make([]byte, 64)}
	binary.LittleEndian.PutUint64(r.meta[1024:], 65)
	s := &schedulerSource{done: make(chan struct{}), cpu: &cpuSource{domain: correlationDomain}, rings: []schedulerRing{{ring: r}}, cpus: []uint32{0}, stopped: true, end: 100}
	for range 2 {
		if _, e := s.NextItem(context.Background()); !errors.Is(e, ErrRingOverwrite) {
			t.Fatal(e)
		}
	}
}
func TestSchedulerAllThreeStreamsCharged(t *testing.T) {
	a := AuthorizedTargets{targets: []Target{{TGID: 1, PIDNamespace: 1, ProcessStart: 1}}, mode: ModeCPUOffCPU}
	cfg := DefaultConfig(1)
	r, e := NewResourceBudget().Reserve(a, cfg, Topology{CPUs: 2, FDLimit: 1024, PageBytes: 4096}, MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if r.FDs != 12 {
		t.Fatalf("all 6 scheduler streams plus CPU/metadata/socket required: %d", r.FDs)
	}
	if _, e = NewResourceBudget().Reserve(a, cfg, Topology{CPUs: 85, FDLimit: 1024, PageBytes: 4096}, MemoryUsage{}); !errors.Is(e, ErrResources) {
		t.Fatal("silently omitted CPUs", e)
	}
}
func TestSchedulerExecControlPrecedesPendingExport(t *testing.T) {
	b := make([]byte, 64)
	binary.LittleEndian.PutUint32(b, perfRecordComm)
	binary.LittleEndian.PutUint16(b[4:], 1<<13)
	binary.LittleEndian.PutUint16(b[6:], 64)
	pending := correlationOut(10, false)
	s := &schedulerSource{done: make(chan struct{}), cpu: &cpuSource{domain: correlationDomain, rings: []*Ring{testRing(make([]byte, 128), 0, b)}}, cpus: []uint32{0}, stopped: true, end: 100, pendingEvent: &pending}
	if item, e := s.NextItem(context.Background()); !errors.Is(e, ErrTargetIdentity) || item.Event != nil || item.Proof != nil {
		t.Fatal(item, e)
	}
	if _, e := s.NextItem(context.Background()); !errors.Is(e, ErrTargetIdentity) {
		t.Fatal(e)
	}
}
func TestSchedulerRecordEndianMismatch(t *testing.T) {
	l, e := parseTraceFormat(SchedulerSwitchKind, schedulerFormat(SchedulerSwitchKind))
	if e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 104)
	binary.BigEndian.PutUint32(b, perfRecordSample)
	binary.BigEndian.PutUint16(b[6:], 104)
	if _, _, e = decodeScheduler(KernelRecordView{first: b}, l, AuthorizedTargets{}); !errors.Is(e, ErrRingMalformed) {
		t.Fatal(e)
	}
}
func TestSchedulerExplicitMonotonicClockABI(t *testing.T) {
	a := schedulerPerfAttr(NumericLayout{id: 17}, DefaultConfig(1))
	if a.Type != 2 || a.Config != 17 || a.ClockID != 1 || a.Flags&(1<<25) == 0 {
		t.Fatal("scheduler kernel ignores requested MONOTONIC clock", a)
	}
	if a.SampleType != 2|4|32|128|1024 || a.SampleRegsUser != 0 || a.SampleRegsIntr != 0 || a.SampleStackUser != 0 {
		t.Fatal("scheduler fixed ABI widened", a)
	}
}
