//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

func emptySchedulerRing(t *testing.T) schedulerRing {
	t.Helper()
	l, e := parseTraceFormat(SchedulerWakeupKind, schedulerFormat(SchedulerWakeupKind))
	if e != nil {
		t.Fatal(e)
	}
	return schedulerRing{ring: &Ring{meta: make([]byte, 4096), data: make([]byte, 4096)}, layout: l}
}

// A live capture whose streams are drained must say so: without periodic
// drained-prefix proofs a consumer can only drain its bounded correlation
// buffer after the capture, and any capture longer than a few hundred events
// overflows it (the runnable-delay split was lost to that on real 6.1/6.6).
func TestSchedulerEmitsMonotonicProgressProofsWhileDrained(t *testing.T) {
	start, e := schedulerNow()
	if e != nil {
		t.Fatal(e)
	}
	s := &schedulerSource{done: make(chan struct{}), start: start, cpus: []uint32{0, 1},
		cpu:   &cpuSource{domain: correlationDomain, lastCheck: time.Now().Add(time.Hour)},
		rings: []schedulerRing{emptySchedulerRing(t)}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	last := start
	for i := range 3 {
		item, e := s.NextItem(ctx)
		if e != nil || item.Event != nil || item.Proof == nil {
			t.Fatalf("item %d: %+v %v", i, item, e)
		}
		p := item.Proof
		if !p.Progress || p.Final || p.Through <= last || p.Domain != correlationDomain || !reflect.DeepEqual(p.CPUs, []uint32{0, 1}) || !p.valid() {
			t.Fatalf("proof %d is not a monotonic progress proof after %d: %+v", i, last, p)
		}
		last = p.Through
	}
}

func schedulerSwitchRecord(t *testing.T, at uint64, prev, next uint32) []byte {
	t.Helper()
	b := make([]byte, 44+64)
	binary.LittleEndian.PutUint32(b, perfRecordSample)
	binary.LittleEndian.PutUint16(b[6:], uint16(len(b)))
	binary.LittleEndian.PutUint64(b[16:], at)
	binary.LittleEndian.PutUint32(b[40:], 64)
	binary.LittleEndian.PutUint32(b[44+24:], prev)
	binary.LittleEndian.PutUint32(b[44+56:], next)
	return b
}

func cpuSampleRecord(at uint64) []byte {
	b := cpuRecord(0x401000, 0x402000, 0x403000).first
	binary.LittleEndian.PutUint64(b[24:], at)
	return b
}

// One backlog of CPU samples must not starve a scheduler event that is older
// than the later samples: events leave in a fair order, so the scheduler
// stream of a lagging consumer is not held back for as long as CPU samples keep
// arriving.
func TestSchedulerEventIsNotStarvedByNewerCPUBacklog(t *testing.T) {
	l, e := parseTraceFormat(SchedulerSwitchKind, schedulerFormat(SchedulerSwitchKind))
	if e != nil {
		t.Fatal(e)
	}
	l.kernel = "6.6"
	records := schedulerSwitchRecord(t, 500, 7, 0)
	data := make([]byte, 4096)
	copy(data, records)
	meta := make([]byte, 4096)
	binary.LittleEndian.PutUint64(meta[1024:], uint64(len(records)))
	sched := schedulerRing{ring: &Ring{meta: meta, data: data}, layout: l}
	task := TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 70, TID: 71, ProcessStart: 1, Generation: 1}
	cpuRing := privacyRing(task, cpuSampleRecord(100), cpuSampleRecord(200), cpuSampleRecord(900))
	targets := AuthorizedTargets{schedulerTasks: []cpuThread{{task: TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 7, ProcessStart: 1, Generation: 1}}}}
	s := &schedulerSource{done: make(chan struct{}), start: 1, end: 1_000_000, stopped: true, cpus: []uint32{0}, rings: []schedulerRing{sched},
		cpu: &cpuSource{domain: correlationDomain, targets: targets, lastCheck: time.Now().Add(time.Hour), rings: []*Ring{cpuRing}}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var order []model.MonoNano
	var kinds []EventKind
	for range 4 {
		item, e := s.NextItem(ctx)
		if e != nil || item.Event == nil {
			t.Fatalf("after %v: %+v %v", order, item, e)
		}
		order = append(order, item.Event.Time)
		kinds = append(kinds, item.Event.Kind)
	}
	if !reflect.DeepEqual(order, []model.MonoNano{100, 200, 500, 900}) || kinds[2] != EventSwitch {
		t.Fatalf("scheduler event starved behind a newer CPU sample: times %v kinds %v", order, kinds)
	}
}

func TestSocketSourceAcceptsOnlyMonotonicProgressBetweenInitialAndFinal(t *testing.T) {
	proof := func(through model.MonoNano, progress, final bool, cpus ...uint32) helperReply {
		return helperReply{Proof: &AcquisitionProof{Domain: correlationDomain, CPUs: cpus, Through: through, Progress: progress, Final: final}}
	}
	run := func(t *testing.T, replies ...helperReply) []error {
		t.Helper()
		client, server := cpuSocketPair(t)
		source := &socketSource{conn: client}
		defer source.Close()
		var errs []error
		for _, r := range replies {
			if e := writeMessage(server, r); e != nil {
				t.Fatal(e)
			}
			_, e := source.NextItem(context.Background())
			errs = append(errs, e)
			if e != nil {
				break
			}
		}
		return errs
	}
	ok := func(t *testing.T, errs []error) {
		t.Helper()
		for _, e := range errs {
			if e != nil {
				t.Fatalf("valid sequence refused: %v", errs)
			}
		}
	}
	t.Run("monotonic progress then final", func(t *testing.T) {
		ok(t, run(t, proof(10, false, false, 0, 1), proof(20, true, false, 0, 1), proof(30, true, false, 0, 1), proof(40, false, true, 0, 1)))
	})
	for name, replies := range map[string][]helperReply{
		"progress before the topology proof": {proof(20, true, false, 0, 1)},
		"progress that regresses":            {proof(10, false, false, 0, 1), proof(30, true, false, 0, 1), proof(25, true, false, 0, 1)},
		"progress before the start":          {proof(10, false, false, 0, 1), proof(9, true, false, 0, 1)},
		"progress with another topology":     {proof(10, false, false, 0, 1), proof(20, true, false, 0)},
		"progress that is also final":        {proof(10, false, false, 0, 1), proof(20, true, true, 0, 1)},
		"progress after the final proof":     {proof(10, false, false, 0, 1), proof(40, false, true, 0, 1), proof(50, true, false, 0, 1)},
		"final before a later progress":      {proof(10, false, false, 0, 1), proof(30, true, false, 0, 1), proof(20, false, true, 0, 1)},
	} {
		t.Run(name, func(t *testing.T) {
			errs := run(t, replies...)
			if last := errs[len(errs)-1]; !errors.Is(last, ErrAcquisitionFailed) {
				t.Fatalf("accepted: %v", errs)
			}
		})
	}
}
