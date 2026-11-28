//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

func TestSchedulerSwitchOnlyKernelSuppliedUserChain(t *testing.T) {
	l, e := parseTraceFormat(SchedulerSwitchKind, schedulerFormat(SchedulerSwitchKind))
	if e != nil {
		t.Fatal(e)
	}
	l.kernel = "6.6"
	b := make([]byte, 120)
	binary.LittleEndian.PutUint32(b, 9)
	binary.LittleEndian.PutUint16(b[6:], 120)
	binary.LittleEndian.PutUint64(b[32:], 2)
	binary.LittleEndian.PutUint64(b[40:], ^uint64(511))
	binary.LittleEndian.PutUint64(b[48:], 0x1234)
	binary.LittleEndian.PutUint32(b[56:], 60)
	binary.LittleEndian.PutUint32(b[84:], 7)
	a := AuthorizedTargets{schedulerTasks: []cpuThread{{task: TaskKey{TID: 7}}}}
	ev, ok, e := decodeScheduler(KernelRecordView{first: b}, l, a)
	if e != nil || !ok || len(ev.Switch.SwitchOutCallchain) != 1 || ev.Switch.SwitchOutCallchain[0].IP != 0x1234 || ev.Switch.MissingCallchain != "" {
		t.Fatal(ev, ok, e)
	}
	binary.LittleEndian.PutUint64(b[40:], ^uint64(127))
	ev, _, e = decodeScheduler(KernelRecordView{first: b}, l, a)
	if e != nil || len(ev.Switch.SwitchOutCallchain) != 0 || ev.Switch.MissingCallchain != ReasonMissingSwitchCallchain {
		t.Fatal(ev, e)
	}
	binary.LittleEndian.PutUint32(b[84:], 999)
	binary.LittleEndian.PutUint32(b[116:], 7)
	ev, _, e = decodeScheduler(KernelRecordView{first: b}, l, a)
	if e != nil || ev.Switch.Previous != nil || ev.Switch.PreviousState != 0 || len(ev.Switch.SwitchOutCallchain) != 0 || ev.Switch.MissingCallchain != "" {
		t.Fatal(ev, e)
	}
}
func TestSchedulerSocketProofObservableAndCompletionClosed(t *testing.T) {
	client, server := cpuSocketPair(t)
	source := &socketSource{conn: client}
	defer source.Close()
	p := AcquisitionProof{Domain: correlationDomain, CPUs: []uint32{0, 1}, Through: 10}
	if e := writeMessage(server, helperReply{Proof: &p}); e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if _, e := source.Next(context.Background()); !errors.Is(e, ErrProgressRequired) {
			t.Fatal(e)
		}
	}
	item, e := source.NextItem(context.Background())
	if e != nil || item.Proof == nil || item.Proof.Through != 10 {
		t.Fatal(item, e)
	}
	// Mutating caller-owned topology must not change the final-proof comparator.
	item.Proof.CPUs[0] = 99
	p.Final = true
	p.Through = 20
	if e = writeMessage(server, helperReply{Proof: &p}); e != nil {
		t.Fatal(e)
	}
	item, e = source.NextItem(context.Background())
	if e != nil || item.Proof == nil || !item.Proof.Final {
		t.Fatal(item, e)
	}
	if e = writeMessage(server, helperReply{Complete: true}); e != nil {
		t.Fatal(e)
	}
	if _, e = source.NextItem(context.Background()); !errors.Is(e, ErrSourceComplete) {
		t.Fatal(e)
	}
}
func TestSchedulerPrematureCompleteRefuses(t *testing.T) {
	client, server := cpuSocketPair(t)
	if e := writeMessage(server, helperReply{Complete: true}); e != nil {
		t.Fatal(e)
	}
	if _, e := (&socketSource{conn: client}).NextItem(context.Background()); !errors.Is(e, ErrAcquisitionFailed) {
		t.Fatal(e)
	}
}
