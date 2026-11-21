//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type blockedProfileSource struct {
	entered, done chan struct{}
	once          sync.Once
}

func (s *blockedProfileSource) Next(context.Context) (SanitizedEvent, error) {
	close(s.entered)
	<-s.done
	return SanitizedEvent{}, ErrAcquisitionClosed
}
func (s *blockedProfileSource) Close() error { s.once.Do(func() { close(s.done) }); return nil }
func TestAssembleSourceCloseInterruptsBlockedNext(t *testing.T) {
	raw := &blockedProfileSource{entered: make(chan struct{}), done: make(chan struct{})}
	s := &ProfileSource{source: raw}
	finished := make(chan struct{})
	go func() { s.Next(context.Background()); close(finished) }()
	<-raw.entered
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close held state lock behind blocking source Next")
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("Next not interrupted")
	}
}

type proofProfileSource struct{ proof AcquisitionProof }

func (s *proofProfileSource) Next(context.Context) (SanitizedEvent, error) {
	return SanitizedEvent{}, ErrProgressRequired
}
func (s *proofProfileSource) NextItem(context.Context) (AcquisitionItem, error) {
	return AcquisitionItem{Proof: &s.proof}, nil
}
func (s *proofProfileSource) Close() error { return nil }
func TestAssembleSourceRetainsActualDrainProof(t *testing.T) {
	d, _ := assemblyTask()
	s := &ProfileSource{source: &proofProfileSource{proof: AcquisitionProof{Domain: d, CPUs: []uint32{0, 2}, Through: 991, Final: true}}}
	item, e := s.NextItem(context.Background())
	if e != nil || item.Proof == nil || !item.Proof.Final || item.Proof.Through != 991 || len(item.Proof.CPUs) != 2 {
		t.Fatal("producer proof lost or fabricated")
	}
	s.Close()
}

// A capture ended by cancelling the context that owns it reports THAT cancellation. The source closes itself when its
// owner ends, and a Next the close interrupts used to answer "acquisition closed" or the context error depending on which
// of the two got there first, so one cancel produced two different verdicts (observed 1 run in ~9 of the real-kernel
// mapping-epoch test under -race on a 6.6 kernel).
func TestAssembleSourceEndedByItsOwnerContextReportsThatContext(t *testing.T) {
	for i := range 300 {
		raw := &blockedProfileSource{entered: make(chan struct{}), done: make(chan struct{})}
		owner, cancel := context.WithCancel(context.Background())
		s := &ProfileSource{source: raw}
		s.bind(owner)
		got := make(chan error, 1)
		go func() { _, e := s.NextItem(context.Background()); got <- e }()
		<-raw.entered
		cancel()
		select {
		case e := <-got:
			if !errors.Is(e, context.Canceled) {
				t.Fatalf("round %d: the owner was cancelled but Next answered %v", i, e)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("round %d: Next not interrupted by the owner's cancellation", i)
		}
	}
	// an explicit Close with an owner that is still alive stays "closed"
	raw := &blockedProfileSource{entered: make(chan struct{}), done: make(chan struct{})}
	owner, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &ProfileSource{source: raw}
	s.bind(owner)
	got := make(chan error, 1)
	go func() { _, e := s.NextItem(context.Background()); got <- e }()
	<-raw.entered
	s.Close()
	if e := <-got; !errors.Is(e, ErrAcquisitionClosed) {
		t.Fatalf("an explicitly closed source answered %v, want ErrAcquisitionClosed", e)
	}
}
