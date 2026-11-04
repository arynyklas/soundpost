//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
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
