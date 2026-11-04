//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"sync"
)

// ProfileSource composes the actual fixed native acquisition with checked,
// pinned process epochs. Maps snapshots do not prove historical VA ownership:
// Until fixed MMAP2 epochs are available, FramesMappings returns identity-only
// tables and keeps all addresses unresolved rather than attributing delayed IPs
// to a later mapping. InitialModules is metadata, not symbolication evidence.
type ProfileSource struct {
	mu                        sync.Mutex
	nextMu                    sync.Mutex
	source                    EventSource
	readers                   []*MappingReader
	initial                   []MappingTable
	mapping, assembly, export *WorkingLease
	stop                      func() bool
	closed                    bool
}

func NewProfileAcquisition(ctx context.Context, a AuthorizedTargets, c Config, r *Reservation, p SymbolPolicy) (*ProfileSource, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if p.validate() != nil || p.Revision != uint64(c.PolicyRevision) || r == nil || len(a.targets) == 0 {
		return nil, ErrInvalid
	}
	s := &ProfileSource{}
	fail := func(e error) (*ProfileSource, error) { s.Close(); return nil, e }
	var e error
	// Serialized map reads: 12MiB scratch covers bounded maps/path/ELF metadata
	// parsing; 2MiB per retained table/identity covers 4096 safe mapping entries.
	// No debug artifact buffer is allocated: C07 is unavailable and never called.
	s.mapping, e = r.ReserveWorking((12<<20)+uint64(len(a.targets))*(2<<20), uint64(len(a.targets))*3+6)
	if e != nil {
		return fail(e)
	}
	s.assembly, e = r.ReserveWorking(8<<20, 0)
	if e != nil {
		return fail(e)
	}
	s.export, e = r.ReserveWorking(2<<20, 0)
	if e != nil {
		return fail(e)
	}
	for _, target := range a.targets {
		if e = ctx.Err(); e != nil {
			return fail(e)
		}
		reader, e := NewMappingReader(a, target, 1, p)
		if e != nil {
			return fail(e)
		}
		s.readers = append(s.readers, reader)
		table, e := reader.Read(ctx)
		if e != nil {
			return fail(e)
		}
		s.initial = append(s.initial, table)
	}
	s.source, e = NewNativeAcquisition(ctx, a, c, r)
	if e != nil {
		return fail(e)
	}
	s.mu.Lock()
	s.stop = context.AfterFunc(ctx, func() { s.Close() })
	s.mu.Unlock()
	return s, nil
}
func (s *ProfileSource) Next(ctx context.Context) (SanitizedEvent, error) {
	item, e := s.NextItem(ctx)
	if e != nil {
		return SanitizedEvent{}, e
	}
	if item.Proof != nil {
		return SanitizedEvent{}, ErrProgressRequired
	}
	return *item.Event, nil
}
func (s *ProfileSource) NextItem(ctx context.Context) (AcquisitionItem, error) {
	s.nextMu.Lock()
	defer s.nextMu.Unlock()
	// Reader membership/backing storage is immutable after factory publication;
	// Close retires each reader and drops only its own slice header.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return AcquisitionItem{}, ErrAcquisitionClosed
	}
	source := s.source
	readers := s.readers
	s.mu.Unlock()
	invalidate := func() {
		for _, r := range readers {
			r.Invalidate(2)
		}
	}
	for _, r := range readers {
		if e := r.Guard(); e != nil {
			invalidate()
			return AcquisitionItem{}, e
		}
	}
	var item AcquisitionItem
	var e error
	if proofSource, ok := source.(interface {
		NextItem(context.Context) (AcquisitionItem, error)
	}); ok {
		item, e = proofSource.NextItem(ctx)
	} else {
		var event SanitizedEvent
		event, e = source.Next(ctx)
		if e == nil {
			item.Event = &event
		}
	}
	if e != nil {
		if ctx.Err() == nil && e != ErrSourceComplete {
			invalidate()
		}
		return AcquisitionItem{}, e
	}
	if item.Event != nil && item.Event.Kind == EventGeneration {
		invalidate()
		return AcquisitionItem{}, ErrTargetIdentity
	}
	for _, r := range readers {
		if e := r.Guard(); e != nil {
			invalidate()
			return AcquisitionItem{}, e
		}
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return AcquisitionItem{}, ErrAcquisitionClosed
	}
	return item, nil
}
func (s *ProfileSource) Stop() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrAcquisitionClosed
	}
	source := s.source
	s.mu.Unlock()
	if stoppable, ok := source.(interface{ Stop() error }); ok {
		return stoppable.Stop()
	}
	return &CapabilityError{Unsupported, ReasonEvent}
}
func (s *ProfileSource) FramesMappings() []MappingTable {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	out := make([]MappingTable, 0, len(s.initial))
	for _, m := range s.initial {
		out = append(out, MappingTable{process: m.process, policy: SymbolPolicy{FramePointersAbsent: m.policy.FramePointersAbsent}})
	}
	return out
}
func (s *ProfileSource) InitialModules() []SafeModule {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var out []SafeModule
	for _, m := range s.initial {
		out = append(out, m.Modules()...)
	}
	return out
}
func (s *ProfileSource) AssemblyReservation() WorkingReservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	return s.assembly
}
func (s *ProfileSource) ExportReservation() WorkingReservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	return s.export
}
func (s *ProfileSource) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.stop != nil {
		s.stop()
	}
	var first error
	closeOne := func(e error) {
		if first == nil {
			first = e
		}
	}
	if s.source != nil {
		closeOne(s.source.Close())
	}
	for _, r := range s.readers {
		r.Invalidate(2)
		closeOne(r.Close())
	}
	s.readers = nil
	s.initial = nil
	closeOne(s.mapping.Close())
	closeOne(s.assembly.Close())
	closeOne(s.export.Close())
	return first
}
