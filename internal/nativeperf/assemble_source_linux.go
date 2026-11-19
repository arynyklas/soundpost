//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// ProfileSource composes the actual fixed native acquisition with checked, pinned process epochs. A maps snapshot only
// proves the state at its own instant, so the source publishes the snapshot as mapping events (taken after every perf
// event was enabled) and, before it publishes a CPU sample, every mapping announcement the kernel already wrote to any
// ring of the capture (see mapping_sideband_linux.go). The consumer rebuilds which mapping owned an address when a
// sample was taken from that stream (mapping_epoch.go) and never from a current /proc snapshot. FramesMappings still
// returns identity-only tables; InitialModules is metadata, not symbolication evidence.
type ProfileSource struct {
	mu                        sync.Mutex
	nextMu                    sync.Mutex
	source                    EventSource
	readers                   []*MappingReader
	initial                   []MappingTable
	mapping, assembly, export *WorkingLease
	stop                      func() bool
	owner                     context.Context
	closed                    bool
	domain                    ClockDomain
	sequence                  uint64
	pending                   []AcquisitionItem
	recon                     []*reconciler
	nextReconcile             time.Time
	finalDue                  bool
}

// ProfileWorkingBytes is what NewProfileAcquisition leases out of the capture's reservation for a request of the given
// number of targets: the serialized map-read scratch (12 MiB plus 2 MiB per retained table), the assembly working set
// (8 MiB) and the export working set (2 MiB). They are charged before anything is allocated and sit on top of the
// capture's admission charge, so anything else the capture's consumer holds (the correlator) has to fit in what the
// 64 MiB budget leaves after both.
func ProfileWorkingBytes(targets uint64) (mapping, assembly, export uint64) {
	return 12<<20 + targets*(2<<20), 8 << 20, 2 << 20
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
	mapping, assembly, export := ProfileWorkingBytes(uint64(len(a.targets)))
	s.mapping, e = r.ReserveWorking(mapping, uint64(len(a.targets))*3+6)
	if e != nil {
		return fail(e)
	}
	s.assembly, e = r.ReserveWorking(assembly, 0)
	if e != nil {
		return fail(e)
	}
	s.export, e = r.ReserveWorking(export, 0)
	if e != nil {
		return fail(e)
	}
	s.domain, e = localCPUDomain()
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
	}
	// Every perf event is enabled before the snapshot is read: a mapping change after that instant is announced in a
	// ring, and one before it is in the snapshot. The read is bracketed by two clock reads on the events' own clock;
	// its rows are the state at some instant in between (see MappingUpdate.Since).
	s.source, e = NewNativeAcquisition(ctx, a, c, r)
	if e != nil {
		return fail(e)
	}
	for _, reader := range s.readers {
		since, e := schedulerNow()
		if e != nil {
			return fail(e)
		}
		table, e := reader.Read(ctx)
		if e != nil {
			return fail(e)
		}
		at, e := schedulerNow()
		if e != nil {
			return fail(e)
		}
		s.initial = append(s.initial, table)
		s.recon = append(s.recon, &reconciler{reader: reader, process: table.process, model: table.entries, lastAt: at})
		for _, event := range snapshotEvents(table, s.domain, since, at) {
			s.pending = append(s.pending, AcquisitionItem{Event: &event})
		}
	}
	s.nextReconcile = time.Now().Add(mappingReconcileInterval)
	s.bind(ctx)
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

// bind makes ctx the owner of the source: when it ends, the source closes, and a read that the close interrupts reports
// that context's error (NextItem), never the closed error that the very same cancellation raced it to.
func (s *ProfileSource) bind(ctx context.Context) {
	s.mu.Lock()
	s.owner = ctx
	s.stop = context.AfterFunc(ctx, func() { s.Close() })
	s.mu.Unlock()
}

// ended is the context error that explains a closed source: the caller's own context, or the owner's.
func (s *ProfileSource) ended(call context.Context) error {
	if e := call.Err(); e != nil {
		return e
	}
	s.mu.Lock()
	owner := s.owner
	s.mu.Unlock()
	if owner != nil {
		return owner.Err()
	}
	return nil
}

func (s *ProfileSource) NextItem(ctx context.Context) (AcquisitionItem, error) {
	item, e := s.nextItem(ctx)
	if e == ErrAcquisitionClosed {
		if ended := s.ended(ctx); ended != nil {
			return AcquisitionItem{}, ended
		}
	}
	return item, e
}
func (s *ProfileSource) nextItem(ctx context.Context) (AcquisitionItem, error) {
	s.nextMu.Lock()
	defer s.nextMu.Unlock()
	if len(s.pending) == 0 {
		item, e := s.fetch(ctx)
		if e != nil {
			return AcquisitionItem{}, e
		}
		s.pending = []AcquisitionItem{item}
		if e = s.enrich(ctx); e != nil {
			s.pending = nil
			return AcquisitionItem{}, e
		}
	} else {
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return AcquisitionItem{}, ErrAcquisitionClosed
		}
	}
	item := s.pending[0]
	s.pending = s.pending[1:]
	if item.Event != nil {
		// One sequence over everything this source publishes, mapping events included.
		event := *item.Event
		s.sequence++
		event.Sequence = model.Uint64(s.sequence)
		if event.Validate() != nil {
			return AcquisitionItem{}, ErrAcquisitionFailed
		}
		item.Event = &event
	}
	return item, nil
}

func (s *ProfileSource) invalidateReaders() {
	s.mu.Lock()
	readers := s.readers
	s.mu.Unlock()
	for _, r := range readers {
		r.Invalidate(2)
	}
}

// fetch is one item of the wrapped acquisition, under the target identity guards.
func (s *ProfileSource) fetch(ctx context.Context) (AcquisitionItem, error) {
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
		e := stoppable.Stop()
		if e == nil {
			// the interval after the last reconciliation is confirmed by one more read before the final proof
			s.mu.Lock()
			s.finalDue = true
			s.mu.Unlock()
		}
		return e
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
