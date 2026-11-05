// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention

import (
	"context"
	"errors"
	"sort"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/storage"
	"time"
)

// WorkerStatus is the last observable state of the maintenance worker. It
// carries no telemetry values.
type WorkerStatus struct {
	Passes         uint64
	LastError      string
	Pressure       storage.PressureStatus
	EvidenceHeld   bool // expired unprocessed evidence is retained because its gap could not commit
	ErasedRecords  uint64
	HeldByLegal    uint64
	Snapshots      uint64
	GapsRecorded   uint64
	ExpiryErased   uint64
	CompletedOps   uint64
	FencingOps     int
	PhysicalLagOps int
}

func (s *Service) Status() WorkerStatus { s.mu.Lock(); defer s.mu.Unlock(); return s.status }

// Start runs RunOnce every Interval until Close or ctx ends.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return model.Fail(model.Conflict)
	}
	run, cancel := context.WithCancel(ctx)
	// The first snapshot and expiry pass are due one interval after start, not at
	// start: a freshly started (or joining) node must not begin with two
	// fsync-heavy snapshot cuts while it is still catching up. Deletions are
	// driven on every pass regardless.
	started := s.cfg.Clock()
	s.last.snapshot, s.last.expiry = started, started
	s.cancel, s.done = cancel, make(chan struct{})
	go func(done chan struct{}) {
		defer close(done)
		t := time.NewTicker(s.worker.Interval)
		defer t.Stop()
		for {
			_ = s.RunOnce(run)
			select {
			case <-run.Done():
				return
			case <-t.C:
			}
		}
	}(s.done)
	return nil
}

// Close stops the worker and waits for the current pass.
func (s *Service) Close() error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.cancel, s.done = nil, nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	return nil
}

// RunOnce is one deterministic maintenance pass: drive deletion fences, erase
// physically, enforce expiry, cut snapshots/compact journals, sample pressure.
// Every step runs even if an earlier one failed; the joined error is returned.
func (s *Service) RunOnce(ctx context.Context) error {
	var errs []error
	step := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	erased, err := s.driveDeletions(ctx)
	step(err)
	now := s.cfg.Clock()
	s.mu.Lock()
	expiryDue := s.last.expiry.IsZero() || now.Sub(s.last.expiry) >= s.worker.ExpiryInterval
	snapDue := erased || s.last.snapshot.IsZero() || now.Sub(s.last.snapshot) >= s.worker.SnapshotInterval
	s.mu.Unlock()
	if expiryDue {
		n, err := s.expire(ctx)
		step(err)
		erased = erased || n > 0
		if err == nil {
			s.mu.Lock()
			s.last.expiry = now
			s.mu.Unlock()
		}
	}
	if snapDue || erased {
		err := s.maintainJournal(ctx)
		step(err)
		if err == nil {
			s.mu.Lock()
			s.last.snapshot = now
			s.mu.Unlock()
		}
	}
	if s.cfg.Pressure != nil {
		st, err := s.cfg.Pressure.ObservePressure(ctx)
		step(err)
		s.mu.Lock()
		s.status.Pressure = st
		s.mu.Unlock()
	}
	joined := errors.Join(errs...)
	s.mu.Lock()
	s.status.Passes++
	s.status.LastError = ""
	if joined != nil {
		var f *model.Fault
		if errors.As(joined, &f) {
			s.status.LastError = string(f.Code)
		} else {
			s.status.LastError = "error"
		}
	}
	s.mu.Unlock()
	return joined
}

// maintainJournal cuts a verified snapshot of every group and truncates each
// journal to it. Truncation never removes evidence: the snapshot carries the
// whole command history, and evidence leaves only through the gap-gated expiry.
// Two cuts are taken so the retained "previous" snapshot is also post-erasure.
func (s *Service) maintainJournal(ctx context.Context) error {
	for range 2 {
		if _, err := s.cfg.Data.CreateSnapshots(ctx); err != nil {
			return err
		}
	}
	if err := s.cfg.Data.CompactJournals(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	s.status.Snapshots++
	s.mu.Unlock()
	return nil
}

// driveDeletions advances every fencing operation (record barriers in each
// slot, then complete once all 64 are recorded and the authority has the
// generation) and physically erases completed ones. It reports whether bytes
// were physically erased.
func (s *Service) driveDeletions(ctx context.Context) (bool, error) {
	ops, err := s.cfg.Control.DeletionOperations(ctx)
	if err != nil {
		return false, err
	}
	var errs []error
	fencing, completed := 0, uint64(0)
	for _, op := range ops {
		if op.Phase == model.DeletePhaseFencing {
			fencing++
			if err := s.fence(ctx, op); err != nil {
				errs = append(errs, err)
			}
		}
	}
	erased, err := s.physical(ctx)
	if err != nil {
		errs = append(errs, err)
	}
	ops, _ = s.cfg.Control.DeletionOperations(ctx)
	lag := 0
	for _, op := range ops {
		if op.Phase == model.DeletePhaseComplete {
			completed++
			if op.PhysicalAt == 0 {
				lag++
			}
		}
	}
	s.mu.Lock()
	s.status.FencingOps, s.status.CompletedOps, s.status.PhysicalLagOps = fencing, completed, lag
	s.mu.Unlock()
	return erased, errors.Join(errs...)
}

func (s *Service) fence(ctx context.Context, op model.DeletionOperation) error {
	var cursors []model.Cursor
	var first error
	for slot := range uint16(model.DeleteSlots) {
		c, err := s.cfg.Data.RecordDeleteBarrier(ctx, slot, op.Predicate)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		cursors = append(cursors, c)
	}
	if len(cursors) > 0 {
		var err error
		if op, err = s.cfg.Control.RecordBarriers(ctx, op.Predicate.Operation, cursors); err != nil {
			return err
		}
	}
	if first != nil {
		return first // an unavailable group blocks completion; the operation stays fencing
	}
	var authority *model.DeletionAuthority
	if op.AuthorityRequired {
		var lg LedgerGeneration
		err := s.cfg.Control.View(ctx, func(st control.State) error {
			done := st
			cur := st.Deletions[op.Predicate.Operation.String()]
			cur.Phase = model.DeletePhaseComplete
			done.Deletions = map[string]model.DeletionOperation{}
			for k, v := range st.Deletions {
				done.Deletions[k] = v
			}
			done.Deletions[op.Predicate.Operation.String()] = cur
			ledger, tombs := BuildLedger(done)
			ledger.Generation++ // completion itself bumps the generation
			lg = LedgerGeneration{Generation: ledger.Generation, Ledger: ledger, Tombstones: tombs}
			return nil
		})
		if err != nil {
			return err
		}
		checkpointer := s.authority()
		if checkpointer == nil {
			return model.Fail(model.Unavailable)
		}
		receipt, err := checkpointer.CheckpointDeletion(ctx, lg)
		if err != nil {
			return model.Fail(model.Unavailable) // authority failure leaves deletion fencing, never success
		}
		authority = &model.DeletionAuthority{Generation: model.Uint64(receipt.Generation), Head: receipt.Head, At: receipt.At}
	}
	_, err := s.cfg.Control.CompleteDeletion(ctx, op.Predicate.Operation, s.now(), authority)
	return err
}

// physical erases the bytes of completed deletions unless a legal hold covers
// them. The delete generation advances BEFORE any byte is erased.
func (s *Service) physical(ctx context.Context) (bool, error) {
	ops, err := s.cfg.Control.DeletionOperations(ctx)
	if err != nil {
		return false, err
	}
	byOrg := map[model.ID][]model.DeletionOperation{}
	for _, op := range ops {
		if op.Phase == model.DeletePhaseComplete && op.PhysicalAt == 0 {
			byOrg[op.Predicate.Org] = append(byOrg[op.Predicate.Org], op)
		}
	}
	orgs := make([]model.ID, 0, len(byOrg))
	for o := range byOrg {
		orgs = append(orgs, o)
	}
	sort.Slice(orgs, func(i, j int) bool { return orgs[i].String() < orgs[j].String() })
	var errs []error
	any := false
	for _, org := range orgs {
		guard, err := s.holdGuard(ctx, nil)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err = s.cfg.Control.AdvanceDeleteGeneration(ctx, org); err != nil {
			errs = append(errs, err)
			continue
		}
		preds := make([]model.DeletePredicate, 0, len(byOrg[org]))
		ids := make([]model.ID, 0, len(byOrg[org]))
		for _, op := range byOrg[org] {
			preds = append(preds, op.Predicate)
			ids = append(ids, op.Predicate.Operation)
		}
		report, err := s.cfg.Data.EraseDeleted(ctx, preds, guard)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		s.mu.Lock()
		s.status.ErasedRecords += report.Records + report.Blobs
		s.status.HeldByLegal += report.Held
		s.mu.Unlock()
		any = any || report.Records+report.Blobs > 0
		if report.Held == 0 {
			if err = s.cfg.Control.RecordPhysicalCleanup(ctx, org, ids, s.now()); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return any, errors.Join(errs...)
}

// holdGuard builds the EraseGuard from a fresh snapshot of control state:
// legal holds veto, and (for expiry) the extra check runs after them.
func (s *Service) holdGuard(ctx context.Context, extra storage.EraseGuard) (storage.EraseGuard, error) {
	var holds []model.LegalHold
	if err := s.cfg.Control.View(ctx, func(st control.State) error { holds = activeHolds(st); return nil }); err != nil {
		return nil, err
	}
	return func(ctx context.Context, c storage.EraseCandidate) (bool, error) {
		for _, h := range holds {
			if c.Record != nil && h.CoversRecord(c.Org, c.Project, *c.Record) || c.Blob != nil && h.CoversBlob(*c.Blob) {
				return false, nil
			}
		}
		if extra != nil {
			return extra(ctx, c)
		}
		return true, nil
	}, nil
}

// expire enforces declared retention. It never shortens a deadline and never
// erases earlier than the receipt's own deadline. Unprocessed lifecycle
// evidence is erased only after a durable gap covers it; if the gap cannot
// commit the evidence stays (EvidenceHeld) rather than silently vanishing.
func (s *Service) expire(ctx context.Context) (uint64, error) {
	now := s.now()
	type runKey struct{ org, project, group model.ID }
	type run struct {
		first, last uint64
		count       uint64
		start, end  model.UnixNano
		kinds       map[model.Kind]bool
	}
	runs := map[runKey]*run{}
	plannedOrgs := map[model.ID]bool{}
	var state control.State
	load := func() error { return s.cfg.Control.View(ctx, func(st control.State) error { state = st; return nil }) }
	if err := load(); err != nil {
		return 0, err
	}
	covered := func(c storage.EraseCandidate) bool {
		for _, g := range state.EvidenceGaps {
			if g.Group == c.Cursor.Group && g.Org == c.Org && g.Project == c.Project && uint64(c.Cursor.Index) > uint64(g.After) && uint64(c.Cursor.Index) <= uint64(g.Through) {
				return true
			}
		}
		return false
	}
	planning := true
	extra := func(ctx context.Context, c storage.EraseCandidate) (bool, error) {
		if s.cfg.References != nil {
			ref, err := s.cfg.References.LatestReference(ctx, c)
			if err != nil {
				return false, err
			}
			if ref > now {
				return false, nil // a retained dependent still needs it (replay checkpoint, artifact reference)
			}
		}
		if evidenceKind(c.Kind) {
			processed := uint64(0)
			if s.cfg.Processed != nil {
				p, err := s.cfg.Processed.Processed(ctx, c.Cursor.Group)
				if err != nil {
					return false, err
				}
				processed = p
			}
			if uint64(c.Cursor.Index) > processed && !covered(c) {
				if planning {
					k := runKey{c.Org, c.Project, c.Cursor.Group}
					r := runs[k]
					at := model.UnixNano(0)
					if c.Record != nil {
						at = model.SignalTime(*c.Record)
					}
					if r == nil {
						r = &run{first: uint64(c.Cursor.Index), last: uint64(c.Cursor.Index), start: at, end: at, kinds: map[model.Kind]bool{}}
						runs[k] = r
					}
					r.first, r.last = min(r.first, uint64(c.Cursor.Index)), max(r.last, uint64(c.Cursor.Index))
					r.start, r.end = min(r.start, at), max(r.end, at)
					r.count++
					r.kinds[c.Kind] = true
				}
				return false, nil
			}
		}
		if planning {
			plannedOrgs[c.Org] = true
		}
		return true, nil
	}
	guard, err := s.holdGuard(ctx, extra)
	if err != nil {
		return 0, err
	}
	if _, err = s.cfg.Data.EraseExpired(ctx, now, wrapDry(guard)); err != nil { // plan: nothing is erased
		return 0, err
	}
	var errs []error
	held := false
	keys := make([]runKey, 0, len(runs))
	for k := range runs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].group.String()+keys[i].project.String() < keys[j].group.String()+keys[j].project.String()
	})
	for _, k := range keys {
		r := runs[k]
		var signals []model.Kind
		for kind := range r.kinds {
			signals = append(signals, kind)
		}
		sort.Slice(signals, func(i, j int) bool { return signals[i] < signals[j] })
		_, err := s.cfg.Control.RecordEvidenceGap(ctx, model.EvidenceGap{Org: k.org, Project: k.project, Group: k.group, After: model.Uint64(r.first - 1), Through: model.Uint64(r.last), Count: model.Uint64(r.count), Start: r.start, End: r.end, Signals: signals, Reason: "unprocessed_expiry", RecordedAt: now})
		if err != nil {
			held = true // the journal is held; nothing of this run is erased
			errs = append(errs, err)
			continue
		}
		s.mu.Lock()
		s.status.GapsRecorded++
		s.mu.Unlock()
	}
	s.mu.Lock()
	s.status.EvidenceHeld = held
	s.mu.Unlock()
	orgs := make([]model.ID, 0, len(plannedOrgs))
	for o := range plannedOrgs {
		orgs = append(orgs, o)
	}
	for _, k := range keys {
		plannedOrgs[k.org] = true
	}
	for o := range plannedOrgs {
		if !contains(orgs, o) {
			orgs = append(orgs, o)
		}
	}
	for _, o := range orgs {
		if _, err := s.cfg.Control.AdvanceDeleteGeneration(ctx, o); err != nil { // before any readable byte is erased
			return 0, errors.Join(append(errs, err)...)
		}
	}
	if err := load(); err != nil {
		return 0, err
	}
	planning = false
	guard, err = s.holdGuard(ctx, extra)
	if err != nil {
		return 0, err
	}
	report, err := s.cfg.Data.EraseExpired(ctx, now, guard)
	if err != nil {
		return 0, errors.Join(append(errs, err)...)
	}
	s.mu.Lock()
	s.status.ExpiryErased += report.Records + report.Blobs
	s.status.HeldByLegal += report.Held
	s.mu.Unlock()
	return report.Records + report.Blobs, errors.Join(errs...)
}

func contains(ids []model.ID, id model.ID) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// wrapDry turns a guard into a planner: it is consulted for every candidate
// (so the plan sees them) but never allows erasure.
func wrapDry(g storage.EraseGuard) storage.EraseGuard {
	return func(ctx context.Context, c storage.EraseCandidate) (bool, error) {
		if _, err := g(ctx, c); err != nil {
			return false, err
		}
		return false, nil
	}
}
