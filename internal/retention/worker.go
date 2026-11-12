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
	Passes        uint64
	LastError     string
	Pressure      storage.PressureStatus
	EvidenceHeld  bool // expired unprocessed evidence is retained because its gap could not commit
	ErasedRecords uint64
	HeldByLegal   uint64
	ScrubPending  bool // the last erasure pass could not finish zeroing free bbolt pages (a reader was open)
	Snapshots     uint64
	GapsRecorded  uint64
	ExpiryErased  uint64
	// UnfencedBlobs counts expired artifact roots an expiry pass kept because no References
	// source is bound: without one nothing proves a root is retired, and erasing it would leave
	// a published intent over missing bytes.
	UnfencedBlobs  uint64
	CompletedOps   uint64
	FencingOps     int
	PhysicalLagOps int
	// ErasedBeforeHold counts records and artifact roots a physical pass erased for operations
	// whose cleanup was then NOT recorded because a legal hold committed after the erasure and
	// before the record: the bytes are gone, the receipt says "held", never "done".
	ErasedBeforeHold uint64
	// ConsecutiveFailures is the number of passes in a row whose RunOnce returned an error (0
	// after a clean pass). It carries no data, only a count, so a permanently failing step is
	// visible without a log.
	ConsecutiveFailures uint64
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
// physically (including the snapshot/journal cleanup a deletion needs), enforce
// expiry, cut snapshots/compact journals, sample pressure. Every step runs even
// if an earlier one failed; the joined error is returned.
func (s *Service) RunOnce(ctx context.Context) error {
	var errs []error
	step := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	step(s.driveDeletions(ctx))
	now := s.cfg.Clock()
	s.mu.Lock()
	expiryDue := s.last.expiry.IsZero() || now.Sub(s.last.expiry) >= s.worker.ExpiryInterval
	snapDue := s.last.snapshot.IsZero() || now.Sub(s.last.snapshot) >= s.worker.SnapshotInterval
	s.mu.Unlock()
	expired := false
	if expiryDue {
		n, err := s.expire(ctx)
		step(err)
		expired = n > 0
		if err == nil {
			s.mu.Lock()
			s.last.expiry = now
			s.mu.Unlock()
		}
	}
	if snapDue || expired {
		step(s.maintainJournal(ctx, expired))
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
	if joined == nil {
		s.status.ConsecutiveFailures = 0
	} else {
		s.status.ConsecutiveFailures++
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
// afterErasure additionally drops every snapshot older than the new one (the
// store would otherwise keep the newest previous snapshot, which pre-dates the
// erasure and still carries the erased segment bytes).
func (s *Service) maintainJournal(ctx context.Context, afterErasure bool) error {
	if _, err := s.cfg.Data.CreateSnapshots(ctx); err != nil {
		return err
	}
	if afterErasure {
		if _, err := s.cfg.Data.DropSupersededSnapshots(ctx); err != nil {
			return err
		}
	}
	if err := s.cfg.Data.CompactJournals(ctx); err != nil {
		return err
	}
	s.mu.Lock()
	s.status.Snapshots++
	s.last.snapshot = s.cfg.Clock() // any completed maintenance, including a deletion's, satisfies the schedule
	s.mu.Unlock()
	return nil
}

// driveDeletions advances every fencing operation (record barriers in each
// slot, then complete once all 64 are recorded and the authority has the
// generation) and physically erases completed ones.
func (s *Service) driveDeletions(ctx context.Context) error {
	ops, err := s.cfg.Control.DeletionOperations(ctx)
	if err != nil {
		return err
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
	if err := s.physical(ctx); err != nil {
		errs = append(errs, err)
	}
	// The control.db scrub of an erasure whose operation has no physical step to
	// run it from: a FAILED deletion (its data was never erased, so its physical
	// step is never recorded) or an effect erased as it committed after its
	// operation's physical step. A no-op unless a scrub is owed.
	if err := s.cfg.Control.ScrubErased(ctx); err != nil {
		errs = append(errs, err)
	}
	// The control Raft group retains every control command (each carries the whole control
	// state), so the payloads a finished deletion erased still sit in its journal, snapshots
	// and retry table until this node's copy is redacted. A no-op unless that is owed.
	if err := s.cfg.Control.RedactRetainedControlCommands(ctx); err != nil {
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
	return errors.Join(errs...)
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
func (s *Service) physical(ctx context.Context) error {
	ops, err := s.cfg.Control.DeletionOperations(ctx)
	if err != nil {
		return err
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
	type cleaned struct {
		org    model.ID
		ids    []model.ID
		pred   model.DeletePredicate
		erased uint64 // records and artifact roots this pass erased for the organization
	}
	var ready []cleaned
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
		s.status.ScrubPending = report.ScrubPending
		s.mu.Unlock()
		// An org is ready to be recorded only when nothing is vetoed AND the free pages the
		// erased bytes landed in are zeroed: a pass that could not finish its scrub (a reader
		// was open) has not erased them from apply.db, and the next pass retries.
		if report.Held == 0 && !report.ScrubPending {
			ready = append(ready, cleaned{org: org, ids: ids, pred: preds[0], erased: report.Records + report.Blobs})
		}
	}
	if len(ready) > 0 {
		// Physical cleanup includes the copies in snapshots and the journal, so it is recorded only
		// after they are cleaned: a failure here leaves it pending and the next pass retries. Every
		// ready organization is checkpointed with one of its own operations.
		for _, r := range ready {
			if err = s.cfg.Data.CheckpointErasure(ctx, r.pred); err != nil {
				return errors.Join(append(errs, err)...)
			}
		}
		if err = s.maintainJournal(ctx, true); err != nil {
			return errors.Join(append(errs, err)...)
		}
		for _, r := range ready {
			held, err := s.cfg.Control.RecordPhysicalCleanup(ctx, r.org, r.ids, s.now())
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if len(held) > 0 {
				// A hold committed after the erasure: control refused to record the cleanup (the
				// receipt says held, never done). The bytes are gone; say so.
				s.mu.Lock()
				s.status.ErasedBeforeHold += r.erased
				s.mu.Unlock()
			}
		}
	}
	return errors.Join(errs...)
}

// holdGuard builds the EraseGuard. Legal holds veto against the CURRENT applied control state,
// re-read for every candidate (and again with Final set, inside the erasing transaction): the
// guard is a check at erase time, not a snapshot of the instant the pass started, so a hold that
// committed while the pass was running still protects what it covers. A linearizable read at
// build time makes this node catch up with everything committed before the pass began; after
// that the read is local (see control.Store.AppliedHolds). A hold committed in the control group
// but not yet applied on this node is the residual window. For expiry the extra check runs
// after the holds, at scan time only.
func (s *Service) holdGuard(ctx context.Context, extra storage.EraseGuard) (storage.EraseGuard, error) {
	if err := s.cfg.Control.View(ctx, func(control.State) error { return nil }); err != nil {
		return nil, err
	}
	var holds control.HoldSnapshot
	return func(ctx context.Context, c storage.EraseCandidate) (bool, error) {
		var err error
		if holds, err = s.cfg.Control.AppliedHolds(holds); err != nil {
			return false, err // fail closed
		}
		for _, h := range holds.Holds {
			if c.Record != nil && h.CoversRecord(c.Org, c.Project, *c.Record) || c.Blob != nil && h.CoversBlob(*c.Blob) {
				return false, nil
			}
		}
		if c.Final {
			return true, nil
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
	type entry struct { // one unprocessed evidence entry (one batch index) that has expired
		start, end model.UnixNano
		kinds      map[model.Kind]bool
	}
	entries := map[runKey]map[uint64]*entry{}
	plannedOrgs := map[model.ID]bool{}
	var state control.State
	load := func() error { return s.cfg.Control.View(ctx, func(st control.State) error { state = st; return nil }) }
	if err := load(); err != nil {
		return 0, err
	}
	// Only a gap the worker enumerated authorizes expiry. An administrator's gap (or one recorded
	// before the declarant was kept) is a statement nothing enumerates: it is audited and kept,
	// never an authority to erase unprocessed evidence.
	covered := func(c storage.EraseCandidate) bool {
		for _, g := range state.EvidenceGaps {
			if g.DeclaredBy == control.GapDeclaredByWorker && g.Group == c.Cursor.Group && g.Org == c.Org && g.Project == c.Project && uint64(c.Cursor.Index) > uint64(g.After) && uint64(c.Cursor.Index) <= uint64(g.Through) {
				return true
			}
		}
		return false
	}
	planning := true
	references := s.references()
	extra := func(ctx context.Context, c storage.EraseCandidate) (bool, error) {
		if c.Blob != nil && references == nil {
			// Nothing can prove the artifact root is fenced (reference ledger retired, intent
			// retired) or unreferenced, and a root erased without that proof leaves a published
			// intent over missing bytes. Keep it and say so; the pass itself is not failed.
			if !planning {
				s.mu.Lock()
				s.status.UnfencedBlobs++
				s.mu.Unlock()
			}
			return false, nil
		}
		if references != nil {
			ref, err := references.LatestReference(ctx, c)
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
					if entries[k] == nil {
						entries[k] = map[uint64]*entry{}
					}
					at := model.UnixNano(0)
					if c.Record != nil {
						at = model.SignalTime(*c.Record)
					}
					e := entries[k][uint64(c.Cursor.Index)]
					if e == nil {
						e = &entry{start: at, end: at, kinds: map[model.Kind]bool{}}
						entries[k][uint64(c.Cursor.Index)] = e
					}
					e.start, e.end = min(e.start, at), max(e.end, at)
					e.kinds[c.Kind] = true
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
	keys := make([]runKey, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		return a.group.String()+a.project.String()+a.org.String() < b.group.String()+b.project.String()+b.org.String()
	})
	// One gap per CONTIGUOUS run of candidate indexes, each entry counted exactly once: the
	// worker declares only what it enumerated, so a gap can never cover a not-yet-expired
	// entry that sits between two candidates (control refuses a worker gap whose Count is not
	// its whole interval).
	for _, k := range keys {
		indexes := make([]uint64, 0, len(entries[k]))
		for i := range entries[k] {
			indexes = append(indexes, i)
		}
		sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
		for from := 0; from < len(indexes); {
			to := from
			for to+1 < len(indexes) && indexes[to+1] == indexes[to]+1 {
				to++
			}
			gap := model.EvidenceGap{Org: k.org, Project: k.project, Group: k.group, After: model.Uint64(indexes[from] - 1), Through: model.Uint64(indexes[to]), Count: model.Uint64(to - from + 1), Reason: "unprocessed_expiry", RecordedAt: now}
			kinds := map[model.Kind]bool{}
			for _, i := range indexes[from : to+1] {
				e := entries[k][i]
				if gap.Start == 0 || e.start < gap.Start {
					gap.Start = e.start
				}
				gap.End = max(gap.End, e.end)
				for kind := range e.kinds {
					kinds[kind] = true
				}
			}
			for kind := range kinds {
				gap.Signals = append(gap.Signals, kind)
			}
			sort.Slice(gap.Signals, func(i, j int) bool { return gap.Signals[i] < gap.Signals[j] })
			from = to + 1
			if _, err := s.cfg.Control.RecordEvidenceGap(ctx, gap); err != nil {
				held = true // the journal is held; nothing of this run is erased
				errs = append(errs, err)
				continue
			}
			s.mu.Lock()
			s.status.GapsRecorded++
			s.mu.Unlock()
		}
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
