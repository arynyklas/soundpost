// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"sync"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// Service is the retention/deletion authority. It never starts goroutines until
// Start; Delete/PollDelete/DeleteGeneration work without the worker.
type Service struct {
	cfg    Config
	worker WorkerConfig
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
	status WorkerStatus
	last   struct{ snapshot, expiry time.Time }
}

// New validates the wiring and registers the control dispatchers (idempotent
// registration by the first Service only; a second New on the same Store fails).
func New(cfg Config) (*Service, error) {
	if cfg.Control == nil || cfg.Base == nil || cfg.Data == nil {
		return nil, model.Fail(model.Invalid)
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if err := cfg.Control.BindRetention(); err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, worker: cfg.Worker.withDefaults()}, nil
}

func (s *Service) authority() Authority {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.Authority
}

// UseAuthority installs the independently durable restore authority on a Service
// built without one (the application owns exactly one Service per control store,
// and the authority comes from operator configuration that is not known when the
// Service is built). It may be installed once; deletions begun before it exist
// do not require a checkpoint, deletions begun after it do.
func (s *Service) UseAuthority(a Authority) error {
	if a == nil {
		return model.Fail(model.Invalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Authority != nil {
		return model.Fail(model.Conflict)
	}
	s.cfg.Authority = a
	return nil
}

func (s *Service) now() model.UnixNano { return model.UnixNano(s.cfg.Clock().UnixNano()) }

// Delete is C11 Delete: one durable control command begins the saga (read
// denial, generation advance) and returns the 202-style fencing receipt, or a
// held receipt. Retrying the same CommandID returns the original outcome.
func (s *Service) Delete(ctx context.Context, scope auth.Scope, req DeleteRequest) (DeleteReceipt, error) {
	if req.OrgID != scope.OrgID() || req.CommandID == (model.ID{}) {
		return DeleteReceipt{}, model.Fail(model.NotFound)
	}
	at := s.now()
	payload, err := json.Marshal(control.DeleteScope{Mode: req.Mode, Projects: req.ProjectIDs, Signals: req.Signals, Start: req.Start, End: req.End, Entities: req.EntityIDs, Reason: req.Reason, At: at, PhysicalDeadline: at + model.UnixNano(s.worker.PhysicalWithin), BackupDeadline: at + model.UnixNano(s.worker.BackupWithin), AuthorityRequired: s.authority() != nil})
	if err != nil {
		return DeleteReceipt{}, model.Fail(model.Invalid)
	}
	res, err := s.cfg.Control.Transact(ctx, scope, control.Command{CommandID: req.CommandID, ExpectedRevision: req.ExpectedRevision, Kind: string(control.KindDeleteScope), Payload: payload})
	if err != nil {
		return DeleteReceipt{}, err
	}
	if len(res.AffectedIDs) != 1 {
		return DeleteReceipt{}, model.Fail(model.Corrupt)
	}
	return s.receipt(ctx, scope.OrgID(), res.AffectedIDs[0])
}

// PollDelete is C11 PollDelete. A scope for another organization (or an
// operation that does not exist) is NotFound.
func (s *Service) PollDelete(ctx context.Context, scope auth.Scope, operation model.ID) (DeleteReceipt, error) {
	if err := s.cfg.Control.View(ctx, func(st control.State) error {
		if err := scope.ValidateControlState(st); err != nil {
			return err
		}
		if scope.Permission() != auth.OrgAdmin || !st.Orgs[scope.OrgID().String()].Admins[scope.PrincipalID().String()] {
			return model.Fail(model.NotFound)
		}
		return nil
	}); err != nil {
		return DeleteReceipt{}, err
	}
	return s.receipt(ctx, scope.OrgID(), operation)
}

// Resume explicitly starts a held deletion once its holds are released.
func (s *Service) Resume(ctx context.Context, scope auth.Scope, operation model.ID) (DeleteReceipt, error) {
	var revision model.Revision
	if err := s.cfg.Control.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
		return DeleteReceipt{}, err
	}
	payload, _ := json.Marshal(control.BeginFence{Operation: operation, At: s.now()})
	if _, err := s.cfg.Control.Transact(ctx, scope, control.Command{CommandID: model.NewID(), ExpectedRevision: revision, Kind: string(control.KindBeginFence), Payload: payload}); err != nil {
		return DeleteReceipt{}, err
	}
	return s.receipt(ctx, scope.OrgID(), operation)
}

func (s *Service) receipt(ctx context.Context, org, id model.ID) (out DeleteReceipt, err error) {
	err = s.cfg.Control.View(ctx, func(st control.State) error {
		op, ok := st.Deletions[id.String()]
		if !ok || op.Predicate.Org != org {
			return model.Fail(model.NotFound)
		}
		out = receiptOf(st, op)
		return nil
	})
	return
}
func receiptOf(st control.State, op model.DeletionOperation) DeleteReceipt {
	r := DeleteReceipt{OperationID: op.Predicate.Operation, Mode: op.Predicate.Mode, Phase: op.Phase, Generation: uint64(op.Predicate.Generation), Revision: st.Revision, Progress: strconv.Itoa(len(op.Barriers)) + "/" + strconv.Itoa(model.DeleteSlots), PhysicalDeadline: op.PhysicalDeadline, BackupDeadline: op.BackupDeadline, Holds: op.Holds, SafeReason: op.SafeReason, Physical: PhysicalPending}
	if op.PhysicalAt != 0 {
		r.Physical = PhysicalDone
	} else if op.Phase != model.DeletePhaseHeld {
		for _, h := range st.Holds {
			if h.Overlaps(op.Predicate) {
				r.Physical = PhysicalHeld
				break
			}
		}
	}
	return r
}

// DeleteGeneration implements auth.DeleteGenerations: the source-lifecycle base
// plus the durable, monotonic per-org deletion counter. Begin, completion,
// artifact GC, retention expiry and physical erasure after a hold release all
// advance the counter through control BEFORE they report their phase, so a
// cache entry, cursor, replay position or export ticket minted under an older
// generation is dead.
func (s *Service) DeleteGeneration(ctx context.Context, org model.ID, projects []model.ID) (uint64, error) {
	base, err := s.cfg.Base.DeleteGeneration(ctx, org, projects)
	if err != nil {
		return 0, err
	}
	own, err := s.cfg.Control.DeleteGeneration(ctx, org)
	if err != nil {
		return 0, err
	}
	return base + own, nil
}

// BuildLedger derives the digest ledger (and the exact tombstones) of every
// completed deletion from control state. Entries are ordered by begin revision.
func BuildLedger(st control.State) (replica.Ledger, []model.DeletePredicate) {
	var ops []model.DeletionOperation
	for _, op := range st.Deletions {
		if op.Phase == model.DeletePhaseComplete {
			ops = append(ops, op)
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].BeginRevision != ops[j].BeginRevision {
			return ops[i].BeginRevision < ops[j].BeginRevision
		}
		return ops[i].Predicate.Operation.String() < ops[j].Predicate.Operation.String()
	})
	var total uint64
	for _, g := range st.DeleteGenerations {
		total += g
	}
	ledger := replica.Ledger{Version: 1, Group: st.Installation, Generation: total, Entries: []replica.LedgerEntry{}}
	tombstones := make([]model.DeletePredicate, 0, len(ops))
	for i, op := range ops {
		ledger.Entries = append(ledger.Entries, replica.LedgerEntry{Index: uint64(i + 1), Kind: op.Predicate.Mode, Hash: op.Predicate.Digest()})
		tombstones = append(tombstones, op.Predicate)
	}
	return ledger, tombstones
}

// Restore re-applies the independent authority's current ledger to a restored
// installation before it may open: control gets the missing tombstones (with
// their retirement effects), then every data slot gets its barrier, and only
// then does the engine's restore gate open. An unverifiable authority fails
// closed.
func (s *Service) Restore(ctx context.Context, authority Authority) error {
	if authority == nil {
		return model.Fail(model.Unavailable)
	}
	ledger, err := authority.CurrentDeletionLedger(ctx)
	if err != nil {
		return model.Fail(model.Unavailable)
	}
	source, ok := authority.(TombstoneSource)
	if !ok {
		return model.Fail(model.Unavailable)
	}
	tombstones, err := source.CurrentDeletionTombstones(ctx)
	if err != nil || len(tombstones) != len(ledger.Entries) {
		return model.Fail(model.Unavailable)
	}
	for i, p := range tombstones {
		if ledger.Entries[i].Hash != p.Digest() || ledger.Entries[i].Index != uint64(i+1) || p.Validate() != nil {
			return model.Fail(model.Corrupt)
		}
	}
	if err = s.cfg.Control.ImportDeletions(ctx, tombstones, s.now()); err != nil {
		return err
	}
	return s.cfg.Data.ApplyDeletionLedger(ctx, ledger, tombstones)
}
