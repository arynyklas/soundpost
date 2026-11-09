// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sort"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"strings"
)

// DeleteScope is the KindDeleteScope payload: one C11 deletion request already
// reduced to deterministic values. Time and deadlines are supplied by the
// caller (apply never reads a clock); the operation ID is the command ID.
type DeleteScope struct {
	Mode              string         `json:"mode"`
	Projects          []model.ID     `json:"projects,omitempty"`
	Signals           []model.Kind   `json:"signals,omitempty"`
	Start             model.UnixNano `json:"start_ns,omitempty"`
	End               model.UnixNano `json:"end_ns,omitempty"`
	Entities          []model.ID     `json:"entities,omitempty"`
	Reason            string         `json:"reason"`
	At                model.UnixNano `json:"at_ns"`
	PhysicalDeadline  model.UnixNano `json:"physical_deadline_ns"`
	BackupDeadline    model.UnixNano `json:"backup_deadline_ns"`
	AuthorityRequired bool           `json:"authority_required"`
}

// BeginFence (KindBeginFence) resumes a held operation once no hold blocks it.
type BeginFence struct {
	Operation model.ID       `json:"operation"`
	At        model.UnixNano `json:"at_ns"`
}

// RecordBarrier is the step of KindCompleteFence that records data-slot barrier
// cursors; it may be partial and is repeated until every slot is recorded.
type RecordBarrier struct {
	Operation model.ID       `json:"operation"`
	Barriers  []model.Cursor `json:"barriers"`
}

// CompleteFence is the final step of KindCompleteFence.
type CompleteFence struct {
	Operation model.ID                 `json:"operation"`
	At        model.UnixNano           `json:"at_ns"`
	Authority *model.DeletionAuthority `json:"authority,omitempty"`
}

// ValidateReplicatedDeleteBarrier is the replication-time check of a data-slot
// tombstone (C12 step 2): a barrier is only ordered for an operation control
// actually committed, with exactly the committed predicate. A held or failed
// operation never fences data; a complete one may still receive barriers when a
// restored installation re-applies its deletion ledger.
func (s *Store) ValidateReplicatedDeleteBarrier(ctx context.Context, b model.DeleteBarrier) error {
	return s.View(ctx, func(st State) error {
		op, ok := st.Deletions[b.Predicate.Operation.String()]
		if !ok || op.Phase != model.DeletePhaseFencing && op.Phase != model.DeletePhaseComplete {
			return model.Fail(model.Stale)
		}
		want, err := model.CanonicalJSON(op.Predicate)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		got, err := model.CanonicalJSON(b.Predicate)
		if err != nil || !bytes.Equal(want, got) {
			return model.Fail(model.Stale)
		}
		return nil
	})
}

// PlaceHold, ReleaseHold and SetRetention are the PolicyChange arms handled here.
type PlaceHold struct {
	Projects []model.ID     `json:"projects,omitempty"`
	Signals  []model.Kind   `json:"signals,omitempty"`
	Start    model.UnixNano `json:"start_ns,omitempty"`
	End      model.UnixNano `json:"end_ns,omitempty"`
	Entities []model.ID     `json:"entities,omitempty"`
	Reason   string         `json:"reason"`
	At       model.UnixNano `json:"at_ns"`
}
type ReleaseHold struct {
	Hold   model.ID       `json:"hold"`
	Reason string         `json:"reason"`
	At     model.UnixNano `json:"at_ns"`
}
type SetRetention struct {
	Project   *model.ID             `json:"project,omitempty"`
	Days      map[model.Kind]uint32 `json:"days"`
	RawDays   uint32                `json:"raw_days,omitempty"`
	Artifacts uint32                `json:"artifact_days,omitempty"`
	Effective model.UnixNano        `json:"effective_ns"`
	Reason    string                `json:"reason"`
	At        model.UnixNano        `json:"at_ns"`
}

// PolicyChange is the closed KindPolicyChange payload of this module: exactly
// one arm matching Kind. Other policy owners extend this dispatcher.
type PolicyChange struct {
	Kind      string        `json:"kind"` // hold_place | hold_release | retention_policy
	Hold      *PlaceHold    `json:"hold,omitempty"`
	Release   *ReleaseHold  `json:"release,omitempty"`
	Retention *SetRetention `json:"retention,omitempty"`
}

// FenceStep is the KindCompleteFence payload: record barriers, complete or fail.
type FenceStep struct {
	Step       string                   `json:"step"` // barrier | complete | fail
	Operation  model.ID                 `json:"operation"`
	Barriers   []model.Cursor           `json:"barriers,omitempty"`
	At         model.UnixNano           `json:"at_ns,omitempty"`
	Authority  *model.DeletionAuthority `json:"authority,omitempty"`
	SafeReason string                   `json:"safe_reason,omitempty"`
}

// BindRetention installs the closed deterministic dispatchers for the C12
// deletion saga, legal holds, retention policy versions and evidence gaps.
func (s *Store) BindRetention() error {
	for kind, h := range map[CommandKind]Handler{KindDeleteScope: applyDeleteScope, KindBeginFence: applyBeginFence, KindCompleteFence: applyFenceStep, KindPolicyChange: applyPolicyChange, KindRecordEvidenceGap: applyEvidenceGap} {
		if err := s.RegisterHandler(kind, h); err != nil {
			return err
		}
	}
	return nil
}

func strictPayload(raw json.RawMessage, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return model.Fail(model.Invalid)
	}
	if d.Decode(new(any)) != io.EOF {
		return model.Fail(model.Invalid)
	}
	return nil
}

// orgAdmin binds a command to an organization administrator of exactly that
// organization; everything else is indistinguishable from an absent target.
func orgAdmin(scope auth.Scope, st *State) (model.ControlOrg, error) {
	o, ok := st.Orgs[scope.OrgID().String()]
	if !ok || scope.Permission() != auth.OrgAdmin || !o.Admins[scope.PrincipalID().String()] {
		return o, model.Fail(model.NotFound)
	}
	return o, nil
}
func cleanReason(v string) (string, bool) {
	v = strings.TrimSpace(v)
	return v, v != "" && len(v) <= 512
}
func bumpGeneration(st *State, org model.ID) uint64 {
	if st.DeleteGenerations == nil {
		st.DeleteGenerations = map[string]uint64{}
	}
	st.DeleteGenerations[org.String()]++
	return st.DeleteGenerations[org.String()]
}
func audit(st *State, principal, org model.ID, action, reason string, at model.UnixNano, targets []model.ID) {
	o := st.Orgs[org.String()]
	st.Audits = append(st.Audits, model.ControlAudit{ID: model.NewID(), Principal: principal, Org: org.String(), Action: action, Reason: reason, Time: int64(at), PolicyEpoch: o.Epoch, Targets: targets, RequestID: targets[0], Outcome: model.AuditAllowed})
}
func blockingHolds(st *State, p model.DeletePredicate) []model.ID {
	var out []model.ID
	for _, h := range st.Holds {
		if h.Overlaps(p) {
			out = append(out, h.ID)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// retireScope makes a retirement unreadable and unwritable at once: the org
// policy epoch moves (every scope minted earlier dies at Revalidate), retired
// projects leave the authorizable set, and their sources are retired.
func retireScope(st *State, p model.DeletePredicate) {
	if p.Mode != model.DeleteRetireOrg && p.Mode != model.DeleteRetireProject {
		return
	}
	// An import can retire an organization this state has never contained: the
	// retirement markers are recorded, but no organization is created for them.
	o, known := st.Orgs[p.Org.String()]
	o.Epoch++
	if st.RetiredProjects == nil {
		st.RetiredProjects = map[string]model.ID{}
	}
	if p.Mode == model.DeleteRetireOrg {
		if st.RetiredOrgs == nil {
			st.RetiredOrgs = map[string]model.ID{}
		}
		st.RetiredOrgs[p.Org.String()] = p.Operation
		for id := range o.Projects {
			st.RetiredProjects[p.Org.String()+":"+id] = p.Operation
		}
		o.Projects = map[string]string{}
	} else {
		for _, id := range p.Projects {
			delete(o.Projects, id.String())
			st.RetiredProjects[p.Org.String()+":"+id.String()] = p.Operation
		}
	}
	if known {
		st.Orgs[p.Org.String()] = o
	}
	for key, src := range st.Sources {
		if src.Org == p.Org && p.CoversProject(p.Org, src.Project) {
			src.Retired = true
			st.Sources[key] = src
		}
	}
}
func beginDeletion(st *State, op *model.DeletionOperation) {
	op.Predicate.Generation = model.Uint64(bumpGeneration(st, op.Predicate.Org))
	op.Phase, op.Holds, op.BeginRevision = model.DeletePhaseFencing, nil, st.Revision+1
	retireScope(st, op.Predicate)
}
func putDeletion(st *State, op model.DeletionOperation) {
	if st.Deletions == nil {
		st.Deletions = map[string]model.DeletionOperation{}
	}
	st.Deletions[op.Predicate.Operation.String()] = op
}

func applyDeleteScope(scope auth.Scope, st *State, cmd Command) (Effect, error) {
	var req DeleteScope
	if err := strictPayload(cmd.Payload, &req); err != nil {
		return Effect{}, err
	}
	o, err := orgAdmin(scope, st)
	if err != nil {
		return Effect{}, err
	}
	org := scope.OrgID()
	if _, retired := st.RetiredOrgs[org.String()]; retired {
		return Effect{}, model.Fail(model.NotFound)
	}
	reason, ok := cleanReason(req.Reason)
	if !ok || req.At <= 0 || req.PhysicalDeadline < req.At || req.BackupDeadline < req.At {
		return Effect{}, model.Fail(model.Invalid)
	}
	pred := model.DeletePredicate{Operation: cmd.CommandID, Org: org, Mode: req.Mode, Projects: req.Projects, Signals: req.Signals, Start: req.Start, End: req.End, Entities: req.Entities}
	if err = pred.Validate(); err != nil {
		return Effect{}, err
	}
	for _, p := range pred.Projects {
		if _, ok := o.Projects[p.String()]; !ok {
			return Effect{}, model.Fail(model.NotFound)
		}
	}
	if _, exists := st.Deletions[cmd.CommandID.String()]; exists {
		return Effect{}, model.Fail(model.Conflict)
	}
	op := model.DeletionOperation{Predicate: pred, Principal: scope.PrincipalID(), Reason: reason, RequestedAt: req.At, AuthorityRequired: req.AuthorityRequired, PhysicalDeadline: req.PhysicalDeadline, BackupDeadline: req.BackupDeadline}
	targets := append([]model.ID{cmd.CommandID}, pred.Projects...)
	if holds := blockingHolds(st, pred); len(holds) > 0 {
		op.Phase, op.Holds, op.BeginRevision = model.DeletePhaseHeld, holds, st.Revision+1
		putDeletion(st, op)
		audit(st, scope.PrincipalID(), org, "delete.held", reason, req.At, targets)
		return Effect{AffectedIDs: []model.ID{cmd.CommandID}, Phase: model.DeletePhaseHeld}, nil
	}
	beginDeletion(st, &op)
	putDeletion(st, op)
	audit(st, scope.PrincipalID(), org, "delete.begin", reason, req.At, targets)
	return Effect{AffectedIDs: []model.ID{cmd.CommandID}, Phase: model.DeletePhaseFencing}, nil
}

func applyBeginFence(scope auth.Scope, st *State, cmd Command) (Effect, error) {
	var req BeginFence
	if err := strictPayload(cmd.Payload, &req); err != nil {
		return Effect{}, err
	}
	if _, err := orgAdmin(scope, st); err != nil {
		return Effect{}, err
	}
	op, ok := st.Deletions[req.Operation.String()]
	if !ok || op.Predicate.Org != scope.OrgID() {
		return Effect{}, model.Fail(model.NotFound)
	}
	switch op.Phase {
	case model.DeletePhaseFencing, model.DeletePhaseComplete:
		return Effect{AffectedIDs: []model.ID{op.Predicate.Operation}, Phase: op.Phase}, nil
	case model.DeletePhaseHeld:
	default:
		return Effect{}, model.Fail(model.Conflict)
	}
	if holds := blockingHolds(st, op.Predicate); len(holds) > 0 {
		op.Holds = holds
		putDeletion(st, op)
		return Effect{AffectedIDs: []model.ID{op.Predicate.Operation}, Phase: model.DeletePhaseHeld}, nil
	}
	beginDeletion(st, &op)
	putDeletion(st, op)
	audit(st, scope.PrincipalID(), op.Predicate.Org, "delete.begin", op.Reason, req.At, []model.ID{op.Predicate.Operation})
	return Effect{AffectedIDs: []model.ID{op.Predicate.Operation}, Phase: model.DeletePhaseFencing}, nil
}

func recordBarriers(st *State, id model.ID, barriers []model.Cursor) (model.DeletionOperation, error) {
	op, ok := st.Deletions[id.String()]
	if !ok {
		return op, model.Fail(model.NotFound)
	}
	if op.Phase != model.DeletePhaseFencing && op.Phase != model.DeletePhaseComplete {
		return op, model.Fail(model.Conflict)
	}
	have := map[model.ID]model.Cursor{}
	for _, c := range op.Barriers {
		have[c.Group] = c
	}
	for _, c := range barriers {
		if c.Group == (model.ID{}) || c.Index == 0 {
			return op, model.Fail(model.Invalid)
		}
		if old, ok := have[c.Group]; ok {
			if old != c {
				return op, model.Fail(model.Conflict)
			}
			continue
		}
		if len(have) >= model.DeleteSlots {
			return op, model.Fail(model.Invalid)
		}
		have[c.Group] = c
	}
	if len(have) == len(op.Barriers) {
		return op, nil
	}
	op.Barriers = op.Barriers[:0]
	for _, c := range have {
		op.Barriers = append(op.Barriers, c)
	}
	sort.Slice(op.Barriers, func(i, j int) bool { return op.Barriers[i].Group.String() < op.Barriers[j].Group.String() })
	putDeletion(st, op)
	return op, nil
}
func completeDeletion(st *State, id model.ID, at model.UnixNano, authority *model.DeletionAuthority) (model.DeletionOperation, error) {
	op, ok := st.Deletions[id.String()]
	if !ok {
		return op, model.Fail(model.NotFound)
	}
	switch op.Phase {
	case model.DeletePhaseComplete:
		return op, nil
	case model.DeletePhaseFencing:
	default:
		return op, model.Fail(model.Conflict)
	}
	if at <= 0 || len(op.Barriers) != model.DeleteSlots {
		return op, model.Fail(model.Unavailable) // an unavailable group blocks completion; it is never skipped
	}
	if op.AuthorityRequired {
		if authority == nil || uint64(authority.Generation) < uint64(op.Predicate.Generation) || authority.At <= 0 {
			return op, model.Fail(model.Unavailable)
		}
		held := *authority
		op.Authority = &held
	}
	op.Phase, op.CompletedAt = model.DeletePhaseComplete, at
	bumpGeneration(st, op.Predicate.Org)
	putDeletion(st, op)
	audit(st, op.Principal, op.Predicate.Org, "delete.complete", op.Reason, at, []model.ID{op.Predicate.Operation})
	return op, nil
}

var failReasons = map[string]bool{"barrier_conflict": true, "authority_rejected": true, "operator_failed": true}

func failDeletion(st *State, id model.ID, at model.UnixNano, reason string) (model.DeletionOperation, error) {
	op, ok := st.Deletions[id.String()]
	if !ok {
		return op, model.Fail(model.NotFound)
	}
	if op.Phase != model.DeletePhaseFencing || !failReasons[reason] {
		return op, model.Fail(model.Conflict)
	}
	// A failed operation keeps its predicate active: nothing is ever un-deleted.
	op.Phase, op.SafeReason, op.CompletedAt = model.DeletePhaseFailed, reason, at
	putDeletion(st, op)
	audit(st, op.Principal, op.Predicate.Org, "delete.failed", reason, at, []model.ID{op.Predicate.Operation})
	return op, nil
}

func applyFenceStep(scope auth.Scope, st *State, cmd Command) (Effect, error) {
	var step FenceStep
	if err := strictPayload(cmd.Payload, &step); err != nil {
		return Effect{}, err
	}
	if _, err := orgAdmin(scope, st); err != nil {
		return Effect{}, err
	}
	if cur, ok := st.Deletions[step.Operation.String()]; !ok || cur.Predicate.Org != scope.OrgID() {
		return Effect{}, model.Fail(model.NotFound)
	}
	var op model.DeletionOperation
	var err error
	switch step.Step {
	case "barrier":
		op, err = recordBarriers(st, step.Operation, step.Barriers)
	case "complete":
		op, err = completeDeletion(st, step.Operation, step.At, step.Authority)
	case "fail":
		op, err = failDeletion(st, step.Operation, step.At, step.SafeReason)
	default:
		err = model.Fail(model.Invalid)
	}
	if err != nil {
		return Effect{}, err
	}
	return Effect{AffectedIDs: []model.ID{step.Operation}, Phase: op.Phase}, nil
}

// ---- in-process (worker) transitions: same pure functions, no scope ----

func (s *Store) RecordBarriers(ctx context.Context, operation model.ID, barriers []model.Cursor) (out model.DeletionOperation, err error) {
	err = s.Update(ctx, func(st *State) (e error) { out, e = recordBarriers(st, operation, barriers); return })
	return
}
func (s *Store) CompleteDeletion(ctx context.Context, operation model.ID, at model.UnixNano, authority *model.DeletionAuthority) (out model.DeletionOperation, err error) {
	err = s.Update(ctx, func(st *State) (e error) { out, e = completeDeletion(st, operation, at, authority); return })
	return
}
func (s *Store) FailDeletion(ctx context.Context, operation model.ID, at model.UnixNano, reason string) (out model.DeletionOperation, err error) {
	err = s.Update(ctx, func(st *State) (e error) { out, e = failDeletion(st, operation, at, reason); return })
	return
}

// RecordPhysicalCleanup advances the org's delete generation BEFORE it reports
// local erasure (every cache/ticket bound to an older generation is dead first)
// and stamps the operations whose bytes are physically gone.
func (s *Store) RecordPhysicalCleanup(ctx context.Context, org model.ID, operations []model.ID, at model.UnixNano) error {
	return s.Update(ctx, func(st *State) error {
		if _, ok := st.Orgs[org.String()]; !ok {
			return model.Fail(model.NotFound)
		}
		bumpGeneration(st, org)
		for _, id := range operations {
			op, ok := st.Deletions[id.String()]
			if !ok || op.Predicate.Org != org || op.Phase != model.DeletePhaseComplete {
				return model.Fail(model.Conflict)
			}
			if op.PhysicalAt == 0 {
				op.PhysicalAt = at
				putDeletion(st, op)
			}
		}
		return nil
	})
}

// AdvanceDeleteGeneration is the seam for every other path that erases readable
// bytes (retention expiry, artifact GC, hold release followed by erasure).
func (s *Store) AdvanceDeleteGeneration(ctx context.Context, org model.ID) (out uint64, err error) {
	err = s.Update(ctx, func(st *State) error {
		if _, ok := st.Orgs[org.String()]; !ok {
			return model.Fail(model.NotFound)
		}
		out = bumpGeneration(st, org)
		return nil
	})
	return
}

// ImportDeletions re-installs completed tombstones from the restore authority
// into a restored control state (idempotent): the retirement effects are
// re-applied and the generation never moves backwards.
//
// The authority is installation-wide and monotonic, so it can name an
// organization the restored state has never contained (created and retired
// after the backup's cut). Such a tombstone is still recorded: the predicate is
// keyed by IDs and denies that organization's data whenever it is consulted, and
// a retirement stays permanent (the org and project IDs it retired can never be
// created). Only the per-organization state the restored control does not have
// (delete generation, policy epoch) is left alone: an organization is never
// invented by an import.
func (s *Store) ImportDeletions(ctx context.Context, tombstones []model.DeletePredicate, at model.UnixNano) error {
	return s.Update(ctx, func(st *State) error {
		for _, p := range tombstones {
			if err := p.Validate(); err != nil {
				return err
			}
			if _, ok := st.Deletions[p.Operation.String()]; ok {
				continue
			}
			if _, known := st.Orgs[p.Org.String()]; known {
				if uint64(p.Generation) > st.DeleteGenerations[p.Org.String()] {
					if st.DeleteGenerations == nil {
						st.DeleteGenerations = map[string]uint64{}
					}
					st.DeleteGenerations[p.Org.String()] = uint64(p.Generation)
				}
				bumpGeneration(st, p.Org)
			}
			putDeletion(st, model.DeletionOperation{Predicate: p, Phase: model.DeletePhaseComplete, Principal: st.Installation, Reason: "restored from deletion authority", RequestedAt: at, BeginRevision: st.Revision + 1, CompletedAt: at, SafeReason: "restored_from_authority"})
			retireScope(st, p)
		}
		return nil
	})
}

func (s *Store) DeletionOperation(ctx context.Context, operation model.ID) (out model.DeletionOperation, found bool, err error) {
	err = s.View(ctx, func(st State) error { out, found = st.Deletions[operation.String()]; return nil })
	return
}
func (s *Store) DeletionOperations(ctx context.Context) (out []model.DeletionOperation, err error) {
	err = s.View(ctx, func(st State) error {
		for _, op := range st.Deletions {
			out = append(out, op)
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].BeginRevision != out[j].BeginRevision {
				return out[i].BeginRevision < out[j].BeginRevision
			}
			return out[i].Predicate.Operation.String() < out[j].Predicate.Operation.String()
		})
		return nil
	})
	return
}

// ActiveDeletions returns the tombstones that hide data right now: operations
// fencing, complete or failed (held ones have not begun). It implements the
// storage DeletionView seam.
func (s *Store) ActiveDeletions(ctx context.Context, org model.ID, projects []model.ID) (out []model.DeletePredicate, err error) {
	err = s.View(ctx, func(st State) error { out = activeDeletions(st, org, projects); return nil })
	return
}
func activeDeletions(st State, org model.ID, projects []model.ID) []model.DeletePredicate {
	var out []model.DeletePredicate
	for _, op := range st.Deletions {
		if op.Phase == model.DeletePhaseHeld || op.Predicate.Org != org {
			continue
		}
		hit := len(projects) == 0 || op.Predicate.Mode == model.DeleteRetireOrg
		for _, p := range projects {
			hit = hit || op.Predicate.CoversProject(org, p)
		}
		if hit {
			out = append(out, op.Predicate)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Operation.String() < out[j].Operation.String() })
	return out
}

// EffectSuppressed is the hook every derived-effect consumer (rules, issues,
// notifications, outbox) calls inside the same control transaction that would
// commit the effect, so a deletion and an effect can never interleave.
func EffectSuppressed(st State, org, project model.ID, kind model.Kind, at model.UnixNano, entity *model.ID) bool {
	for _, p := range activeDeletions(st, org, nil) {
		if p.CoversOrigin(org, project, kind, at, entity) {
			return true
		}
	}
	return false
}

func (s *Store) DeleteGeneration(ctx context.Context, org model.ID) (out uint64, err error) {
	err = s.View(ctx, func(st State) error {
		if _, ok := st.Orgs[org.String()]; !ok {
			return model.Fail(model.NotFound)
		}
		out = st.DeleteGenerations[org.String()]
		return nil
	})
	return
}
