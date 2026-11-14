// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sort"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// Control is the part of the C05 control store that commits rule commands
// (satisfied by *control.Store).
type Control interface {
	Transact(ctx context.Context, scope auth.Scope, cmd control.Command) (control.Result, error)
	View(ctx context.Context, fn func(control.State) error) error
}

// ControlStore adds the rule reads (satisfied by *control.Store). There is no
// second rule store: these read the same committed control state.
type ControlStore interface {
	Control
	RuleBook(ctx context.Context, scope auth.Scope, project, rule model.ID) (control.RuleBook, bool, error)
	RuleOutputs(ctx context.Context, scope auth.Scope, project, rule model.ID, phase string, limit int) ([]control.RuleOutput, error)
}

// maxRevisionRetries bounds the retries of one command that lost a race for the
// control revision (not a semantic conflict).
const maxRevisionRetries = 8

// transact submits one rule command. The control revision is read immediately
// before each attempt; an attempt that only lost a revision race is retried, so
// the command ID (deterministic, owned by the caller) is what makes every retry,
// including one after a lost response, a no-op once committed.
//
// A Conflict is a lost race exactly when the control revision is no longer the
// one the command expected: that is read back from control's state, not
// inferred from the wording of the fault. A semantic conflict (the evaluation
// disagrees with committed state) leaves the revision where it was and is
// returned as it is.
func transact(ctx context.Context, ctl Control, scope auth.Scope, id model.ID, c control.RuleCommand) (control.Result, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return control.Result{}, model.Fail(model.Invalid)
	}
	readRevision := func() (revision model.Revision, err error) {
		err = ctl.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		return revision, err
	}
	for range maxRevisionRetries {
		revision, err := readRevision()
		if err != nil {
			return control.Result{}, err
		}
		res, err := ctl.Transact(ctx, scope, control.Command{CommandID: id, ExpectedRevision: revision, Kind: string(control.KindApplyRuleEvaluation), Payload: raw})
		if err == nil {
			return res, nil
		}
		if faultCode(err) == model.Conflict {
			if now, rerr := readRevision(); rerr == nil && now != revision {
				continue // the revision moved; the command did not conflict with anything
			}
		}
		return control.Result{}, err
	}
	fault := model.Fail(model.Unavailable)
	fault.Retryable = true
	return control.Result{}, fault
}

// commandPayload is the payload of an evaluation as control receives it, and its
// digest. The command travels as JSON, which compacts and HTML-escapes a raw
// payload; the digest control verifies is over those exact bytes.
func commandPayload(eval Evaluation) ([]byte, model.Hash, error) {
	canonical, _, err := eval.Canonical()
	if err != nil {
		return nil, model.Hash{}, err
	}
	payload, err := json.Marshal(json.RawMessage(canonical))
	if err != nil {
		return nil, model.Hash{}, model.Fail(model.Invalid)
	}
	return payload, model.Hash(sha256.Sum256(payload)), nil
}

// overflow reports whether the evaluation exceeds what one control command may
// carry (outputs, the committed payload, any output payload), as the closed
// reason code, or "" when it fits. An evaluation that cannot be serialised at all
// cannot be committed either, and Commit reports that; it is not an overflow.
func overflow(eval Evaluation) string {
	if len(eval.Recording)+len(eval.Conditions) > control.MaxRuleOutputs {
		return ReasonTooManyOutputs
	}
	payload, _, err := commandPayload(eval)
	if err != nil {
		return ""
	}
	if len(payload) > control.MaxRuleEvaluationBytes {
		return ReasonPayloadTooLarge
	}
	tooLarge := func(intent any) bool {
		raw, err := model.CanonicalJSON(intent)
		return err == nil && len(raw) > control.MaxRuleOutputBytes
	}
	for _, intent := range eval.Recording {
		if tooLarge(intent) {
			return ReasonPayloadTooLarge
		}
	}
	for _, intent := range eval.Conditions {
		if tooLarge(intent) {
			return ReasonPayloadTooLarge
		}
	}
	return ""
}

// Committer submits evaluations to C05 under a fence.
type Committer struct {
	control Control
	fencer  Fencer
}

// NewCommitter builds a committer. fencer may be nil only where the caller has
// no group to fence against; production binds the control group.
func NewCommitter(ctl Control, fencer Fencer) *Committer {
	return &Committer{control: ctl, fencer: fencer}
}

func (c *Committer) validateLease(ctx context.Context, lease replica.FenceToken) error {
	if lease.Group == (model.ID{}) || lease.Term == 0 {
		return model.Fail(model.Invalid)
	}
	if c.fencer != nil {
		return fenceFault(c.fencer.ValidateFence(ctx, lease))
	}
	return nil
}

// Commit atomically commits the evaluation, its resulting state and its internal
// outputs (recording and condition intents) through the C05
// KindApplyRuleEvaluation command, under lease. The scope must be the
// organization administrator of the evaluation's project (the worker principal).
//
// The command identity covers the evaluation's digest, so retrying the same
// payload is a no-op whenever and however often it is retried, while a different
// payload for the same (rule, version, at) reaches control as a different
// command and is rejected as a conflict: the first committed payload is final.
func (c *Committer) Commit(ctx context.Context, scope auth.Scope, eval Evaluation, lease replica.FenceToken) (control.Result, error) {
	if eval.Org == (model.ID{}) || eval.Org != scope.OrgID() || eval.Project == (model.ID{}) || eval.Rule == (model.ID{}) || eval.Version == 0 || eval.At < 0 || eval.State.Revision == 0 {
		return control.Result{}, model.Fail(model.Invalid)
	}
	if err := c.validateLease(ctx, lease); err != nil {
		return control.Result{}, err
	}
	payload, digest, err := commandPayload(eval)
	if err != nil {
		return control.Result{}, err
	}
	apply := &control.RuleEvaluationApply{
		Project: eval.Project, Rule: eval.Rule, Version: eval.Version, At: eval.At,
		ExpectedStateRevision: eval.State.Revision - 1,
		Mode:                  string(eval.Mode), Health: string(eval.State.Health),
		Digest: digest, Payload: payload, Cursors: append([]model.Cursor{}, eval.Cursors...), Outputs: []control.RuleOutputIntent{},
	}
	for _, intent := range eval.Recording {
		raw, err := model.CanonicalJSON(intent)
		if err != nil {
			return control.Result{}, model.Fail(model.Invalid)
		}
		apply.Outputs = append(apply.Outputs, control.RuleOutputIntent{ID: intent.ID, Kind: control.RuleOutputRecording, Signal: model.Metric, Payload: raw, Inputs: append([]model.Cursor{}, intent.Inputs...)})
	}
	for _, intent := range eval.Conditions {
		raw, err := model.CanonicalJSON(intent)
		if err != nil {
			return control.Result{}, model.Fail(model.Invalid)
		}
		apply.Outputs = append(apply.Outputs, control.RuleOutputIntent{ID: intent.ID, Kind: control.RuleOutputCondition, Signal: eval.Signal, Notify: intent.Notify, Payload: raw, Inputs: append([]model.Cursor{}, eval.Cursors...)})
	}
	id := derive("apply", eval.Org[:], eval.Project[:], eval.Rule[:], u64(uint64(eval.Version)), u64(uint64(eval.At)), digest[:])
	res, err := transact(ctx, c.control, scope, id, control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: apply})
	return res, err
}

// RecordMissed commits evidence that grid points [from, to] of the rule version
// were not evaluated on time. It changes no condition state.
func (c *Committer) RecordMissed(ctx context.Context, scope auth.Scope, rule Rule, m MissedInterval, at model.UnixNano, lease replica.FenceToken) (control.Result, error) {
	if m.From < 0 || m.To < m.From || m.Count == 0 || at <= 0 {
		return control.Result{}, model.Fail(model.Invalid)
	}
	if err := c.validateLease(ctx, lease); err != nil {
		return control.Result{}, err
	}
	org := scope.OrgID()
	id := derive("missed", org[:], rule.Project[:], rule.ID[:], u64(uint64(rule.Version)), u64(uint64(m.From)), u64(uint64(m.To)))
	return transact(ctx, c.control, scope, id, control.RuleCommand{Operation: control.RuleOpMissed, Lease: &lease, Missed: &control.RuleMissedApply{
		Project: rule.Project, Rule: rule.ID, Version: rule.Version, From: m.From, To: m.To, Count: model.Uint64(m.Count), At: at}})
}

// DeclareReplay is the explicit operator replay mode: it commits (audited) that
// late evaluations of the rule whose scheduled time is within [from, to] may
// notify. Without it a backfilled evaluation can never notify.
func (c *Committer) DeclareReplay(ctx context.Context, scope auth.Scope, rule Rule, from, to model.UnixNano, reason string, at model.UnixNano) (control.Result, error) {
	org := scope.OrgID()
	id := derive("replay", org[:], rule.Project[:], rule.ID[:], u64(uint64(from)), u64(uint64(to)))
	return transact(ctx, c.control, scope, id, control.RuleCommand{Operation: control.RuleOpReplay, Replay: &control.RuleReplayApply{
		Project: rule.Project, Rule: rule.ID, From: from, To: to, Reason: reason, At: at}})
}

// CollectRetired garbage-collects the rule facts of a project that has been
// retired (deleted): pending and admitted outputs are suppressed, and every
// retained payload (outputs, evaluations) is dropped from control, so deleted
// telemetry does not outlive the project inside a snapshot or backup. The scope
// is an organization administrator's; it does not name the retired project,
// which can no longer be authorized. The command is deterministic and idempotent.
func (c *Committer) CollectRetired(ctx context.Context, scope auth.Scope, project model.ID) (control.Result, error) {
	if project == (model.ID{}) {
		return control.Result{}, model.Fail(model.Invalid)
	}
	org := scope.OrgID()
	id := derive("retire", org[:], project[:])
	return transact(ctx, c.control, scope, id, control.RuleCommand{Operation: control.RuleOpRetire, Retire: &control.RuleRetireApply{Project: project}})
}

// StateStore is the control read adapter: it reconstructs this package's State
// and Evaluation from the DTOs control keeps, so control never imports rules. It
// satisfies RuleStateReader for project-scoped worker principals (a scope that
// names exactly one project).
type StateStore struct {
	store ControlStore
}

// NewStateStore builds the read adapter over the control store.
func NewStateStore(store ControlStore) *StateStore { return &StateStore{store: store} }

func workerProject(scope auth.Scope) (model.ID, error) {
	projects := scope.ProjectIDs()
	if len(projects) != 1 {
		return model.ID{}, model.Fail(model.Invalid)
	}
	return projects[0], nil
}

func decodeEvaluation(raw json.RawMessage) (Evaluation, error) {
	var ev Evaluation
	if model.StrictJSON(raw, &ev) != nil {
		return Evaluation{}, model.Fail(model.Corrupt)
	}
	return ev, nil
}

func attach(state *State, book control.RuleBook) {
	state.Replays = nil
	for _, w := range book.Replays {
		state.Replays = append(state.Replays, ReplayWindow{From: w.From, To: w.To})
	}
	state.Missed = nil
	for _, m := range book.Missed {
		state.Missed = append(state.Missed, MissedInterval{From: m.From, To: m.To, Count: uint64(m.Count)})
	}
}

// Read returns the committed state of the newest version of the rule.
func (s *StateStore) Read(ctx context.Context, scope auth.Scope, ruleID model.ID) (State, error) {
	project, err := workerProject(scope)
	if err != nil {
		return State{}, err
	}
	book, found, err := s.store.RuleBook(ctx, scope, project, ruleID)
	if err != nil {
		return State{}, err
	}
	if !found {
		return State{}, nil
	}
	head, ok := book.Version(book.Head)
	if !ok || len(head.Recent) == 0 || len(head.Recent[len(head.Recent)-1].Payload) == 0 {
		return State{}, model.Fail(model.Corrupt)
	}
	ev, err := decodeEvaluation(head.Recent[len(head.Recent)-1].Payload)
	if err != nil {
		return State{}, err
	}
	if ev.State.Org != scope.OrgID() || ev.State.Rule != ruleID || ev.State.Version != book.Head || ev.State.Revision != head.StateRevision {
		return State{}, model.Fail(model.Corrupt)
	}
	state := ev.State
	attach(&state, book)
	return state, nil
}

// ReadEvaluation returns the committed evaluation of (version, at) as committed.
func (s *StateStore) ReadEvaluation(ctx context.Context, scope auth.Scope, ruleID model.ID, version model.Revision, at model.UnixNano) (Evaluation, bool, error) {
	project, err := workerProject(scope)
	if err != nil {
		return Evaluation{}, false, err
	}
	book, found, err := s.store.RuleBook(ctx, scope, project, ruleID)
	if err != nil || !found {
		return Evaluation{}, false, err
	}
	v, ok := book.Version(version)
	if !ok {
		return Evaluation{}, false, nil
	}
	for _, rec := range v.Recent {
		if rec.At == at {
			ev, err := decodeEvaluation(rec.Payload)
			return ev, err == nil, err
		}
	}
	if v.Last != nil && v.Last.At == at {
		// Committed, but its payload is no longer retained: it cannot be returned
		// verbatim, and recomputing it would not be the committed evaluation.
		return Evaluation{}, false, ruleFault(model.Stale, "evaluation_payload_released")
	}
	return Evaluation{}, false, nil
}

// GapEvidence is the EvidenceChecker backed by committed RecordEvidenceGap facts:
// an evidence gap that overlaps the decision window of a project's metric or log
// input makes that window incomplete. Stale-producer and loss-report sources are
// separate EvidenceChecker implementations the application injects.
type GapEvidence struct {
	Gaps interface {
		EvidenceGaps(ctx context.Context, org, project model.ID) ([]model.EvidenceGap, error)
	}
}

// Check implements EvidenceChecker.
func (g GapEvidence) Check(ctx context.Context, scope auth.Scope, project model.ID, from, to model.UnixNano) (Evidence, error) {
	gaps, err := g.Gaps.EvidenceGaps(ctx, scope.OrgID(), project)
	if err != nil {
		return Evidence{}, err
	}
	for _, gap := range gaps {
		if gap.End < from || gap.Start > to {
			continue
		}
		relevant := len(gap.Signals) == 0
		for _, signal := range gap.Signals {
			relevant = relevant || signal == model.Metric || signal == model.Log
		}
		if relevant {
			return Evidence{Incomplete: true, Reason: ReasonEvidenceGap}, nil
		}
	}
	return Evidence{}, nil
}

// OutboxStore is the control-backed output outbox the OutputWorker drains.
type OutboxStore struct {
	store ControlStore
}

// NewOutboxStore builds the outbox adapter over the control store.
func NewOutboxStore(store ControlStore) *OutboxStore { return &OutboxStore{store: store} }

// Pending lists the project's recording outputs that still need work: pending
// (not yet admitted) and admitted (not yet finalized), in (at, ID) order.
func (o *OutboxStore) Pending(ctx context.Context, scope auth.Scope, limit int) ([]control.RuleOutput, error) {
	project, err := workerProject(scope)
	if err != nil {
		return nil, err
	}
	var out []control.RuleOutput
	for _, phase := range []string{control.RulePhasePending, control.RulePhaseAdmitted} {
		list, err := o.store.RuleOutputs(ctx, scope, project, model.ID{}, phase, 0)
		if err != nil {
			return nil, err
		}
		for _, item := range list {
			if item.Kind == control.RuleOutputRecording {
				out = append(out, item)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].At != out[j].At {
			return out[i].At < out[j].At
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Settle commits one output transition under the lease. The command identity is
// derived from the transition, so a repeated settle is a no-op.
func (o *OutboxStore) Settle(ctx context.Context, scope auth.Scope, lease replica.FenceToken, item control.RuleOutput, update control.RuleOutputApply) (control.Result, error) {
	org := scope.OrgID()
	receipt, hash := model.Cursor{}, model.Hash{}
	if update.Receipt != nil {
		receipt = *update.Receipt
	}
	if update.Hash != nil {
		hash = *update.Hash
	}
	id := derive("output", org[:], item.ID[:], []byte(update.To), receipt.Group[:], u64(uint64(receipt.Index)), hash[:], []byte(update.Reason))
	update.Project, update.Rule, update.Output = item.Project, item.Rule, item.ID
	return transact(ctx, o.store, scope, id, control.RuleCommand{Operation: control.RuleOpOutput, Lease: &lease, Output: &update})
}
