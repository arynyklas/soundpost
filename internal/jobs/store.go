// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package jobs

import (
	"context"
	"encoding/json"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
)

// Control is the consumer-owned view of the C05 control authority the job store
// needs; *control.Store implements it once BindJobUpdate has installed the
// KindUpdateJob handler.
type Control interface {
	TransactJobs(ctx context.Context, scope auth.Scope, cmd control.Command) (control.Result, error)
	JobBook(ctx context.Context, scope auth.Scope, project, job model.ID) (control.JobSnapshot, bool, error)
	JobGaps(ctx context.Context, scope auth.Scope, project model.ID) ([]model.EvidenceGap, error)
}

// ControlStore is the durable Store over the control group: one job's state is
// one control record, and every Update is one control transaction whose
// compare-and-set token is the job's version.
type ControlStore struct{ c Control }

var _ Store = (*ControlStore)(nil)

// NewControlStore binds the store to a control authority.
func NewControlStore(c Control) (*ControlStore, error) {
	if c == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &ControlStore{c: c}, nil
}

// Load returns the committed state. A job whose state a deletion erased reads as
// an empty state at the preserved version, so evidence that arrives later builds
// a new history on top of the tombstone instead of stalling on a version the
// reducer cannot reach.
func (s *ControlStore) Load(ctx context.Context, scope auth.Scope, project, job model.ID) (JobState, bool, error) {
	snap, found, err := s.c.JobBook(ctx, scope, project, job)
	if err != nil || !found {
		return JobState{}, false, err
	}
	if snap.Erased {
		return JobState{Version: snap.Version, Org: scope.OrgID(), Project: project, Job: job}, true, nil
	}
	var state JobState
	if err := json.Unmarshal(snap.State, &state); err != nil {
		return JobState{}, false, model.Fail(model.Corrupt)
	}
	if state.Org != scope.OrgID() || state.Project != project || state.Job != job || state.Version != snap.Version {
		return JobState{}, false, model.Fail(model.Corrupt)
	}
	return state, true, nil
}

// Update commits cmd as one control transaction. A lost version race is
// model.Stale (the control fault carries the current version in its detail,
// control.JobVersionConflict); a repeated command ID is a replay when its input
// digest matches and model.Conflict when it does not.
func (s *ControlStore) Update(ctx context.Context, scope auth.Scope, cmd UpdateCommand) (UpdateResult, error) {
	if cmd.CommandID == (model.ID{}) || cmd.Next.Org != scope.OrgID() || cmd.Next.Project != cmd.Project || cmd.Next.Job != cmd.Job {
		return UpdateResult{}, model.Fail(model.Invalid)
	}
	state, err := json.Marshal(cmd.Next)
	if err != nil {
		return UpdateResult{}, model.Fail(model.Invalid)
	}
	payload := control.JobUpdateCommand{Project: cmd.Project, Job: cmd.Job, Kind: string(cmd.Kind), ExpectedVersion: cmd.ExpectedVersion, NewVersion: cmd.Next.Version,
		InputDigest: cmd.InputDigest, State: state, Origin: cmd.Origin}
	if cmd.Audit != nil {
		payload.Audit = &control.JobAudit{Principal: cmd.Audit.Principal, Action: cmd.Audit.Action, Reason: cmd.Audit.Reason, At: cmd.Audit.At, Targets: cmd.Audit.Targets}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return UpdateResult{}, model.Fail(model.Invalid)
	}
	res, err := s.c.TransactJobs(ctx, scope, control.Command{CommandID: cmd.CommandID, Kind: string(control.KindUpdateJob), Payload: raw})
	if err != nil {
		return UpdateResult{}, err
	}
	return UpdateResult{Version: model.Revision(res.Cursor.Index), Replayed: res.Phase == "replayed"}, nil
}

// Gaps returns the committed evidence gaps of the project.
func (s *ControlStore) Gaps(ctx context.Context, scope auth.Scope, project model.ID) ([]model.EvidenceGap, error) {
	return s.c.JobGaps(ctx, scope, project)
}
