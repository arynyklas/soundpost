// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues

import (
	"context"
	"reflect"
	"soundpost/internal/auth"
	"soundpost/internal/model"
)

// Checkpoint is the highest data-journal cursor (per data group) whose
// lifecycle effects are committed. It is only ever written inside the same
// Commit as the evidence, issue changes and effects it covers, so a crash
// leaves either all of them or none, and a replay resumes exactly after it.
type Checkpoint struct {
	Group model.ID
	Index model.Uint64
}

// validateBatch checks that every evidence item lies in the cursor's data
// group at or below the cursor. A batch is "applied through cursor": it names
// the durable position the worker will resume from.
func validateBatch(cursor model.Cursor, evidence []Evidence) error {
	if cursor.Group == (model.ID{}) || cursor.Index == 0 {
		return model.Fail(model.Invalid)
	}
	for _, e := range evidence {
		if e.Origin.Group != cursor.Group || e.Origin.Index > cursor.Index {
			return model.Fail(model.Invalid)
		}
		if e := validateEvidence(e); e != nil {
			return e
		}
	}
	return nil
}

// RecordGap commits a declared evidence gap together with the checkpoint
// advance over it: lifecycle evidence in (After, Through] expired before it was
// processed. The gap must start exactly at the current checkpoint, so a worker
// can never silently skip unprocessed evidence. Until a gap commits the
// checkpoint does not move; once it commits, Health reports the project as
// incomplete, never recovered.
func (s *Service) RecordGap(ctx context.Context, scope auth.Scope, gap model.EvidenceGap) error {
	if gap.ID == (model.ID{}) || gap.Group == (model.ID{}) || gap.Org != scope.OrgID() || gap.Project == (model.ID{}) || !allowsProject(scope, gap.Project) ||
		gap.Through <= gap.After || gap.Count == 0 || gap.End < gap.Start || !safeText(gap.Reason) {
		return model.Fail(model.Invalid)
	}
	if e := s.authorize(ctx, scope, issuesWrite, gap.Project); e != nil {
		return e
	}
	for range maxAttempts {
		state, e := s.d.Store.Load(ctx, scope, gap.Project)
		if e != nil {
			return e
		}
		for _, known := range state.Gaps {
			if known.ID == gap.ID {
				if reflect.DeepEqual(known, gap) {
					return nil
				}
				return model.Fail(model.Conflict)
			}
		}
		if state.Checkpoints[gap.Group] != gap.After {
			return model.Fail(model.Conflict)
		}
		audit := model.ControlAudit{ID: gap.ID, Principal: scope.PrincipalID(), Action: "issues.evidence_gap", Reason: gap.Reason, Time: int64(gap.RecordedAt), Org: scope.OrgID().String(), PolicyEpoch: scope.PolicyEpoch(), Targets: []model.ID{gap.ID}, RequestID: model.RequestCorrelationID(ctx, gap.ID), Outcome: model.AuditAllowed}
		g := gap
		g.Signals = append([]model.Kind(nil), gap.Signals...)
		e = s.d.Store.Commit(ctx, scope, gap.Project, Commit{CommandID: gap.ID, ExpectedRevision: state.Revision, Audits: []model.ControlAudit{audit}, Checkpoint: &Checkpoint{Group: gap.Group, Index: gap.Through}, Gap: &g})
		if code(e) == model.Conflict {
			continue
		}
		return e
	}
	return model.Fail(model.Conflict)
}

// Health reports whether the project's lifecycle evidence is complete. Any
// committed gap makes affected conclusions unknown; it never reads as zero.
type Health struct {
	Complete bool
	Gaps     []model.EvidenceGap
}

func (s *Service) Health(ctx context.Context, scope auth.Scope, project model.ID) (Health, error) {
	state, e := s.read(ctx, scope, project)
	if e != nil {
		return Health{}, e
	}
	return Health{Complete: len(state.Gaps) == 0, Gaps: append([]model.EvidenceGap(nil), state.Gaps...)}, nil
}

func code(e error) model.Code {
	if f, ok := e.(*model.Fault); ok {
		return f.Code
	}
	return ""
}
