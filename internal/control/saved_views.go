// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the C05 half of C11 saved views: the KindSavedView handler and
// the committing entry point auth.Service uses. A saved view is a project-owned
// book record (ControlState.SavedViewBooks, one closed auth.SavedView DTO per
// "org:project:view" key) written by an explicit save of a caller who reads the
// project. What control owns, atomically in one command:
//
//   - the scope: a telemetry.read scope (or, for a delete only, an organization
//     administrator's) that names the owning project and every project the query
//     runs over, validated against the very state the command applies to
//     (session, token, epoch, membership and grant); a wrong organization, a
//     project that does not exist or is retired, a caller without the grant and
//     an absent view are the same not-found;
//   - the owner: the committing scope's principal, never a payload claim; an
//     update or a delete is allowed to the owner or to an organization
//     administrator, and to nobody else;
//   - the revision compare-and-set: two commands that both expect revision N
//     cannot both commit; the loser is a conflict, never merged;
//   - the cap: at most auth.MaxSavedViewsPerProject views per project, refused
//     with Quota (HTTP 429) beyond it, never evicting a view;
//   - the audit, created in the same transition: the actor, the kind
//     (saved_view.save or saved_view.delete), the organization, the project and
//     the view ID. Neither the name nor the expression ever reaches an audit.
//
// The handler writes only SavedViewBooks and Audits. It never touches the
// organization record, so the policy epoch does not move (a live stream or an
// export of the organization is not revoked by a save), and KindSavedView is on
// nonAuthorityKinds, so AuthorityRevision does not move either.

// The SafeDetail of the conflicts and the quota of a saved-view command.
const (
	SavedViewRevisionConflict = "saved_view_revision_conflict"
	SavedViewExists           = "saved_view_exists"
	SavedViewQuota            = "saved_view_quota"
)

const (
	maxSavedViewPayload      = 256 << 10
	savedViewRevisionRetries = 8
	savedViewSaveAction      = "saved_view.save"
	savedViewDeleteAction    = "saved_view.delete"
	savedViewAuditReason     = "saved view"
)

var _ auth.SavedViewStore = (*Store)(nil)

// BindSavedViews installs the KindSavedView handler on this Store only, like the
// other Bind* methods; it is a conflict to bind twice. auth.Service.BindSavedViews
// calls it when the saved-view route is mounted and treats a store that is bound
// already as bound.
func (s *Store) BindSavedViews() error {
	return s.RegisterHandler(KindSavedView, applySavedView)
}

// CommitSavedView commits one KindSavedView command under the caller's own
// scope. Transact compares the caller's view with the one global control
// revision, which every admission moves, so a loser of that race (the plain
// conflict Transact raises, whose detail is just "conflict": the command
// conflicted with nothing) is retried with a fresh revision, a bounded number
// of times; the command ID makes the retry a replay of the first answer if the
// first attempt had committed after all. A conflict the handler raised (a stale
// view revision, an existing view) carries its own SafeDetail and is returned as
// is.
func (s *Store) CommitSavedView(ctx context.Context, scope auth.Scope, cmd Command) (Result, error) {
	if cmd.Kind != string(KindSavedView) {
		return Result{}, model.Fail(model.Invalid)
	}
	for range savedViewRevisionRetries {
		revision, err := s.Revision(ctx)
		if err != nil {
			return Result{}, err
		}
		cmd.ExpectedRevision = revision
		res, err := s.Transact(ctx, scope, cmd)
		var f *model.Fault
		if !errors.As(err, &f) || f.Code != model.Conflict || f.SafeDetail != string(model.Conflict) {
			return res, err
		}
	}
	f := model.Fail(model.Unavailable)
	f.Retryable = true
	return Result{}, f
}

// loadSavedView reads one view record; a record that does not name its own key
// is corrupt, never trusted.
func loadSavedView(st *State, org, project, view model.ID) (auth.SavedView, bool, error) {
	raw, ok := st.SavedViewBooks[auth.SavedViewKey(org, project, view)]
	if !ok {
		return auth.SavedView{}, false, nil
	}
	var v auth.SavedView
	if json.Unmarshal(raw, &v) != nil || v.Org != org || v.Project != project || v.ID != view {
		return auth.SavedView{}, false, model.Fail(model.Corrupt)
	}
	return v, true, nil
}

// savedViewScope admits the scope to the command: a telemetry.read scope for a
// save, a telemetry.read or an organization administrator's scope for a delete,
// never the system runner's, and in every case a scope that names, and whose
// principal currently holds in this state, every project the command touches.
func savedViewScope(scope auth.Scope, st *State, c auth.SavedViewCommand) error {
	if scope.IsSystem() {
		return model.Fail(model.NotFound)
	}
	switch {
	case scope.Permission() == auth.Read:
	case scope.Permission() == auth.OrgAdmin && c.Operation == auth.SavedViewOpDelete:
	default:
		return model.Fail(model.Forbidden)
	}
	projects := []model.ID{c.Project}
	if c.Spec != nil {
		projects = append(projects, c.Spec.Projects...)
	}
	for _, p := range projects {
		if err := issueProjectScope(scope, st, p); err != nil {
			return err
		}
	}
	return nil
}

func applySavedView(scope auth.Scope, st *State, cmd Command) (Effect, error) {
	if len(cmd.Payload) > maxSavedViewPayload {
		return Effect{}, model.Fail(model.TooLarge)
	}
	var c auth.SavedViewCommand
	if err := strictPayload(cmd.Payload, &c); err != nil {
		return Effect{}, err
	}
	// The shape reads no state: it is the same answer for every caller.
	if c.Project == (model.ID{}) || c.View == (model.ID{}) || c.At <= 0 {
		return Effect{}, model.Fail(model.Invalid)
	}
	switch c.Operation {
	case auth.SavedViewOpSave:
		if c.Spec == nil {
			return Effect{}, model.Fail(model.Invalid)
		}
		if err := c.Spec.Validate(c.Project); err != nil {
			return Effect{}, err
		}
	case auth.SavedViewOpDelete:
		if c.Spec != nil || c.ExpectedRevision == 0 {
			return Effect{}, model.Fail(model.Invalid)
		}
	default:
		return Effect{}, model.Fail(model.Invalid)
	}
	// Scope and grants before anything about the view is looked up.
	if err := savedViewScope(scope, st, c); err != nil {
		return Effect{}, err
	}
	org := scope.OrgID()
	principal := scope.PrincipalID()
	rec, exists, err := loadSavedView(st, org, c.Project, c.View)
	if err != nil {
		return Effect{}, err
	}
	var phase string
	if c.Operation == auth.SavedViewOpSave && c.ExpectedRevision == 0 {
		if exists {
			return Effect{}, ruleFault(model.Conflict, SavedViewExists)
		}
		prefix, n := auth.SavedViewPrefix(org, c.Project), 0
		for key := range st.SavedViewBooks {
			if strings.HasPrefix(key, prefix) {
				n++
			}
		}
		if n >= auth.MaxSavedViewsPerProject {
			return Effect{}, ruleFault(model.Quota, SavedViewQuota)
		}
		rec = auth.SavedView{ID: c.View, Org: org, Project: c.Project, Owner: principal, CreatedNS: c.At}
		phase = auth.SavedViewPhaseCreated
	} else {
		if !exists {
			return Effect{}, model.Fail(model.NotFound)
		}
		// The owner and an organization administrator; a reader of the project who
		// is neither sees the view (it is listed to them) and may not change it.
		if rec.Owner != principal && !st.Orgs[org.String()].Admins[principal.String()] {
			return Effect{}, model.Fail(model.Forbidden)
		}
		if rec.Revision != c.ExpectedRevision {
			return Effect{}, ruleFault(model.Conflict, SavedViewRevisionConflict)
		}
		phase = auth.SavedViewPhaseUpdated
	}
	key := auth.SavedViewKey(org, c.Project, c.View)
	rec.Revision++
	action := savedViewSaveAction
	if c.Operation == auth.SavedViewOpDelete {
		delete(st.SavedViewBooks, key)
		phase, action = auth.SavedViewPhaseDeleted, savedViewDeleteAction
	} else {
		rec.SavedViewSpec, rec.UpdatedNS = *c.Spec, c.At
		raw, err := json.Marshal(rec)
		if err != nil {
			return Effect{}, model.Fail(model.Invalid)
		}
		if st.SavedViewBooks == nil {
			st.SavedViewBooks = map[string]json.RawMessage{}
		}
		st.SavedViewBooks[key] = raw
	}
	st.Audits = append(st.Audits, model.ControlAudit{ID: cmd.CommandID, Principal: principal, Action: action, Reason: savedViewAuditReason, Time: int64(c.At), Org: org.String(),
		PolicyEpoch: scope.PolicyEpoch(), Targets: []model.ID{c.Project, c.View}, RequestID: cmd.CommandID, Outcome: model.AuditAllowed})
	return Effect{AffectedIDs: []model.ID{c.View}, Phase: auth.SavedViewPhase(phase, rec.Revision)}, nil
}
