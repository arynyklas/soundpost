// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package releases

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// Store and ScopeAuthorizer are consumer-owned seams. Composition binds the
// application's existing control authority, never a second database or global.
type Store interface {
	Transact(context.Context, auth.Scope, model.ControlCommand) (model.ControlResult, error)
	View(context.Context, func(model.ControlState) error) error
}
type ScopeAuthorizer interface {
	Revalidate(context.Context, auth.Scope) error
}

// Clock supplies action admission time outside deterministic control apply.
type Clock interface {
	Now() model.UnixNano
}
type Service struct {
	store      Store
	authorizer ScopeAuthorizer
	clock      Clock
}

func New(store Store, authorizer ScopeAuthorizer, clock Clock) (*Service, error) {
	if store == nil || authorizer == nil || clock == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &Service{store: store, authorizer: authorizer, clock: clock}, nil
}
func (s *Service) authorize(ctx context.Context, scope auth.Scope) error {
	if e := s.authorizer.Revalidate(ctx, scope); e != nil {
		return e
	}
	if scope.Permission() != auth.OrgAdmin {
		return model.Fail(model.Forbidden)
	}
	return nil
}
func scopedProject(scope auth.Scope, st model.ControlState, project model.ID) error {
	if e := scope.ValidateControlState(st); e != nil {
		return e
	}
	org, ok := st.Orgs[scope.OrgID().String()]
	if !ok || !org.Admins[scope.PrincipalID().String()] {
		return model.Fail(model.NotFound)
	}
	if _, ok := org.Projects[project.String()]; !ok {
		return model.Fail(model.NotFound)
	}
	if len(scope.ProjectIDs()) > 0 && !scope.AllowsProject(project) {
		return model.Fail(model.NotFound)
	}
	return nil
}
func (s *Service) Register(ctx context.Context, scope auth.Scope, release Release, expected model.Revision, commandID model.ID) (Release, error) {
	if e := s.authorize(ctx, scope); e != nil {
		return Release{}, e
	}
	release.History = nil // Receipt history can only be authored by deterministic apply.
	payload, e := json.Marshal(model.ReleaseCommand{Operation: "register_release", At: s.clock.Now(), RequestID: model.RequestCorrelationID(ctx, commandID), Release: &release})
	if e != nil {
		return Release{}, model.Fail(model.Invalid)
	}
	result, e := s.store.Transact(ctx, scope, model.ControlCommand{CommandID: commandID, ExpectedRevision: expected, Kind: "RegisterRelease", Payload: payload})
	if e != nil {
		return Release{}, e
	}
	// The original committed response must survive renames and command retries.
	// A command ID may be retried with altered payload, so use its affected ID,
	// never a payload-supplied ID, to retrieve that original receipt.
	if len(result.AffectedIDs) != 1 {
		return Release{}, model.Fail(model.Corrupt)
	}
	var out Release
	e = s.store.View(ctx, func(st model.ControlState) error {
		if e := scopedProject(scope, st, release.Project); e != nil {
			return e
		}
		key := model.ReleaseScopeKey(scope.OrgID(), release.Project, result.AffectedIDs[0])
		stored, ok := st.Releases[key]
		if !ok {
			return model.Fail(model.NotFound)
		}
		for i, version := range stored.History {
			if version.ControlRevision == result.Revision {
				out = stored
				out.Revision = version.Revision
				out.DisplayLabel = version.DisplayLabel
				out.History = stored.History[:i+1]
				return nil
			}
		}
		return model.Fail(model.Corrupt)
	})
	return out, e
}
func (s *Service) Get(ctx context.Context, scope auth.Scope, project, id model.ID) (Release, error) {
	if e := s.authorize(ctx, scope); e != nil {
		return Release{}, e
	}
	var out Release
	e := s.store.View(ctx, func(st model.ControlState) error {
		if e := scopedProject(scope, st, project); e != nil {
			return e
		}
		var ok bool
		out, ok = st.Releases[model.ReleaseScopeKey(scope.OrgID(), project, id)]
		if !ok {
			return model.Fail(model.NotFound)
		}
		return nil
	})
	return out, e
}
func (s *Service) Graph(ctx context.Context, scope auth.Scope, project model.ID) (Graph, error) {
	if e := s.authorize(ctx, scope); e != nil {
		return nil, e
	}
	out := Graph{}
	e := s.store.View(ctx, func(st model.ControlState) error {
		if e := scopedProject(scope, st, project); e != nil {
			return e
		}
		for _, release := range st.Releases {
			if release.Org == scope.OrgID() && release.Project == project {
				out[release.ID] = release
			}
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}
func (s *Service) MigrateGrouping(ctx context.Context, scope auth.Scope, migration model.GroupingMigration, expected model.Revision, commandID model.ID) (model.GroupingMigration, error) {
	if e := s.authorize(ctx, scope); e != nil {
		return model.GroupingMigration{}, e
	}
	payload, e := json.Marshal(model.ReleaseCommand{Operation: "grouping_migration", At: s.clock.Now(), RequestID: model.RequestCorrelationID(ctx, commandID), Migration: &migration})
	if e != nil {
		return model.GroupingMigration{}, model.Fail(model.Invalid)
	}
	result, e := s.store.Transact(ctx, scope, model.ControlCommand{CommandID: commandID, ExpectedRevision: expected, Kind: "ApplyIssueEvidence", Payload: payload})
	if e != nil {
		return model.GroupingMigration{}, e
	}
	if len(result.AffectedIDs) != 3 {
		return model.GroupingMigration{}, model.Fail(model.Corrupt)
	}
	var out model.GroupingMigration
	e = s.store.View(ctx, func(st model.ControlState) error {
		if e := scopedProject(scope, st, migration.Project); e != nil {
			return e
		}
		var ok bool
		out, ok = st.GroupingMigrations[model.ReleaseScopeKey(scope.OrgID(), migration.Project, result.AffectedIDs[2])]
		if !ok {
			return model.Fail(model.NotFound)
		}
		return nil
	})
	return out, e
}

// GroupingIssue keeps an explicitly migrated issue and its original immutable
// history addressable; this read does not run or imitate the lifecycle reducer.
func (s *Service) GroupingIssue(ctx context.Context, scope auth.Scope, project, id model.ID) (model.GroupingIssue, error) {
	if e := s.authorize(ctx, scope); e != nil {
		return model.GroupingIssue{}, e
	}
	var out model.GroupingIssue
	e := s.store.View(ctx, func(st model.ControlState) error {
		if e := scopedProject(scope, st, project); e != nil {
			return e
		}
		var ok bool
		out, ok = st.GroupingIssues[model.ReleaseScopeKey(scope.OrgID(), project, id)]
		if !ok {
			return model.Fail(model.NotFound)
		}
		return nil
	})
	return out, e
}
