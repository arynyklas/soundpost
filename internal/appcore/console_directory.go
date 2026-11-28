// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"net/http"
	"slices"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

// registerDirectoryConsole mounts the display-name directory (docs/operations/console-api.md, section 3).
func (a *App) registerDirectoryConsole(mux *http.ServeMux, _ ConsoleConfig) {
	httpapi.RegisterDirectoryRoutes(mux, a.Auth)
}

// registerDeployConsole mounts the deploy markers (section 7) and the release list (section 5).
func (a *App) registerDeployConsole(mux *http.ServeMux, _ ConsoleConfig) {
	httpapi.RegisterDeployRoutes(mux, a.Auth)
	var tickets httpapi.ListTickets
	if a.Cache != nil {
		tickets = a.Cache
	}
	source := &releaseListSource{app: a}
	// Without the issue lifecycle the counts are unknown (counts_state not_available), the list itself works.
	if svc, err := a.NewIssueActions(releaseActionClock{}); err == nil {
		source.explain = svc
	}
	httpapi.RegisterReleaseListRoute(mux, a.Auth, source, tickets)
}

// releaseListSource reads one project's release records and issue evidence under the caller's own scope.
type releaseListSource struct {
	app     *App
	explain *issues.Service
}

func (s *releaseListSource) ReleaseList(ctx context.Context, scope auth.Scope, project model.ID) (httpapi.ReleaseListProject, error) {
	if !scope.AllowsProject(project) {
		return httpapi.ReleaseListProject{}, model.Fail(model.NotFound)
	}
	var out httpapi.ReleaseListProject
	err := s.app.Control.View(ctx, func(st model.ControlState) error {
		if err := scope.ValidateControlState(st); err != nil {
			return err
		}
		if !model.ReadOnlyOf(&st).OrgHasProject(scope.OrgID().String(), project.String()) {
			return model.Fail(model.NotFound)
		}
		org := scope.OrgID()
		for _, rel := range st.Releases {
			if rel.Org != org || rel.Project != project {
				continue
			}
			// The registry's debug artifacts and label history are release records, not list content.
			out.Releases = append(out.Releases, model.Release{ID: rel.ID, Org: rel.Org, Project: rel.Project, BuildID: rel.BuildID, Parents: slices.Clone(rel.Parents),
				BuildTime: rel.BuildTime, DisplayLabel: rel.DisplayLabel, Revision: rel.Revision})
		}
		return nil
	})
	if err != nil {
		return httpapi.ReleaseListProject{}, err
	}
	if len(out.Releases) > httpapi.MaxReleaseListScan {
		slices.SortFunc(out.Releases, func(a, b model.Release) int {
			if a.BuildTime != b.BuildTime {
				if a.BuildTime > b.BuildTime {
					return -1
				}
				return 1
			}
			return slices.Compare(a.ID[:], b.ID[:])
		})
		out.Releases, out.Capped = out.Releases[:httpapi.MaxReleaseListScan], true
	}
	out.Issues, out.Explanations, out.IssuesKnown, err = s.issueEvidence(ctx, scope, project)
	return out, err
}

// issueEvidence reads the project's issues and regression evaluations. An authorization answer is the
// caller's; any other failure leaves the counts unknown (known=false), never zero.
func (s *releaseListSource) issueEvidence(ctx context.Context, scope auth.Scope, project model.ID) ([]model.GroupingIssue, map[model.ID][]issues.Explanation, bool, error) {
	if s.explain == nil {
		return nil, nil, false, nil
	}
	snapshot, err := s.app.Control.IssueBook(ctx, scope, project)
	if err != nil {
		return nil, nil, false, authAnswer(err)
	}
	explained, err := s.explain.ExplainAll(ctx, scope, project)
	if err != nil {
		return nil, nil, false, authAnswer(err)
	}
	return snapshot.Issues, explained, true, nil
}

// authAnswer passes an authorization failure on and swallows every other one.
func authAnswer(err error) error {
	for _, code := range []model.Code{model.NotFound, model.Forbidden, model.Unauthenticated} {
		if f, ok := err.(*model.Fault); ok && f.Code == code {
			return err
		}
	}
	return nil
}
