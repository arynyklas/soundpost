// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/gitlab"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

// The GitLab console routes (docs/operations/console-api.md section 10): markdown
// copy, the native one-way create and the connection settings. The orchestration
// lives in internal/gitlab; this file binds it to the node: the organization's
// connection and sealed token from control state, and the incident and issue
// services for the external-link transitions.

// registerGitLabConsole mounts the GitLab routes. An application without the
// incident or action services (a partial test composition) mounts nothing.
func (a *App) registerGitLabConsole(mux *http.ServeMux, cfg ConsoleConfig) {
	if a.Auth == nil || a.Control == nil || a.Incidents == nil || a.Actions == nil {
		return
	}
	issueService, err := a.NewIssueActions(releaseActionClock{})
	if err != nil {
		return
	}
	svc, err := gitlab.New(gitlab.Options{
		Settings: controlGitLab{a},
		Entities: gitlabEntities{incidents: a.Incidents, issues: issueService},
		Origin:   cfg.PublicOrigin,
		Egress:   gitlab.Egress{AllowPrefixes: cfg.EgressAllow},
		RootCAs:  cfg.RootCAs,
	})
	if err != nil {
		return
	}
	copyText, err := httpapi.NewMarkdownCopy(a.Actions, cfg.PublicOrigin)
	if err != nil {
		return
	}
	httpapi.RegisterMarkdownRoutes(mux, a.Auth, copyText)
	httpapi.RegisterGitLabRoutes(mux, a.Auth, svc)
}

// controlGitLab reads the organization's connection and opens its sealed token for
// one call.
type controlGitLab struct{ a *App }

func (c controlGitLab) Connection(ctx context.Context, org model.ID) (gitlab.Connection, bool, error) {
	var conn auth.GitLabConnection
	var sealed string
	var found bool
	err := c.a.Control.View(ctx, func(st model.ControlState) error {
		if _, retired := st.RetiredOrgs[org.String()]; retired {
			return nil
		}
		o, ok := st.Orgs[org.String()]
		if !ok {
			return nil
		}
		var err error
		conn, sealed, found, err = auth.ParseGitLabConnection(o)
		return err
	})
	if err != nil || !found || sealed == "" {
		return gitlab.Connection{}, false, err
	}
	token, err := c.a.Control.OpenSecret(sealed)
	if err != nil {
		return gitlab.Connection{}, false, model.Fail(model.Unavailable)
	}
	out := gitlab.Connection{BaseURL: conn.BaseURL, Token: token, Mappings: make([]gitlab.Mapping, 0, len(conn.Mappings))}
	for _, m := range conn.Mappings {
		out.Mappings = append(out.Mappings, gitlab.Mapping{Project: m.ProjectID, GitLabProject: m.GitLabProject, CreateFrom: m.CreateFrom, Labels: m.Labels})
	}
	return out, true, nil
}

// gitlabEntities reads incidents and error issues and applies the external-link
// transitions through their own services: scope check, version compare-and-set,
// audit and durable write are theirs.
type gitlabEntities struct {
	incidents *incidents.Service
	issues    *issues.Service
}

func (g gitlabEntities) Read(ctx context.Context, scope auth.Scope, kind string, project, id model.ID) (gitlab.Entity, error) {
	if kind == gitlab.KindIssue {
		issue, err := g.issues.Get(ctx, scope, project, id)
		if err != nil {
			return gitlab.Entity{}, err
		}
		return issueEntity(issue), nil
	}
	st, err := g.incidents.Get(ctx, scope, project, id)
	if err != nil {
		return gitlab.Entity{}, err
	}
	return incidentEntity(st)
}

const maxIssueReleases = 8

func issueEntity(i model.GroupingIssue) gitlab.Entity {
	related := make([]gitlab.Ref, 0, maxIssueReleases)
	for _, r := range i.ObservedReleases {
		if len(related) == maxIssueReleases {
			break
		}
		related = append(related, gitlab.Ref{Kind: "release", ID: r})
	}
	return gitlab.Entity{Facts: gitlab.Facts{Kind: gitlab.KindIssue, ID: i.ID, Project: i.Project, Status: i.Workflow, Related: related}, Version: uint64(i.Revision), External: i.External}
}

func incidentEntity(st incidents.State) (gitlab.Entity, error) {
	if st.Erased {
		f := model.Fail(model.NotFound)
		f.SafeDetail = incidents.DetailErased
		return gitlab.Entity{}, f
	}
	related := make([]gitlab.Ref, 0, len(st.Links))
	for _, l := range st.Links {
		related = append(related, gitlab.Ref{Kind: string(l.Kind), ID: l.ID})
	}
	return gitlab.Entity{Facts: gitlab.Facts{Kind: gitlab.KindIncident, ID: st.ID, Project: st.Project, Severity: severityLabel(st.Severity), Status: string(st.Status), Related: related}, Version: uint64(st.Version), External: st.External}, nil
}

func severityLabel(s incidents.Severity) string {
	switch s {
	case incidents.SeverityMinor:
		return "minor"
	case incidents.SeverityMajor:
		return "major"
	case incidents.SeverityCritical:
		return "critical"
	}
	return "unknown"
}

func (g gitlabEntities) Apply(ctx context.Context, scope auth.Scope, kind string, project, id model.ID, expected uint64, op model.ExternalOp) (gitlab.Entity, error) {
	if kind == gitlab.KindIssue {
		issue, err := g.issues.Act(ctx, scope, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: model.Revision(expected), IssueID: id, Kind: "external_" + op.Kind, External: &op})
		if err != nil {
			return gitlab.Entity{}, entityConflict(err)
		}
		return issueEntity(issue), nil
	}
	typ := incidents.TypeExternalBegin
	switch op.Kind {
	case model.ExternalEnd:
		typ = incidents.TypeExternalEnd
	case model.ExternalAdopt:
		typ = incidents.TypeExternalAdopt
	}
	st, err := g.incidents.Act(ctx, scope, incidents.Action{CommandID: model.NewID(), ExpectedVersion: model.Revision(expected), Type: typ,
		Target: incidents.Target{Org: scope.OrgID(), Project: project, Incident: id}, External: &op}, 0)
	if err != nil {
		return gitlab.Entity{}, entityConflict(err)
	}
	return incidentEntity(st)
}

// entityConflict maps a lost version race to gitlab.ErrVersionConflict. The typed
// external_* refusals are conflicts too, but they are the state machine's answer
// and pass through unchanged.
func entityConflict(err error) error {
	var vc *incidents.VersionConflict
	if errors.As(err, &vc) {
		return gitlab.ErrVersionConflict
	}
	var f *model.Fault
	if errors.As(err, &f) && f.Code == model.Conflict && !strings.HasPrefix(f.SafeDetail, "external_") {
		return gitlab.ErrVersionConflict
	}
	return err
}
