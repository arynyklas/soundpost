// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"net/http"
	"net/url"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/gitlab"
	"github.com/arynyklas/soundpost/internal/model"
)

// The GitLab console surface (docs/operations/console-api.md section 10c):
//
//	POST /api/v1/gitlab/issues     preview | create | recheck | link_from
//	POST /api/v1/gitlab/settings   read | save | disconnect | test
//
// Both derive their scope from the caller's own credential before any service is
// touched. Entity writes run under incidents.write / issues.write on the project
// (or organization admin); settings are written by an organization administrator
// under a fresh session and read by any member of the organization.

// GitLab issue operations and settings operations.
const (
	GitLabOpPreview  = "preview"
	GitLabOpCreate   = "create"
	GitLabOpRecheck  = "recheck"
	GitLabOpLinkFrom = "link_from"

	GitLabOpRead       = "read"
	GitLabOpSave       = "save"
	GitLabOpDisconnect = "disconnect"
	GitLabOpTest       = "test"
)

// GitLabIssues is the orchestration the issues route drives; *gitlab.Service
// implements it.
type GitLabIssues interface {
	Preview(ctx context.Context, scope auth.Scope, t gitlab.Target) (gitlab.Preview, error)
	Create(ctx context.Context, scope auth.Scope, req gitlab.CreateRequest) (gitlab.Result, error)
	Recheck(ctx context.Context, scope auth.Scope, t gitlab.Target) (gitlab.Result, error)
	LinkFrom(ctx context.Context, scope, fromScope auth.Scope, t, from gitlab.Target) (gitlab.Result, error)
	CheckToken(ctx context.Context, org model.ID) (gitlab.TokenResult, error)
	ValidBase(raw string) (base, host string, err error)
}

// GitLabEntityRef names an entity. ProjectID is only read on a link_from source
// (default: the request's project).
type GitLabEntityRef struct {
	Kind      string   `json:"kind"`
	ID        model.ID `json:"id"`
	ProjectID model.ID `json:"project_id,omitempty"`
}

// GitLabIssueBody is the closed POST /api/v1/gitlab/issues body.
type GitLabIssueBody struct {
	Op          string           `json:"op"`
	Org         model.ID         `json:"org"`
	ProjectID   model.ID         `json:"project_id"`
	Entity      *GitLabEntityRef `json:"entity"`
	CommandID   model.ID         `json:"command_id,omitempty"`
	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	Labels      []string         `json:"labels,omitempty"`
	From        *GitLabEntityRef `json:"from,omitempty"`
}

// GitLabExistingView is a link stored on the entity or on an entity it is linked to.
type GitLabExistingView struct {
	State         string           `json:"state"`
	URL           string           `json:"url,omitempty"`
	GitLabProject string           `json:"gitlab_project,omitempty"`
	IID           *model.Uint64    `json:"iid,omitempty"`
	Code          string           `json:"code,omitempty"`
	From          *GitLabEntityRef `json:"from,omitempty"`
}

// GitLabPreviewView is the answer to a preview.
type GitLabPreviewView struct {
	State         ViewState           `json:"state"`
	Reason        string              `json:"reason,omitempty"`
	GitLabProject string              `json:"gitlab_project,omitempty"`
	Title         string              `json:"title"`
	Description   string              `json:"description"`
	Labels        []string            `json:"labels"`
	Existing      *GitLabExistingView `json:"existing"`
}

// GitLabResultView is the answer to create, recheck and link_from. State is
// linked, unknown (the request may have reached GitLab; nothing is retried
// automatically), refused (Code says why) or not_linked (a recheck found nothing).
type GitLabResultView struct {
	State         string        `json:"state"`
	Created       bool          `json:"created"`
	URL           string        `json:"url,omitempty"`
	GitLabProject string        `json:"gitlab_project,omitempty"`
	IID           *model.Uint64 `json:"iid,omitempty"`
	Code          string        `json:"code,omitempty"`
}

func iidView(iid uint64) *model.Uint64 {
	if iid == 0 {
		return nil
	}
	v := model.Uint64(iid)
	return &v
}

func resultView(r gitlab.Result) GitLabResultView {
	return GitLabResultView{State: r.State, Created: r.Created, URL: r.URL, GitLabProject: r.GitLabProject, IID: iidView(r.IID), Code: r.Code}
}

func previewView(p gitlab.Preview) GitLabPreviewView {
	v := GitLabPreviewView{State: StateReady, Reason: p.Reason, GitLabProject: p.GitLabProject, Title: p.Title, Description: p.Description, Labels: p.Labels}
	if !p.Available {
		v.State = StateNotAvailable
	}
	if e := p.Existing; e != nil {
		ev := &GitLabExistingView{State: e.State, URL: e.URL, GitLabProject: e.GitLabProject, IID: iidView(e.IID), Code: e.Code}
		if e.From != nil {
			ev.From = &GitLabEntityRef{Kind: e.From.Kind, ID: e.From.ID}
		}
		v.Existing = ev
	}
	return v
}

func gitlabEntityValid(e *GitLabEntityRef) bool {
	return e != nil && e.ID != (model.ID{}) && (e.Kind == gitlab.KindIncident || e.Kind == gitlab.KindIssue)
}

func validGitLabIssueBody(b GitLabIssueBody) error {
	if b.Org == (model.ID{}) || b.ProjectID == (model.ID{}) || !gitlabEntityValid(b.Entity) {
		return invalid("gitlab_request_invalid")
	}
	create := b.Op == GitLabOpCreate
	link := b.Op == GitLabOpLinkFrom
	switch b.Op {
	case GitLabOpPreview, GitLabOpCreate, GitLabOpRecheck, GitLabOpLinkFrom:
	default:
		return invalid("gitlab_op_unknown")
	}
	if create != (b.CommandID != (model.ID{})) {
		return invalid("gitlab_request_invalid")
	}
	if !create && (b.Title != "" || b.Description != "" || b.Labels != nil) || link != (b.From != nil) || link && !gitlabEntityValid(b.From) {
		return invalid("gitlab_request_invalid")
	}
	return nil
}

func gitlabWriteGrant(kind string) auth.Permission {
	if kind == gitlab.KindIssue {
		return auth.IssuesWrite
	}
	return auth.IncidentsWrite
}

// GitLabSettingsBody is the closed POST /api/v1/gitlab/settings body.
type GitLabSettingsBody struct {
	Op            string                `json:"op"`
	Org           model.ID              `json:"org"`
	CommandID     model.ID              `json:"command_id,omitempty"`
	ExpectedEpoch *model.Uint64         `json:"expected_epoch,omitempty"`
	Reason        string                `json:"reason,omitempty"`
	Connection    *GitLabConnectionBody `json:"connection,omitempty"`
}

// GitLabConnectionBody is the connection a save carries; the token is write-only
// and an omitted one keeps the stored token.
type GitLabConnectionBody struct {
	BaseURL  string               `json:"base_url"`
	Token    string               `json:"token,omitempty"`
	Mappings []auth.GitLabMapping `json:"mappings"`
}

// GitLabTokenView is what is known about the token; never the token.
type GitLabTokenView struct {
	HasToken  bool     `json:"has_token"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
}

// GitLabSettingsView is the redacted connection. Epoch is the organization epoch
// the next save carries as expected_epoch.
type GitLabSettingsView struct {
	State     ActionState          `json:"state,omitempty"`
	Connected bool                 `json:"connected"`
	BaseHost  string               `json:"base_host,omitempty"`
	Mappings  []auth.GitLabMapping `json:"mappings"`
	Token     GitLabTokenView      `json:"token"`
	Epoch     model.Uint64         `json:"epoch"`
	CanEdit   bool                 `json:"can_edit"`
}

// GitLabTestView is the answer to a connection test.
type GitLabTestView struct {
	OK        bool     `json:"ok"`
	Scopes    []string `json:"scopes,omitempty"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	Code      string   `json:"code,omitempty"`
}

func settingsView(v auth.GitLabView) GitLabSettingsView {
	out := GitLabSettingsView{Connected: v.Connected, Mappings: []auth.GitLabMapping{}, Epoch: v.Epoch, CanEdit: v.Admin, Token: GitLabTokenView{HasToken: v.HasToken}}
	if c := v.Connection; c != nil {
		if u, err := url.Parse(c.BaseURL); err == nil {
			out.BaseHost = u.Host
		}
		if c.Mappings != nil {
			out.Mappings = c.Mappings
		}
		out.Token.ExpiresAt, out.Token.Scopes = c.Token.ExpiresAt, c.Token.Scopes
	}
	return out
}

func validGitLabSettingsBody(b GitLabSettingsBody) error {
	if b.Org == (model.ID{}) {
		return invalid("gitlab_request_invalid")
	}
	switch b.Op {
	case GitLabOpRead, GitLabOpTest:
		if b.CommandID != (model.ID{}) || b.ExpectedEpoch != nil || b.Reason != "" || b.Connection != nil {
			return invalid("gitlab_request_invalid")
		}
	case GitLabOpSave:
		if b.CommandID == (model.ID{}) || b.ExpectedEpoch == nil || b.Reason == "" || b.Connection == nil {
			return invalid("gitlab_request_invalid")
		}
	case GitLabOpDisconnect:
		if b.CommandID == (model.ID{}) || b.ExpectedEpoch == nil || b.Reason == "" || b.Connection != nil {
			return invalid("gitlab_request_invalid")
		}
	default:
		return invalid("gitlab_op_unknown")
	}
	return nil
}

// gitlabBaseRefused is the typed refusal of a base URL that is not https, carries
// credentials, or is blocked by the egress rules.
func gitlabBaseRefused(err error) error {
	if gitlab.IsEgressBlocked(err) {
		return invalid("gitlab_egress_blocked")
	}
	return invalid("gitlab_base_url_invalid")
}

func (g gitlabRoutes) settings(w http.ResponseWriter, r *http.Request) {
	credential, err := artifactCredential(g.authority, w, r)
	if err != nil {
		queryReply(w, nil, err)
		return
	}
	var body GitLabSettingsBody
	if err = decode(w, r, &body); err != nil {
		queryReply(w, nil, err)
		return
	}
	if err = validGitLabSettingsBody(body); err != nil {
		queryReply(w, nil, err)
		return
	}
	ctx := r.Context()
	switch body.Op {
	case GitLabOpRead:
		view, err := g.authority.GitLabRead(ctx, credential, body.Org)
		queryReply(w, settingsView(view), err)
	case GitLabOpSave:
		c := body.Connection
		base, _, err := g.svc.ValidBase(c.BaseURL)
		if err != nil {
			queryReply(w, nil, gitlabBaseRefused(err))
			return
		}
		_, err = g.authority.GitLabCommand(ctx, credential, auth.GitLabCommandRequest{CommandID: body.CommandID, OrgID: body.Org, ExpectedEpoch: *body.ExpectedEpoch, Op: auth.GitLabSave, Reason: body.Reason,
			Connection: &auth.GitLabConnectionInput{BaseURL: base, Token: c.Token, Mappings: c.Mappings}})
		g.committed(w, r, credential, body.Org, err)
	case GitLabOpDisconnect:
		_, err = g.authority.GitLabCommand(ctx, credential, auth.GitLabCommandRequest{CommandID: body.CommandID, OrgID: body.Org, ExpectedEpoch: *body.ExpectedEpoch, Op: auth.GitLabDisconnect, Reason: body.Reason})
		g.committed(w, r, credential, body.Org, err)
	case GitLabOpTest:
		view, err := g.authority.GitLabRead(ctx, credential, body.Org)
		if err == nil && !view.Admin {
			err = model.Fail(model.NotFound)
		}
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		res, err := g.svc.CheckToken(ctx, body.Org)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		if view.HasToken && (res.OK || res.Code == gitlab.CodeTokenInactive) {
			// Remember what GitLab said (scopes, expiry) for the settings page. A
			// connection that changed meanwhile, or a stale session, just drops it.
			_, _ = g.authority.GitLabCommand(ctx, credential, auth.GitLabCommandRequest{CommandID: model.NewID(), OrgID: body.Org, ExpectedEpoch: view.Epoch, Op: auth.GitLabTokenCheck, Token: &auth.GitLabTokenMeta{ExpiresAt: res.ExpiresAt, Scopes: res.Scopes}})
		}
		queryReply(w, GitLabTestView{OK: res.OK, Scopes: res.Scopes, ExpiresAt: res.ExpiresAt, Code: res.Code}, nil)
	}
}

// committed answers a settings write with the connection as committed.
func (g gitlabRoutes) committed(w http.ResponseWriter, r *http.Request, credential auth.Credential, org model.ID, err error) {
	if err != nil {
		queryReply(w, nil, err)
		return
	}
	view, err := g.authority.GitLabRead(r.Context(), credential, org)
	out := settingsView(view)
	out.State = ActionCommitted
	queryReply(w, out, err)
}

func (g gitlabRoutes) issues(w http.ResponseWriter, r *http.Request) {
	credential, err := artifactCredential(g.authority, w, r)
	if err != nil {
		queryReply(w, nil, err)
		return
	}
	var body GitLabIssueBody
	if err = decode(w, r, &body); err != nil {
		queryReply(w, nil, err)
		return
	}
	if err = validGitLabIssueBody(body); err != nil {
		queryReply(w, nil, err)
		return
	}
	ctx := r.Context()
	target := gitlab.Target{Org: body.Org, Project: body.ProjectID, Kind: body.Entity.Kind, ID: body.Entity.ID}
	if body.Op == GitLabOpPreview {
		var scope auth.Scope
		if target.Kind == gitlab.KindIssue {
			scope, err = issueReadScope(ctx, g.authority, credential, body.Org, body.ProjectID)
		} else {
			scope, err = readScope(ctx, g.authority, credential, body.Org, []model.ID{body.ProjectID})
		}
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		p, err := g.svc.Preview(ctx, scope, target)
		if err == nil {
			err = g.authority.Revalidate(ctx, scope)
		}
		queryReply(w, previewView(p), err)
		return
	}
	scope, err := g.authority.AuthorizeWrite(ctx, credential, body.Org, body.ProjectID, gitlabWriteGrant(target.Kind))
	if err != nil {
		queryReply(w, nil, err)
		return
	}
	var res gitlab.Result
	switch body.Op {
	case GitLabOpCreate:
		res, err = g.svc.Create(ctx, scope, gitlab.CreateRequest{Target: target, CommandID: body.CommandID, Title: body.Title, Description: body.Description, Labels: body.Labels})
	case GitLabOpRecheck:
		res, err = g.svc.Recheck(ctx, scope, target)
	case GitLabOpLinkFrom:
		from := gitlab.Target{Org: body.Org, Project: body.From.ProjectID, Kind: body.From.Kind, ID: body.From.ID}
		if from.Project == (model.ID{}) {
			from.Project = body.ProjectID
		}
		var fromScope auth.Scope
		if fromScope, err = g.authority.AuthorizeWrite(ctx, credential, body.Org, from.Project, gitlabWriteGrant(from.Kind)); err == nil {
			res, err = g.svc.LinkFrom(ctx, scope, fromScope, target, from)
		}
	}
	queryReply(w, resultView(res), err)
}

type gitlabRoutes struct {
	authority *auth.Service
	svc       GitLabIssues
}

// RegisterGitLabRoutes mounts the GitLab console routes.
func RegisterGitLabRoutes(mux *http.ServeMux, authority *auth.Service, svc GitLabIssues) {
	g := gitlabRoutes{authority: authority, svc: svc}
	mux.HandleFunc("POST /api/v1/gitlab/issues", g.issues)
	mux.HandleFunc("POST /api/v1/gitlab/settings", g.settings)
}
