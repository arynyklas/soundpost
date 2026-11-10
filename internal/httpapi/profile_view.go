// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/profiles"
	"soundpost/internal/query"
)

// ProfilesRead is the separate grant a profile read needs.
const ProfilesRead auth.Permission = "profiles.read"

const (
	ReasonProfileServiceNotWired = "profile_service_not_wired"
	ReasonProfilePartial         = "profile_partial"
	DefaultProfileSamples        = 2048
)

// ProfileReader is the narrow consumer-owned seam over profiles.Service.Read.
type ProfileReader interface {
	Read(ctx context.Context, scope auth.Scope, id model.ID, w profiles.Window) (profiles.ProfileView, error)
}

// Profiles is the handler behind POST /api/v1/profiles/view.
type Profiles struct{ reader ProfileReader }

// NewProfiles binds the optional profile reader.
func NewProfiles(reader ProfileReader) *Profiles { return &Profiles{reader: reader} }

// ProfileBody is the POST /api/v1/profiles/view body.
type ProfileBody struct {
	ScopeFields
	Project    model.ID        `json:"project"`
	Profile    model.ID        `json:"profile"`
	Window     query.TimeRange `json:"window"`
	MaxSamples uint32          `json:"max_samples,omitempty"`
	Cursor     string          `json:"cursor,omitempty"`
}

// ProfileResponse answers a profile request.
type ProfileResponse struct {
	Org      model.ID              `json:"org"`
	Project  model.ID              `json:"project"`
	Profile  model.ID              `json:"profile"`
	State    ViewState             `json:"state"`
	Reason   string                `json:"reason,omitempty"`
	Partial  bool                  `json:"partial"`
	View     *profiles.ProfileView `json:"view,omitempty"`
	Sections []ViewSection         `json:"sections"`
}

func profileResponseOf(body ProfileBody, scope auth.Scope, state ViewState, reason string) ProfileResponse {
	return ProfileResponse{Org: scope.OrgID(), Project: body.Project, Profile: body.Profile, State: state, Reason: reason, Sections: []ViewSection{{Name: "profile", State: state, Reason: reason}}}
}

// View reads one profile under the caller's own authority. The scope carries the
// separate profiles.read grant: telemetry.read alone never opens a profile.
func (p *Profiles) View(ctx context.Context, authority *auth.Service, credential auth.Credential, body ProfileBody) (ProfileResponse, auth.Scope, error) {
	max := body.MaxSamples
	if max == 0 {
		max = DefaultProfileSamples
	}
	if body.Project == (model.ID{}) || body.Profile == (model.ID{}) || body.Org == (model.ID{}) || body.Window.End <= body.Window.Start || max > 8192 {
		return ProfileResponse{}, auth.Scope{}, invalid("profile_request_invalid")
	}
	if body.Elevation != nil || body.Permission != "" {
		return ProfileResponse{}, auth.Scope{}, model.Fail(model.Forbidden) // the grant is fixed; an elevation cannot carry it
	}
	scope, err := authority.Authorize(ctx, credential, body.Org, []model.ID{body.Project}, ProfilesRead)
	if err != nil {
		return ProfileResponse{}, auth.Scope{}, err
	}
	if !scope.AllowsProject(body.Project) {
		return ProfileResponse{}, auth.Scope{}, model.Fail(model.NotFound)
	}
	if p == nil || p.reader == nil {
		return profileResponseOf(body, scope, StateNotAvailable, ReasonProfileServiceNotWired), scope, nil
	}
	view, err := p.reader.Read(ctx, scope, body.Profile, profiles.Window{Start: body.Window.Start, End: body.Window.End, MaxSamples: max, Cursor: body.Cursor})
	if err != nil {
		return ProfileResponse{}, auth.Scope{}, err
	}
	if view.Project != body.Project || view.Profile != body.Profile || view.Completeness != "complete" && view.Completeness != "partial" {
		return ProfileResponse{}, auth.Scope{}, model.Fail(model.Corrupt)
	}
	out := profileResponseOf(body, scope, StateReady, "")
	out.View = &view
	if view.Completeness == "partial" || view.Truncated {
		reason := ReasonProfilePartial
		if len(view.Reasons) > 0 {
			reason = view.Reasons[0]
		}
		out.State, out.Reason, out.Partial = StateIncomplete, reason, true
		out.Sections[0] = ViewSection{Name: "profile", State: StateIncomplete, Reason: reason}
	}
	if _, err = json.Marshal(out); err != nil {
		return ProfileResponse{}, auth.Scope{}, model.Fail(model.Corrupt) // a view the wire cannot carry is never an empty 200
	}
	return out, scope, nil
}

// RegisterProfileRoutes mounts the profile view. The route needs the CSRF
// binding of artifactCredential for a session caller and derives its scope from
// the caller's own credential.
//
//	POST /api/v1/profiles/view  ProfileBody -> ProfileResponse
func RegisterProfileRoutes(mux *http.ServeMux, authority *auth.Service, p *Profiles) {
	mux.HandleFunc("POST /api/v1/profiles/view", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body ProfileBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		view, scope, err := p.View(r.Context(), authority, credential, body)
		if err == nil {
			err = authority.Revalidate(r.Context(), scope)
		}
		queryReply(w, view, err)
	})
}
