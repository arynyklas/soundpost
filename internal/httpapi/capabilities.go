// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"net/http"
	"soundpost/internal/auth"
	"soundpost/internal/model"
)

// readCredential authenticates a safe (GET) read: a narrow server token via
// Authorization, otherwise the same-origin strict cookie session.
func readCredential(s *auth.Service, r *http.Request) (auth.Credential, error) {
	if len(r.Header.Values("Authorization")) != 0 {
		return AuthenticateRequest(s, r)
	}
	return s.Authenticate(r.Context(), token(r))
}

// secondaryScope derives the one scope a secondary read/export runs under.
// A wrong org, wrong project, missing grant or absent target all surface as
// the same NotFound from auth, before any index, cache or export table is read.
func secondaryScope(ctx context.Context, s *auth.Service, c auth.Credential, org, project, elevation, source model.ID, permission auth.Permission) (auth.Scope, error) {
	if org == (model.ID{}) || project == (model.ID{}) {
		return auth.Scope{}, model.Fail(model.Invalid)
	}
	if elevation != (model.ID{}) {
		if permission != auth.Read || source != (model.ID{}) {
			return auth.Scope{}, model.Fail(model.Forbidden)
		}
		e, err := s.ResolveElevation(ctx, c, elevation)
		if err != nil {
			return auth.Scope{}, err
		}
		return s.ElevatedScope(ctx, e, org, []model.ID{project}, permission)
	}
	switch permission {
	case auth.Read:
		if source != (model.ID{}) {
			return auth.Scope{}, model.Fail(model.Invalid)
		}
		return s.Authorize(ctx, c, org, []model.ID{project}, auth.Read)
	case auth.RawRead:
		if source == (model.ID{}) {
			return s.Authorize(ctx, c, org, []model.ID{project}, auth.RawRead)
		}
		return s.AuthorizeRestrictedSource(ctx, c, org, project, source)
	}
	return auth.Scope{}, model.Fail(model.Invalid)
}
func parsePermission(v string) (auth.Permission, error) {
	switch v {
	case "", string(auth.Read):
		return auth.Read, nil
	case string(auth.RawRead):
		return auth.RawRead, nil
	}
	return "", model.Fail(model.Invalid)
}
func optionalID(v string) (model.ID, error) {
	if v == "" {
		return model.ID{}, nil
	}
	id, err := model.ParseID(v)
	if err != nil {
		return model.ID{}, model.Fail(model.Invalid)
	}
	return id, nil
}

// RegisterCapabilityRoutes serves GET /api/v1/capabilities. It discloses only
// the real, active sources the caller's scope may read; it never carries
// reader lists, credentials, other projects/orgs, or counts of hidden sources.
func RegisterCapabilityRoutes(mux *http.ServeMux, s *auth.Service) {
	mux.HandleFunc("GET /api/v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		c, err := readCredential(s, r)
		if err != nil {
			reply(w, nil, err)
			return
		}
		q := r.URL.Query()
		org, e1 := model.ParseID(q.Get("org"))
		project, e2 := model.ParseID(q.Get("project"))
		permission, e3 := parsePermission(q.Get("permission"))
		elevation, e4 := optionalID(q.Get("elevation"))
		source, e5 := optionalID(q.Get("source"))
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || len(q) > 5 {
			reply(w, nil, model.Fail(model.Invalid))
			return
		}
		scope, err := secondaryScope(r.Context(), s, c, org, project, elevation, source, permission)
		if err != nil {
			reply(w, nil, err)
			return
		}
		sources, err := s.VisibleSources(r.Context(), scope)
		if err == nil {
			err = s.CommitElevatedRead(r.Context(), scope, "capabilities.read", []model.ID{project})
		}
		if err != nil {
			reply(w, nil, err)
			return
		}
		if sources == nil {
			sources = []auth.VisibleSource{}
		}
		reply(w, struct {
			Sources []auth.VisibleSource `json:"sources"`
		}{sources}, nil)
	})
}
