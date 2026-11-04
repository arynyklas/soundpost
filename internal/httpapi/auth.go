// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"strings"
)

// AuthenticateRequest is the sole HTTP bearer parser. Browser session tokens
// remain cookie-only; narrow server tokens cannot become browser admin sessions.
func AuthenticateRequest(service *auth.Service, r *http.Request) (auth.Credential, error) {
	values := r.Header.Values("Authorization")
	if len(values) > 0 {
		if len(values) != 1 {
			return auth.Credential{}, model.Fail(model.Unauthenticated)
		}
		scheme, value, ok := strings.Cut(values[0], " ")
		if !ok || scheme != "Bearer" || value == "" || strings.ContainsAny(value, " \t\r\n") {
			return auth.Credential{}, model.Fail(model.Unauthenticated)
		}
		c, err := service.Authenticate(r.Context(), value)
		if err != nil {
			return auth.Credential{}, err
		}
		if !c.IsServerToken() {
			return auth.Credential{}, model.Fail(model.Unauthenticated)
		}
		return c, nil
	}
	return service.Authenticate(r.Context(), token(r))
}
func RegisterTokenRoutes(mux *http.ServeMux, s *auth.Service) {
	mux.HandleFunc("POST /api/v1/admin/tokens/issue", func(w http.ResponseWriter, r *http.Request) {
		c, err := protected(s, w, r)
		if err != nil {
			reply(w, nil, err)
			return
		}
		var q struct {
			OrgID       model.ID          `json:"org_id"`
			Principal   model.ID          `json:"principal"`
			Projects    []model.ID        `json:"projects"`
			Permissions []auth.Permission `json:"permissions"`
			Expires     model.Int64       `json:"expires"`
			Reason      string            `json:"reason"`
		}
		if err = decode(w, r, &q); err != nil {
			reply(w, nil, err)
			return
		}
		v, err := s.IssueServerToken(r.Context(), c, q.OrgID, q.Principal, q.Projects, q.Permissions, int64(q.Expires), q.Reason)
		reply(w, v, err)
	})
	mux.HandleFunc("POST /api/v1/admin/tokens/revoke", func(w http.ResponseWriter, r *http.Request) {
		c, err := protected(s, w, r)
		if err != nil {
			reply(w, nil, err)
			return
		}
		var q struct {
			OrgID  model.ID `json:"org_id"`
			ID     model.ID `json:"id"`
			Reason string   `json:"reason"`
		}
		if err = decode(w, r, &q); err == nil {
			err = s.RevokeServerToken(r.Context(), c, q.OrgID, q.ID, q.Reason)
		}
		reply(w, struct{}{}, err)
	})
}
