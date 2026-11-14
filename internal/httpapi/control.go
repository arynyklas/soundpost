// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"net/http"
)

// RegisterControlRoutes exposes a permission probe, never a caller-constructible
// serialized Scope or an arbitrary control/database predicate.
func RegisterControlRoutes(mux *http.ServeMux, s *auth.Service) {
	mux.HandleFunc("POST /api/v1/control/authorize", func(w http.ResponseWriter, r *http.Request) {
		var c auth.Credential
		var err error
		if r.Header.Get("Authorization") != "" {
			c, err = AuthenticateRequest(s, r)
		} else {
			c, err = protected(s, w, r)
		}
		if err != nil {
			reply(w, nil, err)
			return
		}
		var q struct {
			OrgID      model.ID        `json:"org_id"`
			ProjectIDs []model.ID      `json:"project_ids"`
			Permission auth.Permission `json:"permission"`
		}
		if err = decode(w, r, &q); err != nil {
			reply(w, nil, err)
			return
		}
		scope, err := s.Authorize(r.Context(), c, q.OrgID, q.ProjectIDs, q.Permission)
		if err == nil {
			err = s.Revalidate(r.Context(), scope)
		}
		if err != nil {
			reply(w, nil, err)
			return
		}
		reply(w, struct {
			Authorized  bool         `json:"authorized"`
			PolicyEpoch model.Uint64 `json:"policy_epoch"`
		}{true, model.Uint64(scope.PolicyEpoch())}, nil)
	})
}
