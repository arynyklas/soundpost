// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// restoreState is what GET /api/v1/session says about a restored installation: how
// many quarantined items are still inactive. It is absent (not zero) when nothing is
// pending, so an ordinary installation's session body is unchanged.
type restoreState struct {
	Pending int `json:"pending"`
}

// sessionBody is the GET /api/v1/session answer: the core session plus the restore state.
type sessionBody struct {
	auth.Session
	Restore *restoreState `json:"restore,omitempty"`
}

func sessionWithRestore(r *http.Request, s *auth.Service) (sessionBody, error) {
	v, err := s.Session(r.Context(), token(r))
	if err != nil {
		return sessionBody{}, err
	}
	body := sessionBody{Session: v}
	pending, err := s.RestorePending(r.Context())
	if err != nil {
		return sessionBody{}, err
	}
	if pending > 0 {
		body.Restore = &restoreState{Pending: pending}
	}
	return body, nil
}

// registerRestoreRoutes serves the disaster-restore reauthorization surface of the
// auth core (internal/auth/restore.go). Neither route implements a rule of its own:
// both are CSRF-protected and delegate to the instance-admin checks, the freshness
// requirement and the committed audit of auth.Service.
//
//	POST /api/v1/restore/items      {}                          -> RestoreView (instance admin)
//	POST /api/v1/restore/reconcile  Reconciliation (+ Reason)   -> Reconciled (fresh instance admin)
func registerRestoreRoutes(mux *http.ServeMux, s *auth.Service) {
	mux.HandleFunc("POST /api/v1/restore/items", func(w http.ResponseWriter, r *http.Request) {
		c, err := protected(s, w, r)
		if err != nil {
			reply(w, nil, err)
			return
		}
		var q struct{}
		if err = decode(w, r, &q); err != nil {
			reply(w, nil, err)
			return
		}
		view, err := s.RestoreItems(r.Context(), c)
		reply(w, view, err)
	})
	mux.HandleFunc("POST /api/v1/restore/reconcile", func(w http.ResponseWriter, r *http.Request) {
		c, err := protected(s, w, r)
		if err != nil {
			reply(w, nil, err)
			return
		}
		var q auth.Reconciliation
		if err = decode(w, r, &q); err != nil {
			reply(w, nil, err)
			return
		}
		if q.Kind == "" {
			reply(w, nil, model.Fail(model.Invalid))
			return
		}
		out, err := s.Reconcile(r.Context(), c, q)
		reply(w, out, err)
	})
}
