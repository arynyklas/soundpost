// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http"
	"soundpost/internal/auth"
)

type AdminCommandRequest = auth.AdminCommandRequest
type AdminReadRequest = auth.AdminReadRequest

func RegisterAdminRoutes(mux *http.ServeMux, s *auth.Service) {
	mux.HandleFunc("POST /api/v1/admin/commands", func(w http.ResponseWriter, r *http.Request) {
		c, e := protected(s, w, r)
		if e != nil {
			reply(w, nil, e)
			return
		}
		var q AdminCommandRequest
		if e = decode(w, r, &q); e != nil {
			reply(w, nil, e)
			return
		}
		v, e := s.AdminCommand(r.Context(), c, q)
		reply(w, v, e)
	})
	mux.HandleFunc("POST /api/v1/admin/read", func(w http.ResponseWriter, r *http.Request) {
		c, e := protected(s, w, r)
		if e != nil {
			reply(w, nil, e)
			return
		}
		var q AdminReadRequest
		if e = decode(w, r, &q); e != nil {
			reply(w, nil, e)
			return
		}
		v, e := s.AdminRead(r.Context(), c, q)
		reply(w, v, e)
	})
}
