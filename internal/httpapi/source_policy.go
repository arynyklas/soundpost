// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"encoding/json"
	"net/http"
	"soundpost/internal/auth"
	"soundpost/internal/model"
)

func RegisterSourcePolicyRoutes(mux *http.ServeMux, a *auth.Service) {
	mux.HandleFunc("POST /api/v1/quotas", func(w http.ResponseWriter, r *http.Request) {
		c, e := protected(a, w, r)
		if e != nil {
			reply(w, nil, e)
			return
		}
		var q auth.AdmissionQuotaChange
		if e = decode(w, r, &q); e != nil {
			reply(w, nil, e)
			return
		}
		result, e := a.SetAdmissionQuota(r.Context(), c, q)
		reply(w, result, e)
	})
	mux.HandleFunc("POST /api/v1/sources/policy", func(w http.ResponseWriter, r *http.Request) {
		c, e := protected(a, w, r)
		if e != nil {
			reply(w, nil, e)
			return
		}
		var q auth.SourcePolicyChange
		if e = decode(w, r, &q); e != nil {
			reply(w, nil, e)
			return
		}
		operation, e := a.ChangeSourcePolicy(r.Context(), c, q)
		if e != nil {
			reply(w, nil, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(operation)
	})
	mux.HandleFunc("GET /api/v1/operations/{id}", func(w http.ResponseWriter, r *http.Request) {
		c, e := AuthenticateRequest(a, r)
		if e != nil {
			reply(w, nil, e)
			return
		}
		id, e := model.ParseID(r.PathValue("id"))
		if e != nil {
			reply(w, nil, model.Fail(model.NotFound))
			return
		}
		operation, e := a.SourceOperation(r.Context(), c, id)
		reply(w, operation, e)
	})
}
