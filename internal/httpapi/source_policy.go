// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"encoding/json"
	"net/http"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"sync"
	"sync/atomic"
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
	operationRoute(mux, a)
}

// operationPoller owns the one GET /api/v1/operations/{id} route of a mux. The
// route answers two kinds of operation: source-policy operations (auth store;
// scope is the operation's own organization, caller must administer it) and
// lifecycle operations (deletion/restriction, C11 PollDelete; scope is the
// caller's organization admin grant for the ?org= selector). Whichever of
// RegisterSourcePolicyRoutes and RegisterActionRoutes runs first registers the
// route; the other only binds its half, so mount order does not matter and a
// process with only one half answers only that half.
type operationPoller struct {
	authority *auth.Service
	actions   atomic.Pointer[Actions]
}

var operationPollers sync.Map // *http.ServeMux -> *operationPoller
var operationPollersMu sync.Mutex

func operationRoute(mux *http.ServeMux, a *auth.Service) *operationPoller {
	operationPollersMu.Lock()
	defer operationPollersMu.Unlock()
	if p, ok := operationPollers.Load(mux); ok {
		return p.(*operationPoller)
	}
	p := &operationPoller{authority: a}
	operationPollers.Store(mux, p)
	mux.HandleFunc("GET /api/v1/operations/{id}", p.serve)
	return p
}

// serve resolves the id. Without ?org= only a source-policy operation can
// answer (its organization is recorded with it); a lifecycle operation needs
// the organization selector because no store maps a deletion id to its owner
// without a scope. With ?org= the scope is authorized first, then the id is
// looked up as a source operation of that organization, then as a lifecycle
// operation under that scope. Every miss, foreign id included, is the same
// not-found whichever store would have held it.
func (p *operationPoller) serve(w http.ResponseWriter, r *http.Request) {
	c, e := AuthenticateRequest(p.authority, r)
	if e != nil {
		reply(w, nil, e)
		return
	}
	q := r.URL.Query()
	if len(q) != 0 && !onlyKeys(q, "org") {
		reply(w, nil, model.Fail(model.Invalid))
		return
	}
	id, e := model.ParseID(r.PathValue("id"))
	if e != nil {
		reply(w, nil, model.Fail(model.NotFound))
		return
	}
	if !q.Has("org") {
		operation, e := p.authority.SourceOperation(r.Context(), c, id)
		reply(w, operation, e)
		return
	}
	org, e := model.ParseID(q.Get("org"))
	if e != nil {
		queryReply(w, nil, model.Fail(model.NotFound))
		return
	}
	scope, e := p.authority.Authorize(r.Context(), c, org, nil, auth.OrgAdmin)
	if e != nil {
		queryReply(w, nil, e)
		return
	}
	if operation, e := p.authority.SourceOperation(r.Context(), c, id); e == nil && operation.Org == org {
		queryReply(w, operation, nil)
		return
	}
	actions := p.actions.Load()
	if actions == nil {
		queryReply(w, nil, model.Fail(model.NotFound))
		return
	}
	op, e := actions.GetOperation(r.Context(), scope, id)
	queryReply(w, op, e)
}
