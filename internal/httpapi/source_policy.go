// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"net/http"
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
}

// RegisterOperationRoutes mounts the one GET /api/v1/operations/{id} route.
// It answers two kinds of operation: source-policy operations (auth store;
// scope is the operation's own organization, caller must administer it) and
// lifecycle operations (deletion/restriction, C11 PollDelete; scope is the
// organization the id belongs to, found through the control store when the
// caller sends no ?org= selector, or the caller's organization admin grant for
// an explicit ?org=). actions may be nil: the route then answers only
// source-policy operations. Mount it once per mux, next to
// RegisterSourcePolicyRoutes and RegisterActionRoutes.
func RegisterOperationRoutes(mux *http.ServeMux, a *auth.Service, actions *Actions) {
	p := &operationPoller{authority: a, actions: actions}
	mux.HandleFunc("GET /api/v1/operations/{id}", p.serve)
}

type operationPoller struct {
	authority *auth.Service
	actions   *Actions
}

// serve resolves the id. Without ?org= a source-policy operation answers
// first (its organization is recorded with it); on a miss the control store
// maps the id to the organization that owns a lifecycle operation
// (Actions.OperationOrg), that organization is authorized for the caller, and
// only then is the operation read. With ?org= the scope is authorized first,
// then the id is looked up as a source operation of that organization, then as a
// lifecycle operation under that scope. Every miss, foreign id included, is the
// same not-found whichever store would have held it, and an authorization
// refusal of the owning organization is that not-found too: the answer must not
// say that an id exists in an organization the caller does not administer.
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
		if e == nil || faultCodeOf(e) != model.NotFound || p.actions == nil {
			reply(w, operation, e)
			return
		}
		if op, ok, e := p.unscopedLifecycle(r.Context(), c, id); ok || e != nil {
			queryReply(w, op, e)
			return
		}
		reply(w, nil, model.Fail(model.NotFound))
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
	actions := p.actions
	if actions == nil {
		queryReply(w, nil, model.Fail(model.NotFound))
		return
	}
	op, e := actions.GetOperation(r.Context(), scope, id)
	queryReply(w, op, e)
}

// unscopedLifecycle answers a lifecycle operation for a caller who sent no
// organization selector. ok is true when the answer is the operation or a real
// failure to read it; false means "not found for this caller", which the route
// answers like any miss. The control store only names the owning organization;
// that organization is authorized (organization administrator) BEFORE the
// operation is read, and a refusal is a miss, so neither the status nor the
// body distinguishes an id of a foreign organization from an unknown one.
func (p *operationPoller) unscopedLifecycle(ctx context.Context, c auth.Credential, id model.ID) (op LifecycleOperation, ok bool, err error) {
	org, found, err := p.actions.OperationOrg(ctx, id)
	if err != nil {
		return LifecycleOperation{}, true, err
	}
	if !found {
		return LifecycleOperation{}, false, nil
	}
	scope, err := p.authority.Authorize(ctx, c, org, nil, auth.OrgAdmin)
	if err != nil {
		if code := faultCodeOf(err); code == model.Forbidden || code == model.NotFound {
			return LifecycleOperation{}, false, nil
		}
		return LifecycleOperation{}, true, err
	}
	op, err = p.actions.GetOperation(ctx, scope, id)
	if faultCodeOf(err) == model.NotFound && err != nil {
		return LifecycleOperation{}, false, nil
	}
	return op, true, err
}
