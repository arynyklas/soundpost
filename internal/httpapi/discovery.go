// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/query"
	"net/http"
)

// DiscoveryBody is the POST /api/v1/discover body: the scope fields and the C06
// DiscoveryRequest, flattened.
type DiscoveryBody struct {
	ScopeFields
	query.DiscoveryRequest
}

// ExemplarBody is the POST /api/v1/exemplars body.
type ExemplarBody struct {
	ScopeFields
	query.ExemplarRequest
}

// registerDiscovery mounts discovery and exemplars. Both run only through the
// scope derived from the caller's own credential, so a raw.read caller names its
// one restricted source (Source) exactly like a query does and cannot enumerate
// any other source, project or organization; there is no discovery path that
// bypasses the raw-read grant.
func registerDiscovery(mux *http.ServeMux, authority *auth.Service, service QueryService) {
	mux.HandleFunc("POST /api/v1/discover", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var q DiscoveryBody
		if err = decode(w, r, &q); err != nil {
			queryReply(w, nil, err)
			return
		}
		scope, err := queryScope(r.Context(), authority, credential, q.ScopeFields, q.Projects, q.Source)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		res, err := service.Discover(r.Context(), scope, q.DiscoveryRequest)
		if err == nil {
			err = authority.CommitElevatedRead(r.Context(), scope, "query.discover", q.Projects)
		}
		queryReply(w, res, err)
	})
	mux.HandleFunc("POST /api/v1/exemplars", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var q ExemplarBody
		if err = decode(w, r, &q); err != nil {
			queryReply(w, nil, err)
			return
		}
		scope, err := queryScope(r.Context(), authority, credential, q.ScopeFields, q.Projects, nil)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		res, err := service.Exemplars(r.Context(), scope, q.ExemplarRequest)
		if err == nil {
			err = authority.CommitElevatedRead(r.Context(), scope, "query.exemplars", q.Projects)
		}
		queryReply(w, res, err)
	})
}
