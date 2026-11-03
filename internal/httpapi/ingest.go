// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"soundpost/internal/auth"
	"soundpost/internal/ingest"
	"soundpost/internal/model"
	"strings"
)

func sourceCredential(s *auth.Service, r *http.Request) (auth.SourceCredential, error) {
	if r.Header.Get("Cookie") != "" {
		return auth.SourceCredential{}, model.Fail(model.Forbidden)
	}
	for _, name := range []string{"Authorization", "X-Soundpost-Source", "Origin"} {
		if len(r.Header.Values(name)) > 1 {
			return auth.SourceCredential{}, model.Fail(model.Unauthenticated)
		}
	}
	browser, bearer := r.Header.Get("X-Soundpost-Source"), r.Header.Get("Authorization")
	if browser != "" {
		if bearer != "" || r.Header.Get("Origin") == "" || strings.ContainsAny(browser, " \t\r\n") {
			return auth.SourceCredential{}, model.Fail(model.Forbidden)
		}
		return s.AuthenticateSource(r.Context(), browser, r.Header.Get("Origin"), true)
	}
	scheme, raw, ok := strings.Cut(bearer, " ")
	if !ok || scheme != "Bearer" || raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return auth.SourceCredential{}, model.Fail(model.Unauthenticated)
	}
	return s.AuthenticateSource(r.Context(), raw, r.Header.Get("Origin"), false)
}
func ingestReply(w http.ResponseWriter, r *http.Request, v any, e error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if e == nil {
		_ = json.NewEncoder(w).Encode(v)
		return
	}
	var f *model.Fault
	if !errors.As(e, &f) {
		f = model.Fail(model.Unavailable)
	}
	copyF := *f
	copyF.RequestID = model.RequestCorrelationID(r.Context(), model.ID{})
	status := 422
	switch f.Code {
	case model.Unauthenticated:
		status = 401
	case model.Forbidden:
		status = 403
	case model.NotFound:
		status = 404
	case model.Conflict:
		status = 409
	case model.TooLarge:
		status = 413
	case model.Unsupported:
		status = 415
	case model.Quota:
		status = 429
	case model.Unavailable, model.Corrupt, model.Timeout, model.Stale:
		status = 503
	case model.Cancelled:
		status = 503
	}
	if status == 429 || status == 503 {
		copyF.Retryable = true
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(copyF)
}
func RegisterIngestRoutes(mux *http.ServeMux, a *auth.Service, s *ingest.Service) {
	RegisterSourcePolicyRoutes(mux, a)
	cors := func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Expose-Headers", "Retry-After, X-Soundpost-Receipt, X-Soundpost-Cursor, X-Request-ID")
		}
	}
	for _, path := range []string{"/ingest/v1/batches", "/ingest/v1/receipts", "/ingest/v1/source"} {
		mux.HandleFunc("OPTIONS "+path, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Cookie") != "" || r.Header.Get("Access-Control-Request-Method") != "POST" || !a.AllowsBrowserOrigin(r.Context(), r.Header.Get("Origin")) {
				ingestReply(w, r, nil, model.Fail(model.Forbidden))
				return
			}
			for _, h := range strings.Split(strings.ToLower(r.Header.Get("Access-Control-Request-Headers")), ",") {
				if !oneHeader(strings.TrimSpace(h), "content-type", "content-encoding", "x-soundpost-source") {
					ingestReply(w, r, nil, model.Fail(model.Forbidden))
					return
				}
			}
			cors(w, r)
			w.Header().Set("Access-Control-Allow-Methods", "POST")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Encoding, X-Soundpost-Source")
			w.WriteHeader(204)
		})
	}
	mux.HandleFunc("POST /ingest/v1/batches", func(w http.ResponseWriter, r *http.Request) {
		c, e := sourceCredential(a, r)
		if e != nil {
			ingestReply(w, r, nil, e)
			return
		}
		cors(w, r)
		b, e := ingest.Decode(r.Body, r.Header.Get("Content-Encoding"))
		if e != nil {
			ingestReply(w, r, nil, e)
			return
		}
		g, e := s.ResolveSource(r.Context(), c, b)
		if e != nil {
			ingestReply(w, r, nil, e)
			return
		}
		receipt, e := s.Admit(r.Context(), g, b)
		if e == nil {
			w.Header().Set("X-Soundpost-Receipt", receipt.BatchID.String())
			w.Header().Set("X-Soundpost-Cursor", receipt.Cursor.Group.String()+":"+stringRevision(receipt.Cursor.Index))
		}
		ingestReply(w, r, receipt, e)
	})
	mux.HandleFunc("POST /ingest/v1/receipts", func(w http.ResponseWriter, r *http.Request) {
		c, e := sourceCredential(a, r)
		if e != nil {
			ingestReply(w, r, nil, e)
			return
		}
		cors(w, r)
		raw, e := io.ReadAll(io.LimitReader(r.Body, 65537))
		var q model.ReceiptRequest
		if e != nil || len(raw) > 65536 || model.StrictJSON(raw, &q) != nil {
			ingestReply(w, r, nil, model.Fail(model.Invalid))
			return
		}
		v, e := s.LookupReceipt(r.Context(), c, q)
		ingestReply(w, r, v, e)
	})
	mux.HandleFunc("POST /ingest/v1/source", func(w http.ResponseWriter, r *http.Request) {
		c, e := sourceCredential(a, r)
		if e != nil {
			ingestReply(w, r, nil, e)
			return
		}
		cors(w, r)
		v, e := a.SourceConfiguration(r.Context(), c)
		ingestReply(w, r, v, e)
	})
	mux.HandleFunc("POST /api/v1/sources", func(w http.ResponseWriter, r *http.Request) {
		c, e := protected(a, w, r)
		if e != nil {
			reply(w, nil, e)
			return
		}
		var q auth.SourceOnboarding
		if e = decode(w, r, &q); e != nil {
			reply(w, nil, e)
			return
		}
		v, e := a.OnboardSource(r.Context(), c, q)
		reply(w, v, e)
	})
	mux.HandleFunc("POST /api/v1/sources/revoke", func(w http.ResponseWriter, r *http.Request) {
		c, e := protected(a, w, r)
		if e != nil {
			reply(w, nil, e)
			return
		}
		var q struct {
			Source model.ID `json:"source"`
			Reason string   `json:"reason"`
		}
		if e = decode(w, r, &q); e == nil {
			e = a.RevokeSource(r.Context(), c, q.Source, q.Reason)
		}
		if e != nil {
			reply(w, nil, e)
			return
		}
		operation, e := a.SourceFenceFor(r.Context(), c, q.Source)
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
func oneHeader(v string, allowed ...string) bool {
	for _, x := range allowed {
		if v == x {
			return true
		}
	}
	return false
}
func stringRevision(v uint64) string {
	b, _ := json.Marshal(model.Revision(v))
	return strings.Trim(string(b), "\"")
}
