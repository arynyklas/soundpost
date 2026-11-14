// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"io"
	"net/http"
)

// QueryService is the owned C06 engine as the HTTP layer consumes it.
// *query.Engine implements it; no other implementation, and no upstream
// Prometheus/Loki process, is ever behind these routes.
type QueryService interface {
	Execute(ctx context.Context, scope auth.Scope, req query.Request) (query.Result, error)
	Discover(ctx context.Context, scope auth.Scope, req query.DiscoveryRequest) (query.DiscoveryResult, error)
	Exemplars(ctx context.Context, scope auth.Scope, req query.ExemplarRequest) (query.ExemplarResult, error)
	Format(ctx context.Context, scope auth.Scope, req query.FormatRequest) (query.FormatResult, error)
}

// RegisterQueryRoutes mounts the four owned C06 routes. They are POST-only so
// telemetry expressions never appear in a URL, and every one rebuilds the scope
// from the caller's own credential: no body field can name another principal's
// scope.
//
//	POST /api/v1/query         typed Request -> Result{Projects}
//	POST /api/v1/query/format  FormatRequest -> FormatResult
//	POST /api/v1/discover      DiscoveryRequest -> DiscoveryResult
//	POST /api/v1/exemplars     ExemplarRequest -> ExemplarResult
func RegisterQueryRoutes(mux *http.ServeMux, authority *auth.Service, service QueryService) {
	registerQuery(mux, authority, service)
	registerDiscovery(mux, authority, service)
}

// ScopeFields are the authorization fields every C06 body carries next to its
// typed request: the organization, the permission (telemetry.read by default,
// raw.read for one named restricted source) and an optional audited elevation.
type ScopeFields struct {
	Org        model.ID  `json:"org"`
	Permission string    `json:"permission,omitempty"`
	Elevation  *model.ID `json:"elevation,omitempty"`
}

// QueryBody is the POST /api/v1/query body: the scope fields and the C06
// Request, flattened.
type QueryBody struct {
	ScopeFields
	query.Request
}

// FormatBody is the POST /api/v1/query/format body. Formatting reads no
// telemetry, but is behind the same scope as the query it prepares, named by
// Projects.
type FormatBody struct {
	ScopeFields
	Projects []model.ID `json:"projects"`
	query.FormatRequest
}

// queryScope derives the one scope a C06 request runs under. A wrong org,
// project, missing grant, non-reader of the named source or revoked credential
// is the same NotFound from auth, before the engine (or any index) is reached.
func queryScope(ctx context.Context, s *auth.Service, c auth.Credential, f ScopeFields, projects []model.ID, source *model.ID) (auth.Scope, error) {
	if f.Org == (model.ID{}) || len(projects) == 0 {
		return auth.Scope{}, model.Fail(model.Invalid)
	}
	permission, err := parsePermission(f.Permission)
	if err != nil {
		return auth.Scope{}, err
	}
	if f.Elevation != nil {
		if permission != auth.Read || source != nil {
			return auth.Scope{}, model.Fail(model.Forbidden)
		}
		e, err := s.ResolveElevation(ctx, c, *f.Elevation)
		if err != nil {
			return auth.Scope{}, collapseElevationDenial(err)
		}
		scope, err := s.ElevatedScope(ctx, e, f.Org, projects, permission)
		if err != nil {
			return auth.Scope{}, collapseElevationDenial(err)
		}
		return scope, nil
	}
	if permission == auth.Read {
		if source != nil {
			return auth.Scope{}, model.Fail(model.Invalid)
		}
		return s.Authorize(ctx, c, f.Org, projects, auth.Read)
	}
	if source == nil || len(projects) != 1 {
		return auth.Scope{}, model.Fail(model.Invalid)
	}
	return s.AuthorizeRestrictedSource(ctx, c, f.Org, projects[0], *source)
}

func registerQuery(mux *http.ServeMux, authority *auth.Service, service QueryService) {
	mux.HandleFunc("POST /api/v1/query", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var q QueryBody
		if err = decode(w, r, &q); err != nil {
			queryReply(w, nil, err)
			return
		}
		scope, err := queryScope(r.Context(), authority, credential, q.ScopeFields, q.Projects, q.Source)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		res, err := service.Execute(r.Context(), scope, q.Request)
		if err == nil {
			// An elevated read is durably audited before any byte of the response.
			err = authority.CommitElevatedRead(r.Context(), scope, "query.read", q.Projects)
		}
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		// Release point: Execute performed the final authorization and deletion
		// check and already freed its session, so the serialization below runs
		// without a further revalidation. The window from that check to the last
		// byte grows with the response (measured: 200 000 log entries serialize in
		// about 150 ms to a null writer; a response at the working budget takes
		// seconds). Revalidating between value chunks is the live stream's job
		// (internal/query/live.go), whose sessions stay open while bytes flow; this
		// one-shot route deliberately keeps the contract's single final check.
		queryReply(w, resultStream{res}, nil)
	})
	mux.HandleFunc("POST /api/v1/query/format", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var q FormatBody
		if err = decode(w, r, &q); err != nil {
			queryReply(w, nil, err)
			return
		}
		scope, err := queryScope(r.Context(), authority, credential, q.ScopeFields, q.Projects, nil)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		res, err := service.Format(r.Context(), scope, q.FormatRequest)
		if err == nil {
			err = authority.CommitElevatedRead(r.Context(), scope, "query.format", q.Projects)
		}
		queryReply(w, res, err)
	})
}

// languageFault is the wire form of a language error: its category, owned
// error code and source range, and a static safe message. It never contains
// the query text or an upstream status.
type languageFault struct {
	Code         string             `json:"code"`
	LanguageCode string             `json:"language_code"`
	Category     string             `json:"category"`
	SourceRange  *query.SourceRange `json:"source_range"`
	Detail       string             `json:"detail"`
	RequestID    *model.ID          `json:"request_id,omitempty"`
}

func statusOf(code model.Code) int {
	switch code {
	case model.Invalid:
		return http.StatusBadRequest
	case model.Unauthenticated:
		return http.StatusUnauthorized
	case model.Forbidden:
		return http.StatusForbidden
	case model.NotFound:
		return http.StatusNotFound
	case model.Conflict, model.Stale:
		return http.StatusConflict
	case model.TooLarge:
		return http.StatusRequestEntityTooLarge
	case model.Quota:
		return http.StatusTooManyRequests
	case model.Cancelled:
		return 499
	case model.Timeout:
		return http.StatusGatewayTimeout
	case model.Unsupported:
		return http.StatusNotImplemented
	}
	return http.StatusServiceUnavailable
}

// queryReply writes the response. Failures are typed: a language error keeps
// its category and range, anything else is a model fault whose HTTP status
// distinguishes budgets (429), deadlines (504), cancellation (499), deletion
// (409) and authorization (404/403). An error never carries a partial body.
func queryReply(w http.ResponseWriter, v any, e error) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	requestID, _ := model.ParseID(w.Header().Get("X-Request-ID"))
	if e != nil {
		var language *syntax.LanguageError
		if errors.As(e, &language) {
			body := languageFault{Code: "language", LanguageCode: language.Code, Category: language.Category, Detail: language.SafeMessage, SourceRange: &query.SourceRange{StartByte: language.Range.StartByte, EndByte: language.Range.EndByte, StartRune: language.Range.StartRune, EndRune: language.Range.EndRune}}
			if requestID != (model.ID{}) {
				body.RequestID = &requestID
			}
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(body)
			return
		}
		var f *model.Fault
		if !errors.As(e, &f) {
			f = model.Fail(model.Unavailable)
		}
		if requestID != (model.ID{}) {
			copied := *f
			copied.RequestID = requestID
			f = &copied
		}
		w.WriteHeader(statusOf(f.Code))
		_ = json.NewEncoder(w).Encode(f)
		return
	}
	if s, ok := v.(resultStream); ok {
		if err := s.write(w); err != nil {
			// Headers are committed: the only honest outcome is a dead connection,
			// never a truncated body that parses as a short answer.
			panic(http.ErrAbortHandler)
		}
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

// resultStream writes a Result series by series and stream by stream through a
// small buffer, so serializing a large answer never doubles its memory.
type resultStream struct{ res query.Result }

func (s resultStream) write(w io.Writer) error {
	out := bufio.NewWriterSize(w, 32<<10)
	enc := json.NewEncoder(out)
	put := func(key string, v any) error {
		if _, err := out.WriteString(key); err != nil {
			return err
		}
		return enc.Encode(v) // Encode appends a newline, valid JSON whitespace
	}
	if _, err := out.WriteString(`{"projects":[`); err != nil {
		return err
	}
	for i, pr := range s.res.Projects {
		if i > 0 {
			out.WriteByte(',')
		}
		if err := put(`{"project_id":`, pr.ProjectID); err != nil {
			return err
		}
		out.WriteString(`,"value":`)
		if err := writeValue(out, enc, pr.Value); err != nil {
			return err
		}
		for _, f := range []struct {
			key string
			v   any
		}{{`,"diagnostics":`, pr.Diagnostics}, {`,"watermarks":`, pr.Watermarks}, {`,"completeness":`, pr.Completeness}, {`,"stats":`, pr.Stats}} {
			if err := put(f.key, f.v); err != nil {
				return err
			}
		}
		if pr.Failure != nil {
			if err := put(`,"failure":`, pr.Failure); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	}
	if _, err := out.WriteString(`]}`); err != nil {
		return err
	}
	return out.Flush()
}

func writeValue(out *bufio.Writer, enc *json.Encoder, v *query.Value) error {
	if v == nil {
		_, err := out.WriteString("null")
		return err
	}
	element := func(i int, x any) error {
		if i > 0 {
			out.WriteByte(',')
		}
		return enc.Encode(x)
	}
	switch v.Type {
	case query.ValueVector:
		out.WriteString(`{"type":"vector","vector":[`)
		for i, x := range v.Vector {
			if err := element(i, x); err != nil {
				return err
			}
		}
	case query.ValueMatrix:
		out.WriteString(`{"type":"matrix","matrix":[`)
		for i, x := range v.Matrix {
			if err := element(i, x); err != nil {
				return err
			}
		}
	case query.ValueStreams:
		out.WriteString(`{"type":"streams","streams":[`)
		for i, stream := range v.Streams {
			if i > 0 {
				out.WriteByte(',')
			}
			labels, err := json.Marshal(stream.Labels)
			if err != nil {
				return err
			}
			out.WriteString(`{"labels":`)
			out.Write(labels)
			out.WriteString(`,"entries":[`)
			for j, entry := range stream.Entries {
				if err := element(j, entry); err != nil {
					return err
				}
			}
			out.WriteString(`]}`)
		}
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		_, err = out.Write(raw)
		return err
	}
	_, err := out.WriteString(`]}`)
	return err
}
