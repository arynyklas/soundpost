// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/exports"
	"github.com/arynyklas/soundpost/internal/model"
	"net/http"
)

// ExportRequest is the closed C11 /api/v1/exports body. create, status and
// download all rebuild the same scope from the caller's own credential; no
// body field can name another principal's scope.
type ExportRequest struct {
	Operation  string      `json:"operation"`
	Org        model.ID    `json:"org"`
	Project    model.ID    `json:"project"`
	Permission string      `json:"permission,omitempty"`
	Source     *model.ID   `json:"source,omitempty"`
	Elevation  *model.ID   `json:"elevation,omitempty"`
	Signal     model.Kind  `json:"signal,omitempty"`
	Start      model.Int64 `json:"start_ns,omitempty"`
	End        model.Int64 `json:"end_ns,omitempty"`
	ID         *model.ID   `json:"id,omitempty"`
	Ticket     string      `json:"ticket,omitempty"`
}

func RegisterExportRoutes(mux *http.ServeMux, authority *auth.Service, service *exports.Service) {
	mux.HandleFunc("POST /api/v1/exports", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			reply(w, nil, err)
			return
		}
		var q ExportRequest
		if err = decode(w, r, &q); err != nil {
			reply(w, nil, err)
			return
		}
		permission, err := parsePermission(q.Permission)
		if err != nil {
			reply(w, nil, err)
			return
		}
		source, elevation, id := idOrZero(q.Source), idOrZero(q.Elevation), idOrZero(q.ID)
		scope, err := secondaryScope(r.Context(), authority, credential, q.Org, q.Project, elevation, source, permission)
		if err != nil {
			reply(w, nil, err)
			return
		}
		switch q.Operation {
		case "create":
			grant, err := service.Create(r.Context(), scope, exports.Request{Project: q.Project, Signal: q.Signal, Source: source, Start: q.Start, End: q.End})
			if err != nil {
				reply(w, nil, err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(grant)
		case "status":
			op, err := service.Status(r.Context(), scope, id)
			reply(w, op, err)
		case "download":
			// The first chunk is fully authorized (and, when elevated, audited)
			// before any header or byte is committed to the response.
			chunk, err := service.Chunk(r.Context(), scope, q.Ticket, id, 0)
			if err != nil {
				reply(w, nil, err)
				return
			}
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.Header().Set("Content-Disposition", `attachment; filename="`+id.String()+`.ndjson"`)
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			for index := uint64(1); ; index++ {
				if _, err = w.Write(chunk.Data); err != nil {
					return
				}
				if chunk.Last {
					return
				}
				// Every later chunk re-runs scope, ticket, epoch, deletion and
				// audit checks. A failure aborts the stream; it never falls
				// back to releasing the remaining bytes.
				chunk, err = service.Chunk(r.Context(), scope, q.Ticket, id, index)
				if err != nil {
					panic(http.ErrAbortHandler)
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		default:
			reply(w, nil, model.Fail(model.Invalid))
		}
	})
}

func idOrZero(id *model.ID) model.ID {
	if id == nil {
		return model.ID{}
	}
	return *id
}

// OptionalID returns nil for the zero ID so an absent identity is omitted from
// the wire form instead of being serialized (a zero ID is not representable).
func OptionalID(id model.ID) *model.ID {
	if id == (model.ID{}) {
		return nil
	}
	return &id
}
