// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"io"
	"net/http"
	"strconv"
	"time"
)

// LiveService is the owned live stream service as the HTTP layer consumes it.
// *query.LiveService implements it.
type LiveService interface {
	CreateLiveTicket(ctx context.Context, scope auth.Scope, req query.LiveRequest) (query.LiveTicket, error)
	LiveTicketRequest(ctx context.Context, id query.LiveTicketID) (query.LiveRequest, error)
	Live(ctx context.Context, scope auth.Scope, ticket query.LiveTicketID, after *uint64) (query.LiveIterator, error)
}

// LiveTicketBody is the POST /api/v1/live-tickets body: the scope fields and the
// stored live request, flattened. Selector, projects and expression live here,
// never in the stream's GET URL.
type LiveTicketBody struct {
	ScopeFields
	query.LiveRequest
}

// liveCarrier is the authority the ticket remembers next to the request so the
// GET can rebuild the same scope from the caller's own credential. It carries
// no credential and no elevation (live streams refuse elevated scopes: an
// elevated read is audited per release, which a long-lived stream cannot do).
type liveCarrier struct {
	Org        model.ID `json:"org"`
	Permission string   `json:"permission,omitempty"`
}

// liveWriteTimeout bounds one blocked write to a slow consumer; the server's
// global write timeout would otherwise end every long-lived stream.
const liveWriteTimeout = 10 * time.Second

// liveSession is a digest of the presented credential: a ticket is usable only
// by the session that created it, and the credential itself is never stored.
func liveSession(r *http.Request) string {
	credential := token(r)
	if header := r.Header.Get("Authorization"); header != "" {
		credential = header
	}
	sum := sha256.Sum256([]byte("soundpost-live-session\x00" + credential))
	return hex.EncodeToString(sum[:])
}

// RegisterLiveRoutes mounts the owned live stream routes.
//
//	POST /api/v1/live-tickets  scope fields + LiveRequest -> {ticket, expires_at}
//	GET  /api/v1/live?ticket=<id>  (Last-Event-ID: <sequence>) -> text/event-stream
//
// The stream is a genuine push stream of the committed change feed with a
// bounded replay and explicit gap events; it is not Loki tail or WebSocket
// compatible and makes no lossless-delivery claim. Every event is delivered
// only after the caller's scope and the delete generation were revalidated.
func RegisterLiveRoutes(mux *http.ServeMux, authority *auth.Service, service LiveService) {
	mux.HandleFunc("POST /api/v1/live-tickets", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var q LiveTicketBody
		if err = decode(w, r, &q); err != nil {
			queryReply(w, nil, err)
			return
		}
		if q.Elevation != nil {
			queryReply(w, nil, model.Fail(model.Forbidden))
			return
		}
		ctx := query.WithLiveSession(r.Context(), liveSession(r))
		scope, err := queryScope(ctx, authority, credential, q.ScopeFields, q.Projects, q.Source)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		req := q.LiveRequest
		if req.Carrier, err = json.Marshal(liveCarrier{Org: q.Org, Permission: q.Permission}); err != nil {
			queryReply(w, nil, model.Fail(model.Unavailable))
			return
		}
		ticket, err := service.CreateLiveTicket(ctx, scope, req)
		queryReply(w, ticket, err)
	})
	mux.HandleFunc("GET /api/v1/live", func(w http.ResponseWriter, r *http.Request) {
		// The mux routes HEAD to GET patterns. A HEAD must never open a stream or
		// consume the single-use ticket, so it is refused before anything is read.
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		id, after, err := liveParams(r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		ctx := query.WithLiveSession(r.Context(), liveSession(r))
		req, err := service.LiveTicketRequest(ctx, id)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var carrier liveCarrier
		if json.Unmarshal(req.Carrier, &carrier) != nil {
			queryReply(w, nil, model.Fail(model.NotFound))
			return
		}
		scope, err := queryScope(ctx, authority, credential, ScopeFields{Org: carrier.Org, Permission: carrier.Permission}, req.Projects, req.Source)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		it, err := service.Live(ctx, scope, id, after)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		defer it.Close()
		streamLive(w, r, it)
	})
}

// liveParams reads the ticket identifier and the optional Last-Event-ID. The
// ticket is a non-secret identifier; anything else in the URL is refused so no
// selector or credential ever travels in it.
func liveParams(r *http.Request) (query.LiveTicketID, *uint64, error) {
	values := r.URL.Query()
	if len(values) != 1 || len(values["ticket"]) != 1 {
		return model.ID{}, nil, model.Fail(model.Invalid)
	}
	id, err := model.ParseID(values.Get("ticket"))
	if err != nil || id == (model.ID{}) {
		return model.ID{}, nil, model.Fail(model.Invalid)
	}
	header := r.Header.Values("Last-Event-ID")
	if len(header) == 0 {
		return id, nil, nil
	}
	if len(header) != 1 {
		return model.ID{}, nil, model.Fail(model.Invalid)
	}
	n, err := strconv.ParseUint(header[0], 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != header[0] {
		return model.ID{}, nil, model.Fail(model.Invalid)
	}
	return id, &n, nil
}

// streamLive writes events as server-sent events until the stream ends, the
// consumer goes away or a write cannot complete within liveWriteTimeout (a slow
// reader is dropped, never buffered for).
func streamLive(w http.ResponseWriter, r *http.Request, it query.LiveIterator) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	write := func(frame []byte) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(liveWriteTimeout))
		if _, err := w.Write(frame); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !write([]byte(": soundpost live\n\n")) {
		return
	}
	for {
		ev, err := it.Next(r.Context())
		if err != nil {
			if errors.Is(err, io.EOF) || r.Context().Err() != nil {
				return
			}
			// A typed failure that is not an event: tell the consumer, then end.
			ev = query.LiveEvent{Type: query.LiveError, Failure: failureFrame(err)}
		}
		frame, ok := liveFrame(ev)
		if !ok || !write(frame) {
			return
		}
		if ev.Terminal() {
			return
		}
	}
}

func failureFrame(err error) *query.Failure {
	var f *model.Fault
	if errors.As(err, &f) {
		return &query.Failure{Code: string(f.Code), SafeMessage: f.SafeDetail}
	}
	return &query.Failure{Code: string(model.Unavailable), SafeMessage: string(model.Unavailable)}
}

// liveFrame renders one SSE frame. The event ID is the stream sequence of
// record and gap events, so Last-Event-ID names exactly the last event handled.
func liveFrame(ev query.LiveEvent) ([]byte, bool) {
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, false
	}
	frame := make([]byte, 0, len(raw)+64)
	if ev.Sequence != 0 {
		frame = append(frame, "id: "...)
		frame = strconv.AppendUint(frame, uint64(ev.Sequence), 10)
		frame = append(frame, '\n')
	}
	frame = append(frame, "event: "...)
	frame = append(frame, ev.Type...)
	frame = append(frame, "\ndata: "...)
	frame = append(frame, raw...)
	frame = append(frame, '\n', '\n')
	return frame, true
}
