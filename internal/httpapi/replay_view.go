// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/replays"
)

// This file is the C11 replay read: the committed replays.Service stream of one
// replay, released to the browser as NDJSON.
//
// The scope is derived from the caller's credential before the replay service
// is reached; a wrong organization, a project the caller does not hold and an
// unknown replay are the same not-found. A replay service that is not wired is
// an explicit not_available line, never an empty replay. Delivery is bounded
// (events, bytes, wall time) and revalidating: the service fences every event
// itself, and this handler fences once more immediately before every chunk it
// writes, so a revocation that lands between the two ends the response with the
// typed revoke line and no further chunk. Nothing of a service error text is
// ever written: only closed codes.

// ReplayRead is the separate grant a replay read needs in addition to
// telemetry.read (the committed replay service reads under a telemetry.read
// scope, so this handler enforces the second grant itself).
const ReplayRead auth.Permission = "replay.read"

const (
	ReasonReplayServiceNotWired = "replay_service_not_wired"
	// MaxReplayStreamEvents and MaxReplayStreamBytes bound one response; a
	// longer replay ends with a truncated line naming the next sequence.
	MaxReplayStreamEvents = 4096
	MaxReplayStreamBytes  = 16 << 20
	// ReplayStreamDeadline bounds the wall time of one response.
	ReplayStreamDeadline = 2 * time.Minute
	replayWriteDeadline  = 30 * time.Second
)

// ReplayReader is the narrow consumer-owned seam over replays.Service.Read.
type ReplayReader interface {
	Read(ctx context.Context, scope auth.Scope, replay model.ID, window replays.ReplayWindow) (replays.ReplayStream, error)
}

// Replays is the handler behind POST /api/v1/replays/stream. The reader may be nil.
type Replays struct {
	reader ReplayReader
	events int
	bytes  int
}

// NewReplays binds the optional replay reader with the default bounds.
func NewReplays(reader ReplayReader) *Replays {
	return &Replays{reader: reader, events: MaxReplayStreamEvents, bytes: MaxReplayStreamBytes}
}

// WithLimits narrows the per-response event and byte bounds; a bound may only
// shrink, never exceed the package maximum.
func (r *Replays) WithLimits(events, bytes int) *Replays {
	out := *r
	if events > 0 && events <= MaxReplayStreamEvents {
		out.events = events
	}
	if bytes > 0 && bytes <= MaxReplayStreamBytes {
		out.bytes = bytes
	}
	return &out
}

// ReplayBody is the POST /api/v1/replays/stream body. From and To are inclusive
// chunk sequences (zero: the start / the end of the replay).
type ReplayBody struct {
	ScopeFields
	Project model.ID     `json:"project"`
	Replay  model.ID     `json:"replay"`
	From    model.Uint64 `json:"from,omitempty"`
	To      model.Uint64 `json:"to,omitempty"`
	// Probe revalidates scope, both grants, existence and deletion and answers
	// open then end: no chunk body is read or released. A page that holds a
	// replay uses it to learn promptly that its authority ended.
	Probe bool `json:"probe,omitempty"`
}

// ReplayLine is one NDJSON line. Types: open, checkpoint, delta, gap,
// unsupported, revoke, error, truncated, end, not_available. Chunk is present
// only on checkpoint and delta; revoke, error, truncated and end finish the
// stream and nothing follows them.
type ReplayLine struct {
	Type     string             `json:"type"`
	Org      *model.ID          `json:"org,omitempty"`
	Project  *model.ID          `json:"project,omitempty"`
	Replay   *model.ID          `json:"replay,omitempty"`
	State    ViewState          `json:"state,omitempty"`
	Sequence *model.Uint64      `json:"sequence,omitempty"`
	Through  *model.Uint64      `json:"through,omitempty"`
	Hash     *model.Hash        `json:"hash,omitempty"`
	Policy   *model.Revision    `json:"policy_revision,omitempty"`
	Loss     *model.Uint64      `json:"loss,omitempty"`
	Reason   string             `json:"reason,omitempty"`
	Code     string             `json:"code,omitempty"`
	Next     *model.Uint64      `json:"next_sequence,omitempty"`
	Chunk    *model.ReplayChunk `json:"chunk,omitempty"`
}

func faultCodeOf(err error) model.Code {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return model.Unavailable
}

// codeLine is the closed error line: only a fault code, never error text.
func codeLine(code model.Code, seq uint64) ReplayLine {
	switch code {
	case model.Unavailable, model.Timeout, model.Cancelled, model.Corrupt:
	default:
		code = model.Unavailable
	}
	s := model.Uint64(seq)
	return ReplayLine{Type: "error", Code: string(code), Sequence: &s}
}

func lineOf(ev replays.Event) ReplayLine {
	seq := model.Uint64(ev.Sequence)
	l := ReplayLine{Type: string(ev.Kind), Sequence: &seq, Reason: ev.Reason}
	switch ev.Kind {
	case replays.EventCheckpoint, replays.EventDelta:
		policy, loss, hash := ev.Policy, model.Uint64(ev.Loss), ev.Hash
		l.Policy, l.Loss, l.Hash, l.Chunk = &policy, &loss, &hash, ev.Chunk
	case replays.EventGap, replays.EventUnsupported:
		through := model.Uint64(ev.Through)
		l.Through = &through
	case replays.EventError:
		return codeLine(ev.Code, ev.Sequence)
	}
	return l
}

var errReplayEncode = errors.New("replay line not encodable")

type replayWriter struct {
	w       http.ResponseWriter
	rc      *http.ResponseController
	written int
	limit   int
}

// write sends one line and flushes it. ok is false when the line does not fit
// the byte bound (nothing was written) or the client is gone.
func (rw *replayWriter) write(l ReplayLine, force bool) (fits bool, err error) {
	raw, err := json.Marshal(l)
	if err != nil {
		return false, errReplayEncode
	}
	raw = append(raw, '\n')
	if !force && rw.written+len(raw) > rw.limit {
		return false, nil
	}
	_ = rw.rc.SetWriteDeadline(time.Now().Add(replayWriteDeadline))
	if _, err = rw.w.Write(raw); err != nil {
		return false, err
	}
	rw.written += len(raw)
	return true, rw.rc.Flush()
}

// Stream opens and releases one replay under the caller's own authority.
func (h *Replays) Stream(w http.ResponseWriter, r *http.Request, authority *auth.Service, credential auth.Credential, body ReplayBody) error {
	if h == nil {
		h = NewReplays(nil)
	}
	if body.Project == (model.ID{}) || body.Replay == (model.ID{}) || body.To != 0 && body.To < body.From {
		return invalid("replay_request_invalid")
	}
	if body.Elevation != nil {
		return model.Fail(model.Forbidden) // an elevated read cannot carry the separate replay.read grant
	}
	scope, err := queryScope(r.Context(), authority, credential, body.ScopeFields, []model.ID{body.Project}, nil)
	if err != nil {
		return err
	}
	if !scope.AllowsProject(body.Project) {
		return model.Fail(model.NotFound)
	}
	gate, err := authority.Authorize(r.Context(), credential, body.Org, []model.ID{body.Project}, ReplayRead)
	if err != nil {
		return err
	}
	if !gate.AllowsProject(body.Project) {
		return model.Fail(model.NotFound)
	}
	var stream replays.ReplayStream
	if h.reader != nil {
		if stream, err = h.reader.Read(r.Context(), scope, body.Replay, replays.ReplayWindow{From: uint64(body.From), To: uint64(body.To)}); err != nil {
			return err
		}
		defer stream.Close()
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	rw := &replayWriter{w: w, rc: http.NewResponseController(w), limit: h.bytes}
	if stream == nil {
		_, _ = rw.write(ReplayLine{Type: "not_available", State: StateNotAvailable, Reason: ReasonReplayServiceNotWired}, true)
		return nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), ReplayStreamDeadline)
	defer cancel()
	org, project, replay := scope.OrgID(), body.Project, body.Replay
	if _, err = rw.write(ReplayLine{Type: "open", Org: &org, Project: &project, Replay: &replay, State: StateReady}, true); err != nil {
		return nil
	}
	if body.Probe {
		_, _ = rw.write(ReplayLine{Type: "end"}, true)
		return nil
	}
	var last uint64
	for count := 0; ; count++ {
		ev, nerr := stream.Next(ctx)
		if errors.Is(nerr, io.EOF) {
			_, _ = rw.write(ReplayLine{Type: "end"}, true)
			return nil
		}
		if nerr != nil {
			_, _ = rw.write(codeLine(faultCodeOf(nerr), last+1), true)
			return nil
		}
		if count >= h.events {
			next := model.Uint64(ev.Sequence)
			_, _ = rw.write(ReplayLine{Type: "truncated", Next: &next}, true)
			return nil
		}
		line := lineOf(ev)
		if ev.Kind == replays.EventCheckpoint || ev.Kind == replays.EventDelta {
			if ferr := revalidateBoth(ctx, authority, scope, gate); ferr != nil {
				seq := model.Uint64(ev.Sequence)
				switch faultCodeOf(ferr) {
				case model.Unavailable, model.Timeout, model.Cancelled:
					line = codeLine(faultCodeOf(ferr), ev.Sequence)
				default:
					line = ReplayLine{Type: "revoke", Sequence: &seq, Reason: replays.ReasonAuthorityRevoked}
				}
				_, _ = rw.write(line, true)
				return nil
			}
		}
		fits, werr := rw.write(line, false)
		if errors.Is(werr, errReplayEncode) {
			// A chunk the wire cannot carry is corrupt data: a closed error line, never silence.
			_, _ = rw.write(codeLine(model.Corrupt, ev.Sequence), true)
			return nil
		}
		if werr != nil {
			return nil // the client left; the deferred Close stops reading
		}
		if !fits {
			next := model.Uint64(ev.Sequence)
			_, _ = rw.write(ReplayLine{Type: "truncated", Next: &next}, true)
			return nil
		}
		switch ev.Kind {
		case replays.EventRevoke, replays.EventError:
			return nil
		}
		last = max(ev.Sequence, ev.Through)
	}
}

// RegisterReplayRoutes mounts the replay stream. The route needs the CSRF
// binding of artifactCredential for a session caller and derives its scope from
// the caller's own credential; no body field names another principal's scope.
//
//	POST /api/v1/replays/stream  ReplayBody -> application/x-ndjson of ReplayLine
func RegisterReplayRoutes(mux *http.ServeMux, authority *auth.Service, h *Replays) {
	mux.HandleFunc("POST /api/v1/replays/stream", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body ReplayBody
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		if err = h.Stream(w, r, authority, credential, body); err != nil {
			queryReply(w, nil, err)
		}
	})
}

// revalidateBoth fences the telemetry.read scope and the replay.read grant.
func revalidateBoth(ctx context.Context, authority *auth.Service, scope, gate auth.Scope) error {
	if err := authority.Revalidate(ctx, scope); err != nil {
		return err
	}
	return authority.Revalidate(ctx, gate)
}
