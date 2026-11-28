// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// This file is POST /api/v1/replays/list (docs/operations/console-api.md section 5): the recorded replays of the
// requested projects inside a window, summarised per replay ID from the stored chunks.
//
// A replay is a separate grant: the caller needs telemetry.read AND replay.read on every requested project, and a
// caller without replay.read gets the one typed not_available answer without anything being scanned. The list
// reads chunk metadata only (sequence, time, session, gap and loss markers); a chunk's nodes and events are
// never copied into the answer, the stream route stays the only reader of replay content.

// Bounds of the replay scan; reaching one makes the answer incomplete with reason scan_capped.
const (
	maxReplayListRows    = 100_000
	maxReplayListBytes   = 256 << 20
	maxReplayListReplays = 5_000
)

// Recording states of a replay in the list.
const (
	RecordingComplete = "complete"
	RecordingPartial  = "partial"
	RecordingGap      = "gap"
)

// ReplayListBody is the POST /api/v1/replays/list body; the window is required.
type ReplayListBody struct{ ListRequest }

// ReplayListItem is one replay of the list.
type ReplayListItem struct {
	ProjectID model.ID     `json:"project_id"`
	ReplayID  model.ID     `json:"replay_id"`
	SessionID *model.ID    `json:"session_id"`
	FirstAt   model.Int64  `json:"first_at"`
	LastAt    model.Int64  `json:"last_at"`
	Chunks    model.Uint64 `json:"chunks"`
	Recording string       `json:"recording"`
	Gaps      model.Uint64 `json:"gaps"`
}

type replayChunkMark struct {
	seq     uint64
	flagged bool // the chunk reports a gap or a loss itself
}

type replayAgg struct {
	project, replay model.ID
	session         model.ID
	sessionMixed    bool
	first, last     model.UnixNano
	marks           []replayChunkMark
}

func validReplayListBody(b ReplayListBody) error {
	if err := b.validate(true); err != nil {
		return err
	}
	switch b.Sort {
	case "", "last_at", "first_at":
	default:
		return invalid("sort_invalid")
	}
	return nil
}

func (a *replayAgg) key(sort string) int64 {
	if sort == "first_at" {
		return int64(a.first)
	}
	return int64(a.last)
}

// summary derives the chunk count, the gap count and the recording state from the sequences seen: a hole
// between two stored sequences is a gap, a chunk that reports a gap or a loss is a gap, and a series that does
// not start at sequence 1 inside the window is partial (its beginning is outside what was read).
func (a *replayAgg) summary() (chunks, gaps uint64, recording string) {
	slices.SortFunc(a.marks, func(x, y replayChunkMark) int {
		switch {
		case x.seq < y.seq:
			return -1
		case x.seq > y.seq:
			return 1
		}
		return 0
	})
	var prev uint64
	for i := 0; i < len(a.marks); i++ {
		m := a.marks[i]
		for i+1 < len(a.marks) && a.marks[i+1].seq == m.seq { // a redelivered chunk counts once
			i++
			m.flagged = m.flagged || a.marks[i].flagged
		}
		switch {
		case chunks > 0 && m.seq != prev+1:
			gaps++
		case m.flagged:
			gaps++
		}
		chunks++
		prev = m.seq
	}
	switch {
	case gaps > 0:
		recording = RecordingGap
	case len(a.marks) > 0 && a.marks[0].seq != 1:
		recording = RecordingPartial
	default:
		recording = RecordingComplete
	}
	return chunks, gaps, recording
}

// Replays answers one replay list under the caller's own authority.
func (l *ConsoleLists) Replays(ctx context.Context, authority *auth.Service, credential auth.Credential, body ReplayListBody) (any, []auth.Scope, error) {
	if err := validReplayListBody(body); err != nil {
		return nil, nil, err
	}
	scope, err := authority.Authorize(ctx, credential, body.Org, body.Projects, auth.Read)
	if err != nil {
		return nil, nil, err
	}
	if err = body.allowsAll(scope); err != nil {
		return nil, nil, err
	}
	scopes := []auth.Scope{scope}
	gate, err := authority.Authorize(ctx, credential, body.Org, body.Projects, ReplayRead)
	if err != nil && !faultIs(err, model.NotFound) {
		return nil, nil, err
	}
	if err != nil || body.allowsAll(gate) != nil {
		// Nothing is probed: the answer is the same whatever exists.
		return newConsoleList[ReplayListItem](body.ListRequest, StateNotAvailable, ReasonGrantRequired, "replays"), scopes, nil
	}
	scopes = append(scopes, gate)
	if l == nil || l.cfg.Scanner == nil {
		return newConsoleList[ReplayListItem](body.ListRequest, StateNotAvailable, ReasonListSourceNotWired, "replays"), scopes, nil
	}
	digest, err := listDigest("replays", withoutPaging(body.ListRequest))
	if err != nil {
		return nil, nil, err
	}
	var after *listPos
	if body.Cursor != "" {
		after = new(listPos)
		if err = openListCursor(ctx, l.cfg.Tickets, scope, "replays", digest, body.Cursor, after); err != nil {
			return nil, nil, err
		}
	}
	aggs, partial, capped, err := l.scanReplays(ctx, scope, body)
	if err != nil {
		return nil, nil, err
	}
	q := strings.ToLower(strings.TrimSpace(body.Query))
	if q != "" {
		aggs = slices.DeleteFunc(aggs, func(a *replayAgg) bool { return !replayMatches(a, q) })
	}
	slices.SortFunc(aggs, func(a, b *replayAgg) int {
		switch {
		case listLess(a.key(body.Sort), a.project.String(), a.replay.String(), b.key(body.Sort), b.project.String(), b.replay.String()):
			return -1
		case listLess(b.key(body.Sort), b.project.String(), b.replay.String(), a.key(body.Sort), a.project.String(), a.replay.String()):
			return 1
		}
		return 0
	})
	start := 0
	if after != nil {
		start = slices.IndexFunc(aggs, func(a *replayAgg) bool { return after.before(a.key(body.Sort), a.project.String(), a.replay.String()) })
		if start < 0 {
			start = len(aggs)
		}
	}
	out := newConsoleList[ReplayListItem](body.ListRequest, StateReady, "", "replays")
	end := min(start+body.pageLimit(), len(aggs))
	for _, a := range aggs[start:end] {
		chunks, gaps, recording := a.summary()
		item := ReplayListItem{ProjectID: a.project, ReplayID: a.replay, FirstAt: model.Int64(a.first), LastAt: model.Int64(a.last), Chunks: model.Uint64(chunks), Recording: recording, Gaps: model.Uint64(gaps)}
		if !a.sessionMixed {
			item.SessionID = new(a.session)
		}
		out.Items = append(out.Items, item)
	}
	if out.More = end < len(aggs); out.More {
		last := aggs[end-1]
		if out.NextCursor, err = issueListCursor(ctx, l.cfg.Tickets, scope, "replays", digest, listPos{Key: last.key(body.Sort), Project: last.project.String(), ID: last.replay.String()}); err != nil {
			return nil, nil, err
		}
	}
	switch {
	case capped:
		out.State, out.Reason = StateIncomplete, ReasonListScanCapped
	case partial:
		out.State, out.Reason = StateIncomplete, ReasonShardsMissing
	case len(out.Items) == 0 && !out.More:
		out.State, out.Reason = StateEmpty, ReasonListNoItems
	}
	out.Sections = []ViewSection{{Name: "replays", State: out.State, Reason: out.Reason}}
	return out, scopes, nil
}

// withoutPaging is the request identity a cursor binds: everything but the cursor and the page size.
func withoutPaging(r ListRequest) ListRequest {
	r.Cursor, r.Limit = "", 0
	return r
}

func replayMatches(a *replayAgg, q string) bool {
	if !hexPrefix(q) {
		return false
	}
	return strings.HasPrefix(a.replay.String(), q) || !a.sessionMixed && strings.HasPrefix(a.session.String(), q)
}

// scanReplays reads the chunk metadata of the window and folds it per replay. partial says a shard did not
// answer; capped says a bound was reached before the window was read through.
func (l *ConsoleLists) scanReplays(ctx context.Context, scope auth.Scope, body ReplayListBody) (_ []*replayAgg, partial, capped bool, err error) {
	rows, err := l.cfg.Scanner.Scan(ctx, scope, storage.ScanRequest{
		Projects: body.Projects, Signal: model.Replay, Start: body.Window.Start, End: body.Window.End,
		Projection: []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldReplay},
		Fence:      storage.ReadFence{AllowPartial: true},
	})
	if err != nil {
		return nil, false, false, err
	}
	if rows == nil {
		return nil, false, false, model.Fail(model.Corrupt)
	}
	defer rows.Close()
	type key struct{ project, replay model.ID }
	byKey := map[key]*replayAgg{}
	var order []*replayAgg
	scanned, bytes := 0, uint64(0)
	for {
		page, err := rows.Next(ctx)
		if errors.Is(err, io.EOF) {
			return order, partial, capped, nil
		}
		if err != nil {
			return nil, false, false, err
		}
		partial = partial || page.Partial
		if len(page.Values) != page.Len() || len(page.Projects) != page.Len() {
			return nil, false, false, model.Fail(model.Corrupt)
		}
		if bytes += page.Bytes; bytes > maxReplayListBytes {
			return order, partial, true, nil
		}
		for i, v := range page.Values {
			c := v.Replay
			if c == nil {
				return nil, false, false, model.Fail(model.Corrupt)
			}
			if scanned++; scanned > maxReplayListRows {
				return order, partial, true, nil
			}
			k := key{page.Projects[i], c.Replay}
			a := byKey[k]
			if a == nil {
				if len(order) >= maxReplayListReplays {
					return order, partial, true, nil
				}
				a = &replayAgg{project: k.project, replay: k.replay, session: c.Session, first: c.Clock.Wall, last: c.Clock.Wall}
				byKey[k] = a
				order = append(order, a)
			}
			a.first, a.last = min(a.first, c.Clock.Wall), max(a.last, c.Clock.Wall)
			a.sessionMixed = a.sessionMixed || a.session != c.Session
			a.marks = append(a.marks, replayChunkMark{seq: uint64(c.Sequence), flagged: c.Gap || c.Loss > 0})
		}
	}
}
