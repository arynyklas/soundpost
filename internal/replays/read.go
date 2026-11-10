// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"context"
	"errors"
	"io"
	"math"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/storage"
)

var errContextDone = errors.New("context done")

// Read opens an authorized, gap-aware reconstruction of one replay. A caller who
// is not authorized, whose scope does not contain the replay, or for whom the
// replay does not exist (including a deleted one) gets the identical NotFound.
// Only chunk metadata is planned up front; chunk bodies are fetched a few at a
// time and each is released only after a fresh authorization fence.
func (s *Service) Read(ctx context.Context, scope auth.Scope, replayID model.ID, window ReplayWindow) (ReplayStream, error) {
	hide := func(err error) error {
		if transient(err) {
			return err
		}
		return model.Fail(model.NotFound)
	}
	if err := s.authorizer.Revalidate(ctx, scope); err != nil {
		return nil, hide(err)
	}
	if scope.Permission() != auth.Read || replayID == (model.ID{}) || len(scope.ProjectIDs()) == 0 {
		return nil, model.Fail(model.NotFound)
	}
	var generation uint64
	if err := s.control.View(ctx, func(st model.ControlState) error {
		generation = st.DeleteGenerations[scope.OrgID().String()]
		return nil
	}); err != nil {
		return nil, err
	}
	found, err := s.collect(ctx, scope, replayID)
	if err != nil {
		return nil, hide(err)
	}
	// Authority is checked again after the scan: a grant revoked while the
	// index was read opens no stream.
	if err = s.authorizer.Revalidate(ctx, scope); err != nil {
		return nil, hide(err)
	}
	var group *group
	err = s.control.View(ctx, func(st model.ControlState) error {
		if deletionCovers(st, scope.OrgID(), found.project, model.Record{Kind: model.Replay, Payload: model.Payload{Replay: &model.ReplayChunk{Replay: replayID, Clock: model.TraceClock{Wall: found.firstWall}}}}) {
			return model.Fail(model.NotFound)
		}
		settings := st.Orgs[scope.OrgID().String()].Settings
		pins, perr := readPins(settings, found.project)
		if perr != nil {
			return perr
		}
		group, _, perr = loadGroup(settings, pins, found.project, replayID)
		return perr
	})
	if err != nil {
		// Existence and authority are already proven here, so a corrupt index is
		// reported as corrupt rather than hidden; only a deletion is NotFound.
		return nil, err
	}
	if window.To != 0 && window.To < window.From {
		return nil, model.Fail(model.Invalid)
	}
	indexed := group.checkpointHashes()
	found.resolve(indexed, group)
	steps := windowSteps(plan(found.metas, found.max, indexed), found.metas, window)
	return &stream{svc: s, scope: scope, org: scope.OrgID(), project: found.project, replay: replayID, steps: steps, metas: found.metas, generation: generation, wall: found.firstWall, buf: map[uint64]*model.ReplayChunk{}}, nil
}

// collection is the metadata of every stored chunk of one replay in one project.
type collection struct {
	project   model.ID
	metas     map[uint64]*chunkMeta
	alts      map[uint64][]chunkMeta // distinct chunks claiming an already seen sequence
	max       uint64
	firstWall model.UnixNano
	rows      int
}

const maxAlternates = 4

func metaOf(c *model.ReplayChunk) (chunkMeta, bool) {
	seq := uint64(c.Sequence)
	if seq < 1 || seq > MaxSequence {
		return chunkMeta{}, false
	}
	m := chunkMeta{seq: seq, cp: uint64(c.CheckpointSequence), previous: c.Previous, cpHash: c.Checkpoint, gap: c.Gap, session: c.Session, wall: c.Clock.Wall, clock: c.Clock, policy: c.PolicyRevision, loss: uint64(c.Loss)}
	switch err := ValidateChunk(*c); faultCode(err) {
	case "":
	case model.Unsupported:
		m.unsupported = true
	default:
		m.invalid = true
	}
	if h, err := ChunkHash(*c); err == nil {
		m.hash = h
	} else {
		m.invalid = true
	}
	return m, true
}

// scan visits every stored chunk of one replay whose clock wall time lies in
// [start, end).
func (s *Service) scan(ctx context.Context, scope auth.Scope, id model.ID, start, end model.UnixNano, visit func(project model.ID, c *model.ReplayChunk) error) error {
	it, err := s.scanner.Scan(ctx, scope, storage.ScanRequest{Projects: scope.ProjectIDs(), Signal: model.Replay, Start: start, End: end, Selectors: []storage.Matcher{{Target: storage.MatchField, Name: "replay_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: id.String()}}}})
	if err != nil {
		return err
	}
	for {
		page, nerr := it.Next(ctx)
		if errors.Is(nerr, io.EOF) {
			break
		}
		if nerr != nil {
			_ = it.Close()
			return nerr
		}
		if len(page.Values) != page.Len() || len(page.Projects) != page.Len() {
			_ = it.Close()
			return model.Fail(model.Corrupt)
		}
		for i := range page.Values {
			c := page.Values[i].Replay
			if c == nil || c.Replay != id {
				continue
			}
			if err = visit(page.Projects[i], c); err != nil {
				_ = it.Close()
				return err
			}
		}
	}
	return it.Close()
}

func (s *Service) collect(ctx context.Context, scope auth.Scope, id model.ID) (*collection, error) {
	col := &collection{metas: map[uint64]*chunkMeta{}, alts: map[uint64][]chunkMeta{}}
	err := s.scan(ctx, scope, id, math.MinInt64, math.MaxInt64, func(project model.ID, c *model.ReplayChunk) error {
		if col.rows == 0 {
			col.project = project
		} else if project != col.project {
			// The same replay ID in two projects is ambiguous, never merged.
			return model.Fail(model.NotFound)
		}
		col.rows++
		m, ok := metaOf(c)
		if !ok {
			return nil
		}
		if col.firstWall == 0 || m.wall < col.firstWall {
			col.firstWall = m.wall
		}
		col.max = max(col.max, m.seq)
		have := col.metas[m.seq]
		switch {
		case have == nil:
			col.metas[m.seq] = &m
		case have.hash == m.hash:
		case len(col.alts[m.seq]) < maxAlternates:
			col.alts[m.seq] = append(col.alts[m.seq], m)
		default:
			have.conflict = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if col.rows == 0 || len(col.metas) == 0 {
		return nil, model.Fail(model.NotFound)
	}
	return col, nil
}

// resolve settles competing chunks and foreign sessions. A competing pair is
// settled only by the immutable checkpoint index; otherwise the sequence is a
// conflict and never released.
func (c *collection) resolve(indexed map[uint64]model.Hash, g *group) {
	for seq, alts := range c.alts {
		have := c.metas[seq]
		want, pinned := indexed[seq]
		if !pinned {
			have.conflict = true
			continue
		}
		matches := 0
		for _, m := range append([]chunkMeta{*have}, alts...) {
			if m.hash == want {
				matches++
				picked := m
				c.metas[seq] = &picked
			}
		}
		if matches != 1 {
			c.metas[seq].conflict = true
		}
	}
	var session model.ID
	switch {
	case g != nil:
		session = g.Session
	default:
		lowest := uint64(math.MaxUint64)
		for seq, m := range c.metas {
			if seq < lowest && !m.invalid {
				lowest, session = seq, m.session
			}
		}
	}
	for _, m := range c.metas {
		if m.session != session {
			m.conflict = true
		}
	}
}

type stream struct {
	svc        *Service
	scope      auth.Scope
	org        model.ID
	project    model.ID
	replay     model.ID
	steps      []step
	metas      map[uint64]*chunkMeta
	generation uint64
	wall       model.UnixNano
	pos        int
	buf        map[uint64]*model.ReplayChunk
	done       bool
	closed     bool
}

func (r *stream) end() { r.done, r.buf = true, nil }

// fence is the whole release check: current authority, the org delete
// generation, and any deletion covering the replay. A denial is a typed Revoke
// (or Error when the authority itself is unreachable) and ends the stream; no
// further byte follows it.
func (r *stream) fence(ctx context.Context, seq uint64) (Event, bool) {
	if err := ctx.Err(); err != nil {
		return Event{Kind: EventError, Sequence: seq, Code: model.Cancelled}, true
	}
	if err := r.svc.authorizer.Revalidate(ctx, r.scope); err != nil {
		if transient(err) {
			return Event{Kind: EventError, Sequence: seq, Code: faultCode(err)}, true
		}
		return Event{Kind: EventRevoke, Sequence: seq, Reason: ReasonAuthorityRevoked}, true
	}
	wall := r.wall
	if m := r.metas[seq]; m != nil {
		wall = m.wall
	}
	deleted := false
	err := r.svc.control.View(ctx, func(st model.ControlState) error {
		deleted = st.DeleteGenerations[r.org.String()] != r.generation || deletionCovers(st, r.org, r.project, model.Record{Kind: model.Replay, ObservedAt: wall, Payload: model.Payload{Replay: &model.ReplayChunk{Replay: r.replay, Clock: model.TraceClock{Wall: wall}}}})
		return nil
	})
	if err != nil {
		return Event{Kind: EventError, Sequence: seq, Code: model.Unavailable}, true
	}
	if deleted {
		return Event{Kind: EventRevoke, Sequence: seq, Reason: ReasonDeleted}, true
	}
	return Event{}, false
}

func (r *stream) Next(ctx context.Context) (Event, error) {
	if r.closed {
		return Event{}, io.ErrClosedPipe
	}
	if r.done || r.pos >= len(r.steps) {
		r.end()
		return Event{}, io.EOF
	}
	st := r.steps[r.pos]
	if ev, denied := r.fence(ctx, st.seq); denied {
		r.end()
		return ev, nil
	}
	ev := Event{Kind: st.kind, Sequence: st.seq, Through: st.through, Reason: st.reason}
	if m := r.metas[st.seq]; m != nil && st.kind != EventGap {
		ev.Hash, ev.Previous, ev.CheckpointSequence, ev.Checkpoint, ev.Policy, ev.Clock, ev.Loss = m.hash, m.previous, m.cp, m.cpHash, m.policy, m.clock, m.loss
	}
	if st.kind == EventCheckpoint || st.kind == EventDelta {
		chunk, err := r.chunk(ctx, st.seq)
		if err == nil {
			// Bytes fetched while a revocation was landing are discarded.
			if denial, denied := r.fence(ctx, st.seq); denied {
				r.end()
				return denial, nil
			}
		} else {
			r.end()
			if denial, denied := r.fence(ctx, st.seq); denied {
				return denial, nil
			}
			code := faultCode(err)
			if code == "" || !transient(err) {
				code = model.Corrupt
			}
			return Event{Kind: EventError, Sequence: st.seq, Code: code}, nil
		}
		ev.Chunk = chunk
		delete(r.buf, st.seq)
	}
	r.pos++
	return ev, nil
}

// chunk returns the body of seq, refilling a bounded window of upcoming chunk
// bodies when it is not buffered. A body whose hash differs from the verified
// plan (tampered or replaced after planning) is never released.
func (r *stream) chunk(ctx context.Context, seq uint64) (*model.ReplayChunk, error) {
	if c, ok := r.buf[seq]; ok {
		return c, nil
	}
	wanted := map[uint64]model.Hash{}
	start, end := model.UnixNano(math.MaxInt64), model.UnixNano(math.MinInt64)
	for _, st := range r.steps[r.pos:] {
		if len(wanted) == ReadBatch {
			break
		}
		if st.kind == EventCheckpoint || st.kind == EventDelta {
			m := r.metas[st.seq]
			wanted[st.seq] = m.hash
			start, end = min(start, m.wall), max(end, m.wall+1)
		}
	}
	err := r.svc.scan(ctx, r.scope, r.replay, start, end, func(project model.ID, c *model.ReplayChunk) error {
		want, ok := wanted[uint64(c.Sequence)]
		if !ok || project != r.project {
			return nil
		}
		if h, herr := ChunkHash(*c); herr == nil && h == want && ValidateChunk(*c) == nil {
			cp := *c
			r.buf[uint64(c.Sequence)] = &cp
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	c, ok := r.buf[seq]
	if !ok {
		return nil, model.Fail(model.Corrupt)
	}
	return c, nil
}

func (r *stream) Close() error {
	r.closed = true
	r.buf = nil
	return nil
}
