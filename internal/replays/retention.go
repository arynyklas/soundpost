// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"context"
	"encoding/json"
	"slices"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"soundpost/internal/storage"
	"time"
)

const (
	groupPrefix  = model.ReplayIndexKeyPrefix
	pinPrefix    = model.ReplayPinKeyPrefix
	groupVersion = 1
	// retainCoalesce is the slack by which a replay group deadline may trail the
	// deadline of its newest chunk. It bounds control writes to one per minute
	// per replay between checkpoints; chunks are never erased before their own
	// receipt deadline.
	retainCoalesce = time.Minute
	// sweepGrace is how long an index outlives its group deadline.
	sweepGrace = 24 * time.Hour
	maxSweep   = 32
)

type checkpointEntry struct {
	Sequence uint64
	Hash     model.Hash
}

// group is the immutable checkpoint index of one replay: its root identity
// (project, replay, session) and every checkpoint ever recorded. Entries are
// only ever added; Head digests the whole record and the project pin freezes
// (Seq, Head), so an edited, removed or rolled-back index is detected on load.
type group struct {
	Version     int
	Project     model.ID
	Replay      model.ID
	Session     model.ID
	Seq         uint64
	Checkpoints []checkpointEntry
	Head        model.Hash
}

// pin carries the retention group deadline: a replay lives and dies with its
// root, so no chunk is released for erasure before the latest chunk deadline.
type pin struct {
	Seq         uint64
	Head        model.Hash
	RetainUntil model.UnixNano
}

func (g group) digest() model.Hash {
	g.Head = model.Hash{}
	raw, err := model.CanonicalJSON(g)
	if err != nil {
		return model.Hash{}
	}
	return model.HashCanonical(raw)
}

func groupKey(project, replay model.ID) string {
	return groupPrefix + project.String() + ":" + replay.String()
}
func pinKey(project model.ID) string { return pinPrefix + project.String() }

func readPins(settings map[string]json.RawMessage, project model.ID) (map[string]pin, error) {
	raw, ok := settings[pinKey(project)]
	if !ok {
		return map[string]pin{}, nil
	}
	var pins map[string]pin
	if model.StrictJSON(raw, &pins) != nil || pins == nil {
		return nil, model.Fail(model.Corrupt)
	}
	return pins, nil
}

// loadGroup returns the verified index and its pin, nil when the replay has
// none, and Corrupt for any disagreement between the index and its pin.
func loadGroup(settings map[string]json.RawMessage, pins map[string]pin, project, replay model.ID) (*group, pin, error) {
	p, pinned := pins[replay.String()]
	raw, stored := settings[groupKey(project, replay)]
	if !stored && !pinned {
		return nil, pin{}, nil
	}
	if stored != pinned {
		return nil, pin{}, model.Fail(model.Corrupt)
	}
	var g group
	if model.StrictJSON(raw, &g) != nil || g.Version != groupVersion || g.Project != project || g.Replay != replay || len(g.Checkpoints) > MaxCheckpoints || g.Head != g.digest() || g.Seq != p.Seq || g.Head != p.Head {
		return nil, pin{}, model.Fail(model.Corrupt)
	}
	for i, c := range g.Checkpoints {
		if c.Sequence < 1 || c.Sequence > MaxSequence || i > 0 && c.Sequence <= g.Checkpoints[i-1].Sequence {
			return nil, pin{}, model.Fail(model.Corrupt)
		}
	}
	return &g, p, nil
}

// checkpointHashes is the pinned checkpoint map of an index (nil when none).
func (g *group) checkpointHashes() map[uint64]model.Hash {
	if g == nil {
		return nil
	}
	out := make(map[uint64]model.Hash, len(g.Checkpoints))
	for _, c := range g.Checkpoints {
		out[c.Sequence] = c.Hash
	}
	return out
}

// Record is RecordScope for a caller that holds a source grant.
func (s *Service) Record(ctx context.Context, grant policy.SourceGrant, project model.ID, chunk model.ReplayChunk, retainUntil model.UnixNano) error {
	scope, err := grant.Scope()
	if err != nil {
		return err
	}
	return s.RecordScope(ctx, scope, project, chunk, retainUntil)
}

// RecordScope is the post-admission index step: after a validated chunk is
// durably appended, admission records it here. A checkpoint is added to the
// immutable index (a second, different chunk at a recorded checkpoint sequence,
// or a foreign session for the replay root, is a Conflict and changes nothing),
// and the group retention deadline moves to the latest chunk deadline.
// Idempotent, and a call that would change nothing writes nothing: no control
// revision is spent and nothing is replicated, so the minute of retention
// coalescing really bounds the control writes of a replay.
func (s *Service) RecordScope(ctx context.Context, scope auth.Scope, project model.ID, chunk model.ReplayChunk, retainUntil model.UnixNano) error {
	if err := s.indexable(ctx, scope, project, chunk); err != nil {
		return err
	}
	now := s.now()
	if int64(retainUntil) <= now.UnixNano() {
		return model.Fail(model.Invalid)
	}
	hash, err := checkpointHash(chunk)
	if err != nil {
		return err
	}
	org := scope.OrgID()
	var write bool
	if err = s.control.View(ctx, func(st model.ControlState) error {
		var err error
		write, err = applyIndex(&st, org, project, chunk, hash, retainUntil, now)
		return err
	}); err != nil || !write {
		return err
	}
	update := s.control.Update
	if u, ok := s.control.(replayIndexUpdater); ok {
		update = u.UpdateReplayIndex
	}
	return update(ctx, func(st *model.ControlState) error {
		_, err := applyIndex(st, org, project, chunk, hash, retainUntil, now)
		return err
	})
}

// replayIndexUpdater is implemented by *control.Store: an update that does not move the control
// AuthorityRevision. The replay index entry is not authority state, and without this a replayed
// chunk would move AuthorityRevision like any unclassified writer and starve a deletion Begin. A
// ReferenceStore without it (a test double) falls back to Update, which always bumps.
type replayIndexUpdater interface {
	UpdateReplayIndex(context.Context, func(*model.ControlState) error) error
}

// CheckIndex decides from the index alone whether RecordScope would refuse the
// chunk as a Conflict (a foreign session for the replay root, or a different
// chunk at a recorded checkpoint sequence) or TooLarge (the index is full). It
// reads the control state under the scope's own organization and writes nothing,
// so admission can refuse such a chunk before it is stored.
func (s *Service) CheckIndex(ctx context.Context, scope auth.Scope, project model.ID, chunk model.ReplayChunk) error {
	if err := s.indexable(ctx, scope, project, chunk); err != nil {
		return err
	}
	hash, err := checkpointHash(chunk)
	if err != nil {
		return err
	}
	now := s.now()
	return s.control.View(ctx, func(st model.ControlState) error {
		_, err := applyIndex(&st, scope.OrgID(), project, chunk, hash, 0, now)
		return err
	})
}

// indexable is what both index entry points check before they touch control: the
// closed format, the project against the scope, and the scope against current
// grants (so a revoked scope learns nothing from the index).
func (s *Service) indexable(ctx context.Context, scope auth.Scope, project model.ID, chunk model.ReplayChunk) error {
	if err := ValidateChunk(chunk); err != nil {
		return err
	}
	if !scope.AllowsProject(project) {
		return model.Fail(model.Forbidden)
	}
	return s.authorizer.Revalidate(ctx, scope)
}

// checkpointHash is the hash the index pins for a checkpoint chunk; a delta is
// not indexed, so it is never hashed here.
func checkpointHash(chunk model.ReplayChunk) (model.Hash, error) {
	if chunk.CheckpointSequence != chunk.Sequence {
		return model.Hash{}, nil
	}
	return ChunkHash(chunk)
}

// applyIndex applies one chunk to the replay index held in st and reports
// whether the stored index or pin changed (false: nothing to write). It mutates
// st only when it reports true.
func applyIndex(st *model.ControlState, org, project model.ID, chunk model.ReplayChunk, hash model.Hash, retainUntil model.UnixNano, now time.Time) (bool, error) {
	o, ok := st.Orgs[org.String()]
	if !ok {
		return false, model.Fail(model.NotFound)
	}
	if o.Settings == nil {
		o.Settings = map[string]json.RawMessage{}
	}
	pins, err := readPins(o.Settings, project)
	if err != nil {
		return false, err
	}
	g, p, err := loadGroup(o.Settings, pins, project, chunk.Replay)
	if err != nil {
		return false, err
	}
	changed := false
	if g == nil {
		g = &group{Version: groupVersion, Project: project, Replay: chunk.Replay, Session: chunk.Session}
		changed = true
	}
	if g.Session != chunk.Session {
		return false, model.Fail(model.Conflict)
	}
	if chunk.CheckpointSequence == chunk.Sequence {
		seq := uint64(chunk.Sequence)
		i, found := slices.BinarySearchFunc(g.Checkpoints, seq, func(e checkpointEntry, v uint64) int {
			switch {
			case e.Sequence < v:
				return -1
			case e.Sequence > v:
				return 1
			}
			return 0
		})
		switch {
		case found && g.Checkpoints[i].Hash != hash:
			return false, model.Fail(model.Conflict)
		case !found:
			if len(g.Checkpoints) >= MaxCheckpoints {
				return false, model.Fail(model.TooLarge)
			}
			g.Checkpoints = slices.Insert(g.Checkpoints, i, checkpointEntry{Sequence: seq, Hash: hash})
			changed = true
		}
	}
	retain := max(p.RetainUntil, retainUntil)
	if !changed && int64(retain)-int64(p.RetainUntil) <= int64(retainCoalesce) {
		return false, nil
	}
	if changed {
		g.Seq++
		g.Head = g.digest()
		raw, err := json.Marshal(g)
		if err != nil {
			return false, model.Fail(model.Corrupt)
		}
		o.Settings[groupKey(project, chunk.Replay)] = raw
	}
	pins[chunk.Replay.String()] = pin{Seq: g.Seq, Head: g.Head, RetainUntil: retain}
	sweep(o.Settings, pins, project, now)
	raw, err := json.Marshal(pins)
	if err != nil {
		return false, model.Fail(model.Corrupt)
	}
	o.Settings[pinKey(project)] = raw
	st.Orgs[org.String()] = o
	return true, nil
}

// sweep forgets indexes whose whole group deadline passed long ago.
func sweep(settings map[string]json.RawMessage, pins map[string]pin, project model.ID, now time.Time) {
	removed := 0
	for key, p := range pins {
		if removed == maxSweep {
			return
		}
		if int64(p.RetainUntil)+int64(sweepGrace) < now.UnixNano() {
			if id, err := model.ParseID(key); err == nil {
				delete(settings, groupKey(project, id))
			}
			delete(pins, key)
			removed++
		}
	}
}

// deletionCovers reports whether a live deletion saga hides the record.
// Deletion takes precedence over every retention and reference rule.
func deletionCovers(st model.ControlState, org, project model.ID, r model.Record) bool {
	if _, retired := st.RetiredOrgs[org.String()]; retired {
		return true
	}
	for _, op := range st.Deletions {
		if op.Phase != model.DeletePhaseHeld && op.Predicate.CoversRecord(org, project, r) {
			return true
		}
	}
	return false
}

// LatestReference implements retention.References for replay chunks: the latest
// deadline of the whole replay group (the group lives and dies with its root),
// zero when the chunk is unindexed or under deletion. A pin map that does not
// parse is an error, so the expiry pass fails closed.
func (s *Service) LatestReference(ctx context.Context, c storage.EraseCandidate) (model.UnixNano, error) {
	if c.Kind != model.Replay || c.Record == nil || c.Record.Payload.Replay == nil {
		return 0, nil
	}
	var out model.UnixNano
	err := s.control.View(ctx, func(st model.ControlState) error {
		if deletionCovers(st, c.Org, c.Project, *c.Record) {
			return nil
		}
		pins, err := readPins(st.Orgs[c.Org.String()].Settings, c.Project)
		if err != nil {
			return err
		}
		out = pins[c.Record.Payload.Replay.Replay.String()].RetainUntil
		return nil
	})
	return out, err
}
