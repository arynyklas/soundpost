// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
	"github.com/arynyklas/soundpost/internal/storage"
	"maps"
	"slices"
	"strings"
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
	// maxSweepVisit bounds the settings keys one write looks at to find expired pins.
	maxSweepVisit = 512
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

// pinKey is the Settings key of one replay's pin: one small value per replay, so recording a
// replay rewrites its own group and pin and nothing that grows with the project's live replays.
func pinKey(project, replay model.ID) string {
	return pinPrefix + project.String() + ":" + replay.String()
}

// legacyPinKey is the key of the one pin map per project that earlier builds wrote (replay ->
// pin, rewritten whole by every new replay, 16 MiB ceiling near 108k live replays). It is read
// while present and removed by the first index write of the project (migrateLegacyPins).
func legacyPinKey(project model.ID) string { return pinPrefix + project.String() }

// readLegacyPins parses the legacy pin map of the project: empty when there is none, Corrupt
// when it does not parse.
func readLegacyPins(settings map[string]json.RawMessage, project model.ID) (map[string]pin, error) {
	raw, ok := settings[legacyPinKey(project)]
	if !ok {
		return nil, nil
	}
	var pins map[string]pin
	if model.StrictJSON(raw, &pins) != nil || pins == nil {
		return nil, model.Fail(model.Corrupt)
	}
	return pins, nil
}

// readPin returns the pin of one replay. A contracted organization (model.IndexesContractedKey)
// has the replay's own key, else the legacy pin map's entry. Before the contraction (D70) both
// are kept current, and the previous release (a rolled-back voter) may have written only the
// map, so the newer of the two answers: the higher Seq, then the later deadline. A value or a
// legacy map that does not parse is Corrupt, whichever replay is asked about.
func readPin(settings map[string]json.RawMessage, project, replay model.ID) (pin, bool, error) {
	legacy, err := readLegacyPins(settings, project)
	if err != nil {
		return pin{}, false, err
	}
	var own pin
	hasOwn := false
	if raw, ok := settings[pinKey(project, replay)]; ok {
		if model.StrictJSON(raw, &own) != nil {
			return pin{}, false, model.Fail(model.Corrupt)
		}
		hasOwn = true
	}
	l, hasLegacy := legacy[replay.String()]
	_, contracted := settings[model.IndexesContractedKey]
	switch {
	case hasOwn && hasLegacy && !contracted && (l.Seq > own.Seq || l.Seq == own.Seq && l.RetainUntil > own.RetainUntil):
		return l, true, nil
	case hasOwn:
		return own, true, nil
	}
	return l, hasLegacy, nil
}

// ContractPins drops the whole-project pin maps of every project of the organization (D70): each
// entry the replay's own pin does not already carry at least as new is written to its own key, a
// pin whose group the previous release swept goes with the map, and the map is removed. It does
// not mark the organization contracted (the caller does, with the ledger index). It reports
// whether anything changed; a map that does not parse is Corrupt and nothing is changed.
func ContractPins(o *model.ControlOrg) (bool, error) {
	next := maps.Clone(o.Settings)
	changed := false
	for key := range o.Settings {
		rest, ok := strings.CutPrefix(key, pinPrefix)
		if !ok {
			continue
		}
		project, err := model.ParseID(rest)
		if err != nil {
			continue
		}
		legacy, err := readLegacyPins(o.Settings, project)
		if err != nil {
			return false, err
		}
		for replay, l := range legacy {
			id, err := model.ParseID(replay)
			if err != nil {
				continue
			}
			if raw, ok := o.Settings[pinKey(project, id)]; ok {
				var own pin
				if model.StrictJSON(raw, &own) == nil && (own.Seq > l.Seq || own.Seq == l.Seq && own.RetainUntil >= l.RetainUntil) {
					continue
				}
			}
			raw, err := json.Marshal(l)
			if err != nil {
				return false, model.Fail(model.Corrupt)
			}
			next[pinKey(project, id)] = raw
		}
		prefix := pinPrefix + project.String() + ":"
		for k := range o.Settings {
			replay, ok := strings.CutPrefix(k, prefix)
			if !ok {
				continue
			}
			id, err := model.ParseID(replay)
			if err != nil {
				continue
			}
			if _, kept := legacy[replay]; !kept {
				if _, stored := o.Settings[groupKey(project, id)]; !stored {
					delete(next, k)
				}
			}
		}
		delete(next, key)
		changed = true
	}
	o.Settings = next
	return changed, nil
}

// migrateLegacyPins moves every pin of the legacy pin map to its own key and removes the map.
// A pin that already has its own key keeps it (the newer record); an entry whose key is not a
// replay ID names nothing and is dropped.
func migrateLegacyPins(settings map[string]json.RawMessage, project model.ID) error {
	legacy, err := readLegacyPins(settings, project)
	if err != nil || legacy == nil {
		return err
	}
	for key, p := range legacy {
		id, err := model.ParseID(key)
		if err != nil {
			continue
		}
		if _, ok := settings[pinKey(project, id)]; ok {
			continue
		}
		raw, err := json.Marshal(p)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		settings[pinKey(project, id)] = raw
	}
	delete(settings, legacyPinKey(project))
	return nil
}

// loadGroup returns the verified index and its pin, nil when the replay has
// none, and Corrupt for any disagreement between the index and its pin.
func loadGroup(settings map[string]json.RawMessage, project, replay model.ID) (*group, pin, error) {
	p, pinned, err := readPin(settings, project, replay)
	if err != nil {
		return nil, pin{}, err
	}
	raw, stored := settings[groupKey(project, replay)]
	if !stored && !pinned {
		return nil, pin{}, nil
	}
	if stored != pinned {
		// Before the contraction an older release that swept a replay removed its group and its
		// map entry and left the replay's own pin behind: no group, a map without the replay.
		if !stored {
			if _, contracted := settings[model.IndexesContractedKey]; !contracted {
				if legacy, lerr := readLegacyPins(settings, project); lerr == nil && legacy != nil {
					if _, ok := legacy[replay.String()]; !ok {
						return nil, pin{}, nil
					}
				}
			}
		}
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
	g, p, err := loadGroup(o.Settings, project, chunk.Replay)
	if err != nil {
		return false, err
	}
	changed := false
	if g == nil {
		// A replay is rooted by a checkpoint: a delta (which carries no root of its
		// own) must not be the chunk that creates the group and fixes its session.
		if chunk.CheckpointSequence != chunk.Sequence {
			return false, model.Fail(model.Conflict)
		}
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
	rawPin, err := json.Marshal(pin{Seq: g.Seq, Head: g.Head, RetainUntil: retain})
	if err != nil {
		return false, model.Fail(model.Corrupt)
	}
	if o.IndexesContracted() {
		if err := migrateLegacyPins(o.Settings, project); err != nil {
			return false, err
		}
		o.Settings[pinKey(project, chunk.Replay)] = rawPin
		sweep(o.Settings, project, now, nil)
	} else if err := writeBothPins(o.Settings, project, chunk.Replay, pin{Seq: g.Seq, Head: g.Head, RetainUntil: retain}, rawPin, now); err != nil {
		return false, err
	}
	st.Orgs[org.String()] = o
	return true, nil
}

// writeBothPins is the pin write of an organization that is not contracted (D70): the replay's
// own pin and the whole-project pin map the previous release reads, which costs what a write cost
// on that release. A project that has pins of its own and no map (written before the map was
// kept) has the map built from them first.
func writeBothPins(settings map[string]json.RawMessage, project, replay model.ID, p pin, rawPin json.RawMessage, now time.Time) error {
	legacy, err := readLegacyPins(settings, project)
	if err != nil {
		return err
	}
	if legacy == nil {
		legacy = map[string]pin{}
		prefix := pinPrefix + project.String() + ":"
		for key, raw := range settings {
			if id, ok := strings.CutPrefix(key, prefix); ok {
				var own pin
				if model.StrictJSON(raw, &own) != nil {
					return model.Fail(model.Corrupt)
				}
				legacy[id] = own
			}
		}
	}
	legacy[replay.String()] = p
	settings[pinKey(project, replay)] = rawPin
	for _, gone := range sweep(settings, project, now, legacy) {
		delete(legacy, gone)
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		return model.Fail(model.Corrupt)
	}
	settings[legacyPinKey(project)] = raw
	return nil
}

// sweep forgets indexes whose whole group deadline passed long ago and returns their replay
// IDs. It looks at a bounded number of keys per write (map order is random, so every pin is
// reached over writes) and drops at most maxSweep: the cost of a write does not grow with the
// project's live replays. legacy, when not nil, is the whole-project map kept beside the pins: a
// deadline the previous release extended there keeps the replay.
func sweep(settings map[string]json.RawMessage, project model.ID, now time.Time, legacy map[string]pin) []string {
	var gone []string
	prefix := pinPrefix + project.String() + ":"
	visited := 0
	for key, raw := range settings {
		if len(gone) == maxSweep || visited == maxSweepVisit {
			return gone
		}
		visited++
		replay, ok := strings.CutPrefix(key, prefix)
		if !ok {
			continue
		}
		var p pin
		if json.Unmarshal(raw, &p) != nil {
			continue
		}
		if l, ok := legacy[replay]; ok && l.RetainUntil > p.RetainUntil {
			p.RetainUntil = l.RetainUntil
		}
		if int64(p.RetainUntil)+int64(sweepGrace) < now.UnixNano() {
			if id, err := model.ParseID(replay); err == nil {
				delete(settings, groupKey(project, id))
				delete(settings, key)
				gone = append(gone, replay)
			}
		}
	}
	return gone
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
		p, _, err := readPin(st.Orgs[c.Org.String()].Settings, c.Project, c.Record.Payload.Replay.Replay)
		if err != nil {
			return err
		}
		out = p.RetainUntil
		return nil
	})
	return out, err
}
