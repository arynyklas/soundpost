// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"bytes"
	"context"
	"io"
	"maps"
	"math"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/retention"
	"github.com/arynyklas/soundpost/internal/storage"
)

// Source-map retention of retained profiles (09.04-W3).
//
// A profile chunk names the artifacts that resolve its frames (ProfileFrame.Artifact, the
// canonical artifact ID). The profile producer keeps those maps through
// artifacts.Lifecycle.HoldProfiles, a ledger entry of kind profile per (profile, map) that lasts
// until the retention deadline of the profile signal, so a retained profile never outlives the
// map it can be symbolicated with. Like the issue producer it runs under the system principal
// (issues.write, read), which cannot hold artifacts.write.
//
// Progress is a per-process, per-project checkpoint per data group: a restart or a change of
// leader rescans the project's retained profiles once. That is safe because a hold is
// idempotent (HoldProfiles extends nothing already held and writes nothing for a repeat); the
// checkpoint only avoids the cost.
//
// Bounds, all explicit: one pass reads at most profileScanBytes (a project whose retained
// profiles exceed it is refused as TooLarge, as the issue producer refuses oversized error
// evidence), applies at most profileProduceRows records, and a hold that the ledger cannot take
// (a published map of the project required; a ledger that already holds refledger.MaxEntries
// usages) is skipped, never an error.

const (
	profileScanBytes   = 64 << 20
	profileProduceRows = 2048
)

// ProfileMapProducer keeps the source maps that retained profiles name.
func (a *App) ProfileMapProducer() Producer {
	return &profileMapProducer{app: a, done: map[profileProjectKey]map[model.ID]model.Uint64{}}
}

type profileProjectKey struct{ org, project model.ID }

type profileMapProducer struct {
	app  *App
	mu   sync.Mutex
	done map[profileProjectKey]map[model.ID]model.Uint64 // highest fully held index per data group
}

type profileRow struct {
	group   model.ID
	index   model.Uint64
	profile model.ID
	roots   []model.ID
}

// profileMaps lists the distinct artifact IDs the frames of one chunk name, in first-seen
// order, at most refledger.MaxHolderRoots.
func profileMaps(c model.ProfileChunk) []model.ID {
	var out []model.ID
	for _, f := range c.Frames {
		if f.Artifact == "" || len(out) >= refledger.MaxHolderRoots {
			continue
		}
		id, err := model.ParseID(f.Artifact)
		if err != nil || id == (model.ID{}) || slices.Contains(out, id) {
			continue
		}
		out = append(out, id)
	}
	return out
}

func (p *profileMapProducer) checkpoints(key profileProjectKey) map[model.ID]model.Uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.done[key])
}

func (p *profileMapProducer) advance(key profileProjectKey, group model.ID, index model.Uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done[key] == nil {
		p.done[key] = map[model.ID]model.Uint64{}
	}
	p.done[key][group] = max(p.done[key][group], index)
}

func (p *profileMapProducer) Produce(ctx context.Context, scopes ProducerScopes, lease replica.FenceToken) (int, error) {
	if err := p.app.leaseGate(ctx, lease); err != nil {
		return 0, err
	}
	life := p.app.ArtifactLifecycle
	if life == nil {
		return 0, model.Fail(model.Unavailable)
	}
	read, err := scopes.Scope(ctx, auth.Read)
	if err != nil {
		return 0, err
	}
	write, err := scopes.Scope(ctx, auth.IssuesWrite)
	if err != nil {
		return 0, err
	}
	org, project := scopes.Org(), scopes.Project()
	key := profileProjectKey{org, project}
	now := model.UnixNano(life.Now().UnixNano()) // the clock every deadline in the ledger is on
	var days uint32
	if err = p.app.Control.ViewCore(ctx, func(st model.ControlState) error {
		days = retention.Resolve(st, org, &project, now).DaysFor(model.Profile, false)
		return nil
	}); err != nil || days == 0 {
		return 0, err
	}
	until := now + model.UnixNano(time.Duration(days)*24*time.Hour)
	rows, err := p.scan(ctx, read, key)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if c := bytes.Compare(rows[i].group[:], rows[j].group[:]); c != 0 {
			return c < 0
		}
		return rows[i].index < rows[j].index
	})
	rows = takeWholeCursors(rows)

	// One hold per profile with the union of the maps its chunks name.
	byProfile := map[model.ID]*artifacts.ProfileHold{}
	var order []model.ID
	for _, r := range rows {
		if len(r.roots) == 0 {
			continue
		}
		h := byProfile[r.profile]
		if h == nil {
			h = &artifacts.ProfileHold{Profile: r.profile, Until: until}
			byProfile[r.profile] = h
			order = append(order, r.profile)
		}
		for _, root := range r.roots {
			if len(h.Roots) < refledger.MaxHolderRoots && !slices.Contains(h.Roots, root) {
				h.Roots = append(h.Roots, root)
			}
		}
	}
	slices.SortFunc(order, func(a, b model.ID) int { return bytes.Compare(a[:], b[:]) })
	var batch []artifacts.ProfileHold
	distinct := map[model.ID]bool{}
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := p.app.leaseGate(ctx, lease); err != nil {
			return err
		}
		if _, err := life.HoldProfiles(ctx, write, batch); err != nil {
			return err
		}
		batch, distinct = nil, map[model.ID]bool{}
		return nil
	}
	for _, id := range order {
		h := *byProfile[id]
		fresh := 0
		for _, r := range h.Roots {
			if !distinct[r] {
				fresh++
			}
		}
		if len(distinct)+fresh > artifacts.MaxHoldRoots || len(batch) >= artifacts.MaxHoldProfiles {
			if err := flush(); err != nil {
				return 0, err
			}
		}
		batch = append(batch, h)
		for _, r := range h.Roots {
			distinct[r] = true
		}
	}
	if err := flush(); err != nil {
		return 0, err
	}
	// Every record taken is held (or has no map): the checkpoint moves only now, so a failed
	// hold leaves the records for the next pass.
	for _, r := range rows {
		p.advance(key, r.group, r.index)
	}
	return len(byProfile), nil
}

// takeWholeCursors returns the leading rows (sorted by group, then index) of up to
// profileProduceRows records, never splitting the records of one cursor.
func takeWholeCursors(rows []profileRow) []profileRow {
	end := 0
	for end < len(rows) && end < profileProduceRows {
		g, idx := rows[end].group, rows[end].index
		for end < len(rows) && rows[end].group == g && rows[end].index == idx {
			end++
		}
	}
	return rows[:end]
}

// scan reads the project's profile records above the checkpoint, within what the scan's
// watermark proves complete. Everything is copied out of the borrowed page.
func (p *profileMapProducer) scan(ctx context.Context, read auth.Scope, key profileProjectKey) ([]profileRow, error) {
	done := p.checkpoints(key)
	after := make([]model.Cursor, 0, len(done))
	for group, index := range done {
		after = append(after, model.Cursor{Group: group, Index: index})
	}
	it, err := p.app.Storage.Scan(ctx, read, storage.ScanRequest{Projects: []model.ID{key.project}, Signal: model.Profile, Start: math.MinInt64, End: math.MaxInt64, After: after})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	marks := map[model.ID]model.Uint64{}
	for _, m := range it.Watermarks() {
		marks[m.Group] = m.Index
	}
	var out []profileRow
	var bytesRead uint64
	for {
		page, err := it.Next(ctx)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if page.Partial {
			return nil, model.Fail(model.Unavailable)
		}
		if bytesRead += page.Bytes; bytesRead > profileScanBytes {
			return nil, model.Fail(model.TooLarge)
		}
		for i := range page.IDs {
			origin := page.Origins[i]
			if origin.Group == (model.ID{}) || origin.Index <= done[origin.Group] || page.Projects[i] != key.project {
				continue
			}
			if mark, ok := marks[origin.Group]; ok && origin.Index > mark {
				continue
			}
			chunk := page.Values[i].Profile
			if chunk == nil {
				continue
			}
			out = append(out, profileRow{group: origin.Group, index: origin.Index, profile: chunk.Profile, roots: profileMaps(*chunk)})
		}
	}
}
