// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"slices"
	"time"

	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/artifacts/refledger"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/retention"
)

// Source-map retention of the issue pipeline (L2-P18, 10.09-W1).
//
// An error occurrence names the source maps that resolve its frames: Frame.Artifact is the
// canonical artifact ID (the only lookup key the symbolicator accepts). The issue producer
// groups occurrences into issues under the system principal, which holds issues.write and
// cannot hold artifacts.write (D1), so it keeps the maps through artifacts.Lifecycle.HoldIssues
// and SettleIssues, which that scope is admitted to:
//
//   - before a batch of occurrences is applied, every issue the batch touches holds the maps
//     the batch's frames name, until the retention deadline of the error records that use
//     them (the audited error retention of the project from the producer's clock: the map
//     lives as long as the last retained record that uses it, the design's rule);
//   - after the batch, SettleIssues reads the committed issue book and drops the holds of an
//     issue that is resolved or ignored, and takes them again when it reopens.
//
// An occurrence may name an ID that is not a published map of its project (the client writes
// frames): that hold is skipped, never an error, and never reaches another project or
// organization, because the lifecycle looks the root up under the scope's own org and project.

// maxOccurrenceMaps bounds the distinct maps one occurrence can ask the lifecycle to hold.
const maxOccurrenceMaps = refledger.MaxHolderRoots

// occurrenceMaps lists the distinct artifact IDs the frames of one occurrence name, including
// the frames of its exception graph, in first-seen order and at most maxOccurrenceMaps.
func occurrenceMaps(occ model.ErrorOccurrence) []model.ID {
	var out []model.ID
	add := func(frames []model.Frame) {
		for _, f := range frames {
			if f.Artifact == "" || len(out) >= maxOccurrenceMaps {
				continue
			}
			id, err := model.ParseID(f.Artifact)
			if err != nil || id == (model.ID{}) || slices.Contains(out, id) {
				continue
			}
			out = append(out, id)
		}
	}
	add(occ.Frames)
	if occ.Graph != nil {
		for _, n := range occ.Graph.Nodes {
			add(n.Frames)
		}
	}
	return out
}

// mapHolds is the maps each issue of one batch needs.
type mapHolds map[model.ID]*artifacts.IssueHold

func (h mapHolds) add(issue model.ID, roots []model.ID) {
	if len(roots) == 0 {
		return
	}
	hold := h[issue]
	if hold == nil {
		hold = &artifacts.IssueHold{Issue: issue}
		h[issue] = hold
	}
	for _, r := range roots {
		if len(hold.Roots) < maxOccurrenceMaps && !slices.Contains(hold.Roots, r) {
			hold.Roots = append(hold.Roots, r)
		}
	}
}

// mapRetention is the map side of one Produce call of one project.
type mapRetention struct {
	app          *App
	org, project model.ID
	lease        replica.FenceToken
}

func (p *issueProducer) newMapHolds(_ context.Context, scopes ProducerScopes, lease replica.FenceToken) *mapRetention {
	return &mapRetention{app: p.app, org: scopes.Org(), project: scopes.Project(), lease: lease}
}

// until is the deadline a hold taken now lasts to: the error retention in force for the
// project, from the lifecycle's own clock (the clock every deadline in the ledger is on).
func (m *mapRetention) until(ctx context.Context, life *artifacts.Lifecycle) (model.UnixNano, error) {
	now := model.UnixNano(life.Now().UnixNano())
	var days uint32
	err := m.app.Control.View(ctx, func(st model.ControlState) error {
		days = retention.Resolve(st, m.org, &m.project, now).DaysFor(model.ErrorKind, false)
		return nil
	})
	if err != nil || days == 0 {
		return 0, err
	}
	return now + model.UnixNano(time.Duration(days)*24*time.Hour), nil
}

func (m *mapRetention) lifecycle() (*artifacts.Lifecycle, error) {
	if m.app.ArtifactLifecycle == nil {
		return nil, model.Fail(model.Unavailable)
	}
	return m.app.ArtifactLifecycle, nil
}

// hold takes the holds of one batch, in chunks the lifecycle accepts.
func (m *mapRetention) hold(ctx context.Context, write auth.Scope, holds mapHolds) error {
	if len(holds) == 0 {
		return nil
	}
	life, err := m.lifecycle()
	if err != nil {
		return err
	}
	until, err := m.until(ctx, life)
	if err != nil || until == 0 {
		return err
	}
	issues := make([]model.ID, 0, len(holds))
	for issue := range holds {
		issues = append(issues, issue)
	}
	slices.SortFunc(issues, func(a, b model.ID) int { return slices.Compare(a[:], b[:]) })
	var batch []artifacts.IssueHold
	distinct := map[model.ID]bool{}
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := m.app.leaseGate(ctx, m.lease); err != nil {
			return err
		}
		if _, err := life.HoldIssues(ctx, write, batch); err != nil {
			return err
		}
		batch, distinct = nil, map[model.ID]bool{}
		return nil
	}
	for _, issue := range issues {
		hold := *holds[issue]
		hold.Until = until
		fresh := 0
		for _, r := range hold.Roots {
			if !distinct[r] {
				fresh++
			}
		}
		if len(distinct)+fresh > artifacts.MaxHoldRoots || len(batch) >= artifacts.MaxHoldIssues {
			if err := flush(); err != nil {
				return err
			}
		}
		batch = append(batch, hold)
		for _, r := range hold.Roots {
			distinct[r] = true
		}
	}
	return flush()
}

// settleRounds bounds the SettleIssues calls of one pass; the lifecycle changes a bounded
// number of issues per call and the rest wait for the next pass.
const settleRounds = 8

// settle reconciles the project's holds with the committed issue book.
func (m *mapRetention) settle(ctx context.Context, write auth.Scope) error {
	life, err := m.lifecycle()
	if err != nil {
		return err
	}
	for range settleRounds {
		if err := m.app.leaseGate(ctx, m.lease); err != nil {
			return err
		}
		res, err := life.SettleIssues(ctx, write)
		if err != nil {
			return err
		}
		if !res.More {
			return nil
		}
	}
	return nil
}
