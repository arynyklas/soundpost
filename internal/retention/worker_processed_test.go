// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// expireCandidates runs one expiry pass whose planner offers the candidates and
// returns the batch indexes the pass was allowed to erase.
func (g *gapFx) expireCandidates(cands ...storage.EraseCandidate) (erased []uint64) {
	g.t.Helper()
	g.plane.expired = func(ctx context.Context, _ model.UnixNano, guard storage.EraseGuard) (storage.EraseReport, error) {
		report := storage.EraseReport{}
		for _, c := range cands {
			ok, err := guard(ctx, c)
			if err != nil {
				return report, err
			}
			if ok {
				erased = append(erased, uint64(c.Cursor.Index))
				report.Records++
			}
		}
		return report, nil
	}
	g.advance(2 * time.Hour)
	g.run()
	return erased
}

// [01.08-W3] Error evidence at or below the project's committed issue checkpoint
// is processed and expires without a gap; evidence above it needs one.
func TestExpiryReadsTheIssueCheckpointAsProcessed(t *testing.T) {
	g := newGapFx(t)
	g.proc.at[g.group] = 0 // the injected provider knows nothing: only control state speaks
	raw, err := json.Marshal(map[string]any{"checkpoints": map[string]model.Uint64{g.group.String(): 4}})
	if err != nil {
		t.Fatal(err)
	}
	if err = g.store.Update(g.ctx, func(st *control.State) error {
		if st.IssueBooks == nil {
			st.IssueBooks = map[string]json.RawMessage{}
		}
		st.IssueBooks[g.org.String()+":"+g.project.String()] = raw
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	cand := func(index uint64) storage.EraseCandidate {
		r := model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: model.UnixNano(10 + index)}
		return storage.EraseCandidate{Org: g.org, Project: g.project, Cursor: model.Cursor{Group: g.group, Index: model.Uint64(index)}, Kind: model.ErrorKind, Record: &r}
	}
	if got := g.expireCandidates(cand(3), cand(4), cand(5)); len(got) != 3 {
		t.Fatalf("erased %v", got)
	}
	gaps := g.gaps()
	if len(gaps) != 1 || gaps[[2]uint64{4, 5}].Count != 1 {
		t.Fatalf("gaps %+v: only index 5, above the checkpoint, may need one", gaps)
	}
}

// [01.08-W3] A job_attempt record whose attempt command the job book holds is
// processed; one the book does not hold, or an unreadable candidate, is not.
func TestExpiryReadsTheJobBookAsProcessed(t *testing.T) {
	g := newGapFx(t)
	g.proc.at[g.group] = 0
	job := model.NewID()
	cand := func(index uint64) storage.EraseCandidate {
		r := model.Record{ID: model.NewID(), Kind: model.JobAttempt, ObservedAt: model.UnixNano(10 + index), Payload: model.Payload{Job: &model.JobAttemptEvent{Job: job}}}
		return storage.EraseCandidate{Org: g.org, Project: g.project, Cursor: model.Cursor{Group: g.group, Index: model.Uint64(index)}, Kind: model.JobAttempt, Record: &r}
	}
	applied, unapplied := cand(7), cand(9)
	origin := applied.Cursor
	rec := control.JobRecord{Org: g.org, Project: g.project, Job: job, Version: 1, State: json.RawMessage(`{}`),
		Commands: []control.JobCommandEntry{{ID: jobs.AttemptCommandID(g.org, g.project, origin, applied.Record.ID), Principal: model.NewID(), Kind: "attempt", Version: 1, Origin: &origin}}}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err = g.store.Update(g.ctx, func(st *control.State) error {
		if st.JobBooks == nil {
			st.JobBooks = map[string]json.RawMessage{}
		}
		st.JobBooks[g.org.String()+":"+g.project.String()+":"+job.String()] = raw
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := g.expireCandidates(applied, unapplied); len(got) != 2 {
		t.Fatalf("erased %v", got)
	}
	gaps := g.gaps()
	if len(gaps) != 1 || gaps[[2]uint64{8, 9}].Count != 1 {
		t.Fatalf("gaps %+v: only the record the job book never applied may need one", gaps)
	}
}
