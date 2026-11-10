// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"encoding/json"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/retention"
	"soundpost/internal/storage"
	"testing"
	"time"
)

func (f *fx) generation() uint64 {
	f.t.Helper()
	g, err := f.gens.DeleteGeneration(f.ctx, f.org, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return g
}

// The delete generation must advance BEFORE bytes become unreadable: a cache entry, cursor or
// export ticket minted under the old generation must already be dead when the erasure starts.
// The physical pass is observed from inside the erase call of a deletion that was already
// completed by an earlier pass, so nothing but the pass's own advance can move the generation
// between the two readings.
func TestPhysicalPassAdvancesTheDeleteGenerationBeforeItErases(t *testing.T) {
	f := newFx(t, options{})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	var atErase uint64
	f.plane.erased = func(ctx context.Context, _ []model.DeletePredicate, _ storage.EraseGuard) (storage.EraseReport, error) {
		atErase = f.generation()
		return storage.EraseReport{Held: 1}, nil // nothing erased: the cleanup stays pending
	}
	if _, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} }); err != nil {
		t.Fatal(err)
	}
	f.run() // completes the deletion
	before := f.generation()
	f.run()
	if atErase <= before {
		t.Fatalf("generation %d observed at the erase call, %d before the pass: not advanced before erasing", atErase, before)
	}
}

// The same ordering for retention expiry, where the advance is the only thing that kills a warm
// cache entry or ticket for bytes that expire: the generation read at the planning pass is
// already behind the one read when the erasing pass starts.
func TestExpiryPassAdvancesTheDeleteGenerationBeforeItErases(t *testing.T) {
	f := newFx(t, options{})
	record := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: 10}
	candidate := storage.EraseCandidate{Org: f.org, Project: f.project, Kind: model.Metric, Record: &record, Cursor: model.Cursor{Group: model.NewID(), Index: 1}}
	var planned, erasing uint64
	calls := 0
	f.plane.expired = func(ctx context.Context, _ model.UnixNano, g storage.EraseGuard) (storage.EraseReport, error) {
		calls++
		if calls == 1 { // the dry planning pass registers the organization as having expirable data
			if _, err := g(ctx, candidate); err != nil {
				return storage.EraseReport{}, err
			}
			planned = f.generation()
			return storage.EraseReport{}, nil
		}
		erasing = f.generation()
		return storage.EraseReport{Records: 1}, nil
	}
	f.run()
	if calls != 2 {
		t.Fatalf("expiry made %d EraseExpired calls, want plan + erase", calls)
	}
	if erasing <= planned {
		t.Fatalf("generation %d at the erasing pass, %d at the plan: expired bytes were erased before the generation advanced", erasing, planned)
	}
}

// N2: every organization whose operations were erased is checkpointed with one of ITS operations,
// not the first organization's predicate standing in for all.
func TestEveryReadyOrganizationIsCheckpointedWithItsOwnOperation(t *testing.T) {
	f := newFx(t, options{})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	second := model.NewID()
	raw, _ := json.Marshal(auth.AdminPayload{Name: "second", Reason: "fixture"})
	if _, err := f.auth.AdminCommand(f.ctx, f.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(), OrgID: second, Kind: "create_org", Payload: raw}); err != nil {
		t.Fatal(err)
	}
	other := model.DeletePredicate{Operation: model.NewID(), Org: second, Mode: model.DeleteRetireOrg, Generation: 1}
	if err := f.store.ImportDeletions(f.ctx, []model.DeletePredicate{other}, model.UnixNano(f.at().UnixNano())); err != nil {
		t.Fatal(err)
	}
	receipt, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} })
	if err != nil {
		t.Fatal(err)
	}
	var checkpointed []model.ID
	f.plane.checkpointed = func(p model.DeletePredicate) error { checkpointed = append(checkpointed, p.Operation); return nil }
	f.run()
	seen := map[model.ID]bool{}
	for _, op := range checkpointed {
		seen[op] = true
	}
	if !seen[receipt.OperationID] || !seen[other.Operation] {
		t.Fatalf("checkpointed operations %v: want one of each organization (%s, %s)", checkpointed, receipt.OperationID, other.Operation)
	}
}

// N4: a permanently failing step is visible without a log: the status counts consecutive failed
// passes and returns to zero after a clean one. It carries a count, never data.
func TestWorkerStatusCountsConsecutiveFailedPasses(t *testing.T) {
	f := newFx(t, options{})
	failing := true
	f.plane.trace = func(step string) error {
		if step == "snapshot" && failing {
			return model.Fail(model.Unavailable)
		}
		return nil
	}
	for want := uint64(1); want <= 3; want++ {
		if err := f.svc.RunOnce(f.ctx); err == nil {
			t.Fatal("the failing snapshot step was not reported")
		}
		if got := f.svc.Status().ConsecutiveFailures; got != want {
			t.Fatalf("after %d failed passes the status counts %d", want, got)
		}
	}
	failing = false
	f.run()
	if got := f.svc.Status().ConsecutiveFailures; got != 0 {
		t.Fatalf("a clean pass left the failure counter at %d", got)
	}
}

type gapFx struct {
	*fx
	group model.ID
	proc  *fixedProcessed
}

// gapExpiry runs one expiry pass whose planner offers unprocessed error evidence at the given
// indexes of one group (two records for an index that appears twice), and returns the indexes
// the pass was allowed to erase.
func (g *gapFx) gapExpiry(indexes ...uint64) (erased []uint64) {
	g.t.Helper()
	cand := func(index uint64) storage.EraseCandidate {
		r := model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: model.UnixNano(10 + index)}
		return storage.EraseCandidate{Org: g.org, Project: g.project, Cursor: model.Cursor{Group: g.group, Index: model.Uint64(index)}, Kind: model.ErrorKind, Record: &r}
	}
	g.plane.expired = func(ctx context.Context, _ model.UnixNano, guard storage.EraseGuard) (storage.EraseReport, error) {
		report := storage.EraseReport{}
		for _, i := range indexes {
			ok, err := guard(ctx, cand(i))
			if err != nil {
				return report, err
			}
			if ok {
				erased = append(erased, i)
				report.Records++
			}
		}
		return report, nil
	}
	g.advance(2 * time.Hour)
	g.run()
	return erased
}
func newGapFx(t *testing.T) *gapFx {
	proc := &fixedProcessed{at: map[model.ID]uint64{}}
	g := &gapFx{fx: newFx(t, options{processed: proc}), group: model.NewID(), proc: proc}
	proc.at[g.group] = 2
	return g
}
func (g *gapFx) gaps() map[[2]uint64]model.EvidenceGap {
	g.t.Helper()
	all, err := g.store.EvidenceGaps(g.ctx, g.org, g.project)
	if err != nil {
		g.t.Fatal(err)
	}
	out := map[[2]uint64]model.EvidenceGap{}
	for _, gap := range all {
		out[[2]uint64{uint64(gap.After), uint64(gap.Through)}] = gap
	}
	return out
}

// I6: a worker gap enumerates what it covers. Candidates 3 and 5 declare (2,3] and (4,5], not the
// contiguous run (2,5]: entry 4 was not expired, so when it expires later it is unprocessed
// evidence of its own and needs its own durable gap; the earlier gap does not swallow it. Two
// records of one batch are one entry.
func TestWorkerGapsNeverSwallowEntriesBetweenCandidates(t *testing.T) {
	g := newGapFx(t)
	if got := g.gapExpiry(3, 3, 5); len(got) != 3 {
		t.Fatalf("erased %v: gap-covered evidence is erasable", got)
	}
	gaps := g.gaps()
	if len(gaps) != 2 || gaps[[2]uint64{2, 3}].Count != 1 || gaps[[2]uint64{4, 5}].Count != 1 {
		t.Fatalf("gaps %+v: want exactly (2,3] and (4,5], one entry each", gaps)
	}
	for _, gap := range gaps {
		if gap.DeclaredBy != control.GapDeclaredByWorker {
			t.Fatalf("worker gap declared by %q", gap.DeclaredBy)
		}
	}
	// Entry 4 expires later: it is not covered by anything yet, so it needs a gap of its own.
	if got := g.gapExpiry(4); len(got) != 1 {
		t.Fatalf("erased %v", got)
	}
	if gaps = g.gaps(); len(gaps) != 3 || gaps[[2]uint64{3, 4}].Count != 1 {
		t.Fatalf("entry 4 was swallowed by an earlier gap instead of getting its own: %+v", gaps)
	}
}

// I6: an administrator's gap, however wide, is recorded but authorizes nothing: the worker still
// declares and commits its own gap for evidence inside the administrator's interval before that
// evidence may be erased.
func TestAdministratorGapNeverAuthorizesExpiry(t *testing.T) {
	g := newGapFx(t)
	wide := model.EvidenceGap{ID: model.NewID(), Org: g.org, Project: g.project, Group: g.group, After: 2, Through: 900, Count: 1, Start: 1, End: 2, Signals: []model.Kind{model.ErrorKind}, Reason: "operator note", RecordedAt: g.svcNow()}
	raw, err := json.Marshal(wide)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.store.Transact(g.ctx, g.adminScope(), control.Command{CommandID: model.NewID(), ExpectedRevision: g.revision(), Kind: string(control.KindRecordEvidenceGap), Payload: raw}); err != nil {
		t.Fatal(err)
	}
	if got := g.gapExpiry(5); len(got) != 1 {
		t.Fatalf("erased %v", got)
	}
	gaps := g.gaps()
	own, ok := gaps[[2]uint64{4, 5}]
	if !ok || own.DeclaredBy != control.GapDeclaredByWorker || len(gaps) != 2 {
		t.Fatalf("evidence inside an administrator's interval was erased without a gap of the worker's own: %+v", gaps)
	}
}
func (g *gapFx) svcNow() model.UnixNano { return model.UnixNano(g.at().UnixNano()) }
