// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// Job books and cutover records are covered by the real deletion path, not only
// by the pure functions on a hand-built state: dropping either hook from
// eraseControlBooks must fail here. (01.08 review CD-5.)

// commitRuleSeq is commitRule for the n-th evaluation of one rule version: the
// writer's compare-and-set token is the number of evaluations committed so far.
func (f *eraseFx) commitRuleSeq(s eraseSeed, at uint64, signal model.Kind, expectedState model.Revision) {
	f.t.Helper()
	lease := f.lease()
	payload := fmt.Sprintf(`{"series":%q}`, s.canary)
	out := control.RuleOutputIntent{ID: model.NewID(), Kind: control.RuleOutputRecording, Signal: signal,
		Payload: json.RawMessage(fmt.Sprintf(`{"batch":{"records":[{"metric":%q}]}}`, s.canary)), Inputs: []model.Cursor{{Group: model.ID{9}, Index: 1}}}
	e := &control.RuleEvaluationApply{Project: s.project, Rule: s.rule, Version: 1, ExpectedStateRevision: expectedState, At: model.UnixNano(at), Mode: control.RuleModeLive, Health: control.RuleHealthOK,
		Digest: digestOf(payload), Payload: json.RawMessage(payload), Cursors: []model.Cursor{{Group: model.ID{9}, Index: model.Uint64(at)}}, Outputs: []control.RuleOutputIntent{out}}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindApplyRuleEvaluation, model.NewID(), control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: e})); err != nil {
		f.t.Fatal(err)
	}
}

func (f *eraseFx) seedCutover(project model.ID, canary string) {
	f.t.Helper()
	payload := json.RawMessage(fmt.Sprintf(`{"checked":%q}`, canary))
	rec := control.CutoverRecord{Org: f.org, Project: project, ID: model.NewID(), Old: model.NewID(), New: model.NewID(), Revision: 2, Phase: control.CutoverNewActive, EnteredAt: 5,
		Frontier: []control.CutoverFrontier{}, Steps: []control.CutoverStep{{Command: model.NewID(), Principal: f.user, Digest: model.Hash{2}, From: control.CutoverShadow, To: control.CutoverNewActive, Revision: 2, At: 5, Reason: "operator said " + canary, Payload: payload}}}
	raw, err := json.Marshal(rec)
	if err != nil {
		f.t.Fatal(err)
	}
	if err = f.store.Update(f.ctx, func(st *control.State) error {
		if st.CutoverBooks == nil {
			st.CutoverBooks = map[string]json.RawMessage{}
		}
		st.CutoverBooks[f.org.String()+":"+project.String()] = raw
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *eraseFx) seedJob(project model.ID, state string) {
	f.t.Helper()
	jobID := model.NewID()
	rec := control.JobRecord{Org: f.org, Project: project, Job: jobID, Version: 3, Digest: model.Hash{0x4a}, State: json.RawMessage(state),
		Commands: []control.JobCommandEntry{{ID: model.NewID(), Principal: f.user, Kind: "attempt", Digest: model.Hash{1}, Version: 3}}}
	raw, err := json.Marshal(rec)
	if err != nil {
		f.t.Fatal(err)
	}
	if err = f.store.Update(f.ctx, func(st *control.State) error {
		if st.JobBooks == nil {
			st.JobBooks = map[string]json.RawMessage{}
		}
		st.JobBooks[f.org.String()+":"+project.String()+":"+jobID.String()] = raw
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
}

func jobStateOf(canary string, extra string) string {
	return fmt.Sprintf(`{"job_id":"j","note":%q%s}`, canary, extra)
}

func (f *eraseFx) expectGone(canary string) {
	f.t.Helper()
	if f.stateHolds(canary) {
		f.t.Errorf("%s is still in the control state", canary)
	}
	if f.snapshotHolds(canary) {
		f.t.Errorf("%s is still in the control snapshot", canary)
	}
	if hits := controlDBHits(f.t, f.dir, canary); len(hits) != 0 {
		f.t.Errorf("%s is still in %v", canary, hits)
	}
}

func (f *eraseFx) expectKept(canary string) {
	f.t.Helper()
	if !f.stateHolds(canary) || !f.snapshotHolds(canary) {
		f.t.Errorf("%s was erased but is not covered", canary)
	}
}

func TestDeletionErasesJobAndCutoverBooks(t *testing.T) {
	const (
		jobA, cutA    = "CANARYJOBAfe1c7de9b86a2d30", "CANARYCUTAfe1c7de9b86a2d30"
		jobB, cutB    = "CANARYJOBBfe1c7de9b86a2d30", "CANARYCUTBfe1c7de9b86a2d30"
		jobOld, jobIn = "CANARYJOBOLDfe1c7de9b86a2d", "CANARYJOBINfe1c7de9b86a2d30"
	)
	seed := func(f *eraseFx) {
		f.seedJob(f.project, jobStateOf(jobA, ""))
		f.seedCutover(f.project, cutA)
		f.seedJob(f.otherProject, jobStateOf(jobB, ""))
		f.seedCutover(f.otherProject, cutB)
	}
	t.Run("retire project", func(t *testing.T) {
		f := newEraseFx(t)
		seed(f)
		f.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}})
		f.expectGone(jobA)
		f.expectGone(cutA)
		f.expectKept(jobB)
		f.expectKept(cutB)
	})
	t.Run("retire org", func(t *testing.T) {
		f := newEraseFx(t)
		seed(f)
		f.saga(control.DeleteScope{Mode: model.DeleteRetireOrg})
		for _, c := range []string{jobA, cutA, jobB, cutB} {
			f.expectGone(c)
		}
	})
	t.Run("historical range", func(t *testing.T) {
		f := newEraseFx(t)
		seed(f) // the job states name no time: they cannot be attributed to the range
		f.seedJob(f.project, jobStateOf(jobOld, `,"observed_ns":"5"`))
		f.seedJob(f.project, jobStateOf(jobIn, `,"observed_ns":"50"`))
		f.saga(f.lateRange())
		f.expectGone(jobA)
		f.expectGone(jobIn)
		f.expectKept(jobOld) // dated before the range
		f.expectKept(jobB)   // another project
		f.expectKept(cutA)   // a range covers no cutover record: it holds no telemetry
		f.expectKept(cutB)
	})
	t.Run("entity", func(t *testing.T) {
		f := newEraseFx(t)
		seed(f)
		f.saga(control.DeleteScope{Mode: model.DeleteEntity, Projects: []model.ID{f.project}, Entities: []model.ID{model.NewID()}})
		for _, c := range []string{jobA, cutA, jobB, cutB} {
			f.expectKept(c)
		}
	})
}

// A rule's retained evaluations are erased by their scheduled time in the
// half-open range [Start,End): one at End, one after End and one before Start
// keep their payload; the first and the last evaluation inside it lose theirs.
// (01.08 review CD-6.)
func TestRuleBookRangeIsHalfOpenAtBothEnds(t *testing.T) {
	f := newEraseFx(t)
	s := f.newSeed(f.project, "CANARYEDGE7c41e90d2b86a0f")
	for i, at := range []uint64{39, 40, 99, 100, 101} {
		f.commitRuleSeq(s, at, model.Metric, model.Revision(i))
	}
	f.saga(f.lateRange()) // [40,100) of the metric signal
	book, found, err := f.store.RuleBook(f.ctx, f.adminScope(), s.project, s.rule)
	if err != nil || !found {
		t.Fatalf("book: %v %v", found, err)
	}
	if len(book.Versions) != 1 {
		t.Fatalf("versions: %+v", book.Versions)
	}
	want := map[model.UnixNano]bool{39: true, 40: false, 99: false, 100: true, 101: true} // payload intact?
	seen := 0
	for _, r := range book.Versions[0].Recent {
		intact, known := want[r.At]
		if !known {
			t.Fatalf("unexpected evaluation at %d", r.At)
		}
		seen++
		if intact == dropped(r.Payload) {
			t.Errorf("evaluation at %d: payload dropped=%v, want intact=%v", r.At, dropped(r.Payload), intact)
		}
	}
	if seen != len(want) {
		t.Fatalf("retained evaluations: %d, want %d", seen, len(want))
	}
}
