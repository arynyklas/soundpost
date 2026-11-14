// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package jobs_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
)

// A job whose evidence is after a completed range deletion's end is not derived
// from the deleted range: the deletion's late re-erasure must not tombstone it in
// the transition that commits it, and one whose evidence is inside the range is
// erased as it commits. (09.06 review C-1, the job half.)

func (o *ownApp) completedRange(t *testing.T, start, end model.UnixNano) {
	t.Helper()
	ctx := context.Background()
	scope, err := o.app.Auth.Authorize(ctx, o.actor, o.org1, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	var revision model.Revision
	if err = o.app.Control.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	at := hm(12, 0, 0)
	raw, err := json.Marshal(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{o.project1}, Signals: []model.Kind{model.JobAttempt},
		Start: start, End: end, At: at, Reason: "fixture", PhysicalDeadline: at + 1, BackupDeadline: at + 2})
	if err != nil {
		t.Fatal(err)
	}
	op := model.NewID()
	if _, err = o.app.Control.Transact(ctx, scope, control.Command{CommandID: op, ExpectedRevision: revision, Kind: string(control.KindDeleteScope), Payload: raw}); err != nil {
		t.Fatal(err)
	}
	var barriers []model.Cursor
	for slot := range uint16(model.DeleteSlots) {
		barriers = append(barriers, model.Cursor{Group: model.ID{byte(slot + 1)}, Index: 1})
	}
	if _, err = o.app.Control.RecordBarriers(ctx, op, barriers); err != nil {
		t.Fatal(err)
	}
	if _, err = o.app.Control.CompleteDeletion(ctx, op, at, nil); err != nil {
		t.Fatal(err)
	}
}

func TestJobOpenedAfterACompletedRangeDeletionSurvivesAndIsUpdatable(t *testing.T) {
	ctx := context.Background()
	o := openOwn(t)
	p := o.project1
	o.completedRange(t, hm(1, 0, 0), hm(2, 0, 0)) // long before the job's evidence
	h := newRealHFor(t, o.fixture, hm(11, 10, 0), jobID)
	w, r := h.writer(t), h.reader(t)
	def := hourly()
	key := jobsKey(hm(11, 0, 0))
	erasing := func() int {
		n := 0
		_ = o.app.Control.View(ctx, func(st control.State) error {
			for _, a := range st.Audits {
				if a.Action == "delete.control_erased" {
					n++
				}
			}
			return nil
		})
		return n
	}
	before := erasing()

	apply(t, h.svc, w, record(p, 1, ev(runA, att1, key, 1, 1, "started", hm(11, 0, 5), nil)))
	if _, err := h.svc.ObserveSchedule(ctx, w, jobs.ScheduleEvidence{CommandID: model.NewID(), Project: p, Job: jobID, Observer: model.ID{7}, ObservedAt: hm(11, 10, 0), CompleteThrough: hm(11, 10, 0), Healthy: true, Definition: &def}); err != nil {
		t.Fatal(err)
	}
	st, outcome := apply(t, h.svc, w, record(p, 2, ev(runA, att1, key, 1, 2, "succeeded", hm(11, 0, 5), new(hm(11, 0, 20)))))
	if outcome != jobs.Applied || st.Version != 3 || len(st.Attempts) != 1 {
		t.Fatalf("a job updated after a completed range deletion lost its history: %v %+v", outcome, st)
	}
	if snap, found, err := o.app.Control.JobBook(ctx, w, p, jobID); err != nil || !found || snap.Erased {
		t.Fatalf("the job's record is a tombstone: %+v found=%v err=%v", snap, found, err)
	}
	report, err := h.svc.Health(ctx, r, p, jobID)
	if err != nil || report.Health.Status != jobs.StatusSucceeded || len(report.State.Attempts) != 1 {
		t.Fatalf("health of the job: %v %+v", err, report.Health)
	}
	if n := erasing(); n != before {
		t.Fatalf("%d spurious erasing audit(s) for commits that erased nothing", n-before)
	}
}

func TestJobWithEvidenceInsideACompletedRangeIsErasedAsItCommits(t *testing.T) {
	o := openOwn(t)
	p := o.project1
	o.completedRange(t, hm(11, 0, 0), hm(11, 30, 0))
	h := newRealHFor(t, o.fixture, hm(11, 10, 0), jobID)
	w := h.writer(t)
	key := jobsKey(hm(11, 0, 0))
	st, outcome := apply(t, h.svc, w, record(p, 1, ev(runA, att1, key, 1, 1, "started", hm(11, 0, 5), nil)))
	if outcome != jobs.Applied || st.Version != 1 {
		t.Fatalf("the late update was refused: %v %+v", outcome, st)
	}
	if snap, found, err := o.app.Control.JobBook(context.Background(), w, p, jobID); err != nil || !found || !snap.Erased || snap.Version != 1 {
		t.Fatalf("a job with evidence inside the range must read as erased at its version: %+v found=%v err=%v", snap, found, err)
	}
}
