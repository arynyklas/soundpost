// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package jobs_test

import (
	"context"
	"encoding/json"
	"errors"
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
	// The command commits and its state is erased in the same transition: the typed erased
	// result (09.08x-W3), no longer Applied with a payload that is gone.
	if st, outcome, err := h.svc.ApplyAttempt(context.Background(), w, record(p, 1, ev(runA, att1, key, 1, 1, "started", hm(11, 0, 5), nil))); !jobs.IsErased(err) {
		t.Fatalf("the late update answered %v %+v %v, want the erased result", outcome, st, err)
	}
	if snap, found, err := o.app.Control.JobBook(context.Background(), w, p, jobID); err != nil || !found || !snap.Erased || snap.Version != 1 {
		t.Fatalf("a job with evidence inside the range must read as erased at its version: %+v found=%v err=%v", snap, found, err)
	}
	// The listing carries the flag too: the console's only "History erased" wording rests on it.
	page, err := h.svc.List(context.Background(), h.reader(t), p, model.ID{}, 10)
	if err != nil || len(page.Jobs) != 1 || page.Jobs[0].Job != jobID || !page.Jobs[0].Erased {
		t.Fatalf("the listing must report the erased job as erased: %+v err=%v", page, err)
	}
}

// An update whose evidence lies inside an already erased range commits (the version moves) and the
// late pass erases its state in the same transition. The service must say so with a typed result
// callers can tell from success and from corruption, not answer Applied with the state it
// submitted and no payload behind it (09.08x-W3). The typed answer is model.NotFound with the
// SafeDetail "job_erased", the shape an action on an erased incident has.
func TestAttemptInsideACompletedRangeIsReportedErasedNotApplied(t *testing.T) {
	ctx := context.Background()
	o := openOwn(t)
	p := o.project1
	o.completedRange(t, hm(11, 0, 0), hm(11, 30, 0))
	h := newRealHFor(t, o.fixture, hm(11, 10, 0), jobID)
	w := h.writer(t)
	key := jobsKey(hm(11, 0, 0))
	erased := func(err error) bool {
		var f *model.Fault
		return errors.As(err, &f) && f.Code == model.NotFound && f.SafeDetail == "job_erased"
	}
	st, outcome, err := h.svc.ApplyAttempt(ctx, w, record(p, 1, ev(runA, att1, key, 1, 1, "started", hm(11, 0, 5), nil)))
	if !erased(err) {
		t.Fatalf("an attempt inside an erased range answered %v %+v, %v; want not_found/job_erased", outcome, st, err)
	}
	if snap, found, err := o.app.Control.JobBook(ctx, w, p, jobID); err != nil || !found || !snap.Erased || snap.Version != 1 {
		t.Fatalf("the command did not commit as a tombstone at version 1: %+v found=%v err=%v", snap, found, err)
	}
	// A schedule observation and a correction are write paths of the same store: the same answer.
	def := hourly()
	_, err = h.svc.ObserveSchedule(ctx, w, jobs.ScheduleEvidence{CommandID: model.NewID(), Project: p, Job: jobID, Observer: model.ID{7}, ObservedAt: hm(11, 10, 0), CompleteThrough: hm(11, 10, 0), Healthy: true, Definition: &def})
	if !erased(err) {
		t.Fatalf("a schedule observation inside an erased range answered %v, want not_found/job_erased", err)
	}
}
