// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package jobs_test

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	ctl "soundpost/internal/control"
	"soundpost/internal/jobs"
	"soundpost/internal/model"
)

// These tests run the read methods over the real adapter on a real control
// store (appcore.Open: real auth, real Raft) with an application of their own,
// so a project listing sees exactly the jobs seeded here.

type listEnv struct {
	f                 *fixture
	org, org2         model.ID
	project, project2 model.ID
	empty             model.ID
	clock             *fakeClock
	svc               *jobs.Service
	index             uint64
	writer, reader    auth.Scope
	otherReader       auth.Scope
	otherWriter       auth.Scope
	emptyReader       auth.Scope
}

func getListEnv(t *testing.T) *listEnv {
	t.Helper()
	var listEnvV *listEnv
	var listErr error
	func() {
		e := &listEnv{org: model.NewID(), org2: model.NewID(), project: model.NewID(), project2: model.NewID(), empty: model.NewID(), clock: &fakeClock{at: hm(12, 3, 0)}}
		dir := t.TempDir()
		app, err := appcore.Open(dir)
		if err != nil {
			listErr = err
			return
		}
		t.Cleanup(func() { app.Close() })
		e.f = &fixture{app: app, passwords: "jobs list password 2026"}
		ctx := context.Background()
		boot, err := app.Control.BootstrapToken()
		if err != nil {
			listErr = err
			return
		}
		session, err := app.Auth.Bootstrap(ctx, boot, "jobs-list-admin@example.test", e.f.passwords)
		if err != nil {
			listErr = err
			return
		}
		actor, err := app.Auth.Authenticate(ctx, session.Token)
		if err != nil {
			listErr = err
			return
		}
		steps := []func() error{
			func() error { return admin(e.f, actor, e.org, "create_org", auth.AdminPayload{Name: "list one"}) },
			func() error {
				return admin(e.f, actor, e.org, "create_project", auth.AdminPayload{ID: e.project, Name: "application"})
			},
			func() error {
				return admin(e.f, actor, e.org, "create_project", auth.AdminPayload{ID: e.empty, Name: "no jobs"})
			},
			func() error { return admin(e.f, actor, e.org2, "create_org", auth.AdminPayload{Name: "list two"}) },
			func() error {
				return admin(e.f, actor, e.org2, "create_project", auth.AdminPayload{ID: e.project2, Name: "other application"})
			},
		}
		users := []struct {
			email   string
			org     model.ID
			project model.ID
			perm    string
		}{{"w1@example.test", e.org, e.project, "policy.write"}, {"r1@example.test", e.org, e.project, "telemetry.read"}, {"w2@example.test", e.org2, e.project2, "policy.write"}, {"r2@example.test", e.org2, e.project2, "telemetry.read"}, {"r3@example.test", e.org, e.empty, "telemetry.read"}}
		for _, u := range users {
			id := model.NewID()
			steps = append(steps,
				func() error {
					return admin(e.f, actor, u.org, "create_user", auth.AdminPayload{ID: id, Email: u.email, Password: e.f.passwords})
				},
				func() error {
					return admin(e.f, actor, u.org, "membership", auth.AdminPayload{UserID: id, Enabled: true})
				},
				func() error {
					return admin(e.f, actor, u.org, "grant", auth.AdminPayload{UserID: id, ProjectID: u.project, Permissions: []string{u.perm}, Enabled: true})
				})
		}
		for _, step := range steps {
			if err = step(); err != nil {
				listErr = err
				return
			}
		}
		listEnvV = e
		e.writer = e.f.scope(t, "w1@example.test", e.org, e.project, auth.PolicyWrite)
		e.reader = e.f.scope(t, "r1@example.test", e.org, e.project, auth.Read)
		e.otherWriter = e.f.scope(t, "w2@example.test", e.org2, e.project2, auth.PolicyWrite)
		e.otherReader = e.f.scope(t, "r2@example.test", e.org2, e.project2, auth.Read)
		e.emptyReader = e.f.scope(t, "r3@example.test", e.org, e.empty, auth.Read)
		store, err := jobs.NewControlStore(app.Control)
		if err != nil {
			listErr = err
			return
		}
		if e.svc, err = jobs.New(store, app.Auth, e.clock); err != nil {
			listErr = err
		}
	}()
	if listErr != nil {
		t.Fatal(listErr)
	}
	return listEnvV
}

func (e *listEnv) apply(t *testing.T, job model.ID, run, attempt model.ID, schedule string, ordinal, seq uint64, state string, observed model.UnixNano, terminal *model.UnixNano) jobs.AttemptEvidence {
	t.Helper()
	e.index++
	ev := ev(run, attempt, schedule, ordinal, seq, state, observed, terminal)
	ev.Job = job
	rec := record(e.project, e.index, ev)
	if _, _, err := e.svc.ApplyAttempt(context.Background(), e.writer, rec); err != nil {
		t.Fatalf("apply: %v", err)
	}
	return rec
}

var (
	jobRecovered = model.ID{0x10, 1}
	jobFailed    = model.ID{0x20, 2}
	jobCancelled = model.ID{0x30, 3}
	jobScheduled = model.ID{0x40, 4}

	listOrigin model.Cursor
)

// seedList commits, through the real service, a recovered run, a failed job, a
// cancelled job and a scheduled job that only an observer has spoken about.
func seedList(t *testing.T) *listEnv {
	e := getListEnv(t)
	func() {
		e.apply(t, jobRecovered, runA, att1, "manual.a", 1, 1, "failed", hm(11, 0, 0), new(hm(11, 0, 5)))
		e.apply(t, jobRecovered, runA, att2, "manual.a", 2, 2, "started", hm(11, 1, 0), nil)
		rec := e.apply(t, jobRecovered, runA, att2, "manual.a", 2, 3, "succeeded", hm(11, 1, 0), new(hm(11, 1, 30)))
		listOrigin = rec.Cursor
		e.apply(t, jobFailed, runA, att1, "manual.a", 1, 1, "failed", hm(11, 2, 0), new(hm(11, 2, 5)))
		e.apply(t, jobCancelled, runA, att1, "manual.a", 1, 1, "cancelled", hm(11, 3, 0), new(hm(11, 3, 5)))
		def := hourly()
		if _, err := e.svc.ObserveSchedule(context.Background(), e.writer, jobs.ScheduleEvidence{CommandID: model.NewID(), Project: e.project, Job: jobScheduled, Observer: observe, ObservedAt: hm(12, 3, 0), CompleteThrough: hm(12, 3, 0), Healthy: true, Definition: &def}); err != nil {
			t.Fatal(err)
		}
	}()
	return e
}

func TestJobListPagesInIDOrderWithTruthfulHealth(t *testing.T) {
	e := seedList(t)
	ctx := context.Background()
	want := []model.ID{jobRecovered, jobFailed, jobCancelled, jobScheduled}
	var got []jobs.Summary
	after := model.ID{}
	for pages := 0; ; pages++ {
		page, err := e.svc.List(ctx, e.reader, e.project, after, 3)
		if err != nil {
			t.Fatal(err)
		}
		if pages > 1 || len(page.Jobs) > 3 || page.EvaluatedAt != hm(12, 3, 0) {
			t.Fatalf("page %d: %d jobs at %d", pages, len(page.Jobs), page.EvaluatedAt)
		}
		got = append(got, page.Jobs...)
		if !page.More {
			break
		}
		after = page.Jobs[len(page.Jobs)-1].Job
	}
	if len(got) != len(want) {
		t.Fatalf("%d jobs listed, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].Job != id {
			t.Fatalf("order: %v at %d, want %v", got[i].Job, i, id)
		}
		// The listed verdict is exactly the verdict a single-job health read gives.
		report, err := e.svc.Health(ctx, e.reader, e.project, id)
		if err != nil || !reflect.DeepEqual(report.Health, got[i].Health) || report.Version != got[i].Version {
			t.Fatalf("job %v: list %+v vs health %+v (%v)", id, got[i].Health, report.Health, err)
		}
	}
	byJob := map[model.ID]jobs.Summary{}
	for _, s := range got {
		byJob[s.Job] = s
	}
	if s := byJob[jobRecovered]; s.Health.Status != jobs.StatusSucceeded || s.Runs != 1 || s.Attempts != 2 {
		t.Fatalf("recovered job: %+v", s)
	}
	if s := byJob[jobFailed]; s.Health.Status != jobs.StatusFailed || s.Attempts != 1 {
		t.Fatalf("failed job: %+v", s)
	}
	if s := byJob[jobCancelled]; s.Health.Status != jobs.StatusCancelled {
		t.Fatalf("cancelled job reads %q", s.Health.Status)
	}
	if s := byJob[jobScheduled]; s.Health.Status != jobs.StatusMissed || s.Definition.Schedule == nil || s.Definition.Schedule.Timezone != "UTC" || s.Runs != 0 {
		t.Fatalf("scheduled job: %+v", s)
	}
}

func TestJobListIsBoundedAndReadOnly(t *testing.T) {
	e := seedList(t)
	ctx := context.Background()
	for _, limit := range []int{0, -3, jobs.MaxListPage + 1} {
		if _, err := e.svc.List(ctx, e.reader, e.project, model.ID{}, limit); code(err) != model.Invalid {
			t.Fatalf("limit %d: %v", limit, err)
		}
	}
	if page, err := e.svc.List(ctx, e.reader, e.project, model.ID{}, jobs.MaxListPage); err != nil || len(page.Jobs) != 4 || page.More {
		t.Fatalf("limit at the bound: %+v %v", page, err)
	}
	// A project with no jobs is an empty page, not an error.
	if page, err := e.svc.List(ctx, e.emptyReader, e.empty, model.ID{}, 5); err != nil || len(page.Jobs) != 0 || page.More {
		t.Fatalf("empty project: %+v %v", page, err)
	}
	before, err := e.svc.Health(ctx, e.reader, e.project, jobFailed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.svc.List(ctx, e.reader, e.project, model.ID{}, 10); err != nil {
		t.Fatal(err)
	}
	if _, err = e.svc.View(ctx, e.reader, e.project, jobFailed); err != nil {
		t.Fatal(err)
	}
	after, err := e.svc.Health(ctx, e.reader, e.project, jobFailed)
	if err != nil || after.Version != before.Version {
		t.Fatalf("a read moved the job version: %d -> %d (%v)", before.Version, after.Version, err)
	}
}

// Scope first: reads need telemetry.read exactly, and a wrong scope, a project
// outside the scope and a missing job are one not-found.
func TestJobReadsAreScopeFirstAndIndistinguishable(t *testing.T) {
	e := seedList(t)
	ctx := context.Background()
	if _, err := e.svc.List(ctx, e.writer, e.project, model.ID{}, 5); code(err) != model.Forbidden {
		t.Fatalf("policy.write listed: %v", err)
	}
	if _, err := e.svc.View(ctx, e.writer, e.project, jobFailed); code(err) != model.Forbidden {
		t.Fatalf("policy.write viewed: %v", err)
	}
	if _, err := e.svc.List(ctx, auth.Scope{}, e.project, model.ID{}, 5); err == nil {
		t.Fatal("zero scope listed")
	}
	if _, err := e.svc.View(ctx, auth.Scope{}, e.project, jobFailed); err == nil {
		t.Fatal("zero scope viewed")
	}
	_, missingJob := e.svc.View(ctx, e.reader, e.project, model.ID{0xee})
	_, otherOrgsProject := e.svc.View(ctx, e.otherReader, e.project, jobFailed)
	_, ownOtherProject := e.svc.View(ctx, e.reader, e.project2, jobFailed)
	_, guessedProject := e.svc.View(ctx, e.reader, model.NewID(), jobFailed)
	_, otherOrgJob := e.svc.View(ctx, e.otherReader, e.project2, jobFailed)
	_, listForeign := e.svc.List(ctx, e.otherReader, e.project, model.ID{}, 5)
	_, listMissing := e.svc.List(ctx, e.reader, model.NewID(), model.ID{}, 5)
	for name, err := range map[string]error{"missing job": missingJob, "other org's project": otherOrgsProject, "own scope other project": ownOtherProject, "guessed project": guessedProject, "other org's job id": otherOrgJob, "list foreign": listForeign, "list missing": listMissing} {
		if code(err) != model.NotFound || err.Error() != missingJob.Error() {
			t.Fatalf("%s: %v vs %v", name, err, missingJob)
		}
	}
	// The same job ID seeded in the other organization is not reachable from this one.
	if _, err := e.svc.View(ctx, e.otherReader, e.project2, jobRecovered); code(err) != model.NotFound {
		t.Fatalf("org 2 reached org 1's job: %v", err)
	}
	page, err := e.svc.List(ctx, e.otherReader, e.project2, model.ID{}, 5)
	if err != nil || len(page.Jobs) != 0 {
		t.Fatalf("org 2 listing leaked org 1's jobs: %+v %v", page, err)
	}
}

func TestJobViewReportsHealthRunsAndCommittedSource(t *testing.T) {
	e := seedList(t)
	ctx := context.Background()
	view, err := e.svc.View(ctx, e.reader, e.project, jobRecovered)
	if err != nil {
		t.Fatal(err)
	}
	report, err := e.svc.Health(ctx, e.reader, e.project, jobRecovered)
	if err != nil || !reflect.DeepEqual(view.Report, report) {
		t.Fatalf("view report differs from the health read: %v", err)
	}
	if view.Erased || view.Origin == nil || *view.Origin != listOrigin {
		t.Fatalf("source cursor %+v, want %+v", view.Origin, listOrigin)
	}
	run, attempts, ok := view.Report.State.RunAttempts(runA)
	if !ok || run.Status != jobs.RunRecovered || len(attempts) != 2 || attempts[0].ID != att1 || attempts[1].ID != att2 || attempts[0].Effective() != jobs.AttemptFailed {
		t.Fatalf("run %+v attempts %+v", run, attempts)
	}
	// A job that only the observer wrote has no attempt origin.
	sched, err := e.svc.View(ctx, e.reader, e.project, jobScheduled)
	if err != nil || sched.Origin != nil || sched.Report.Health.Status != jobs.StatusMissed {
		t.Fatalf("scheduled job view: %+v %v", sched, err)
	}
}

// A service over a store that cannot enumerate says so with the typed
// unsupported fault, but only after the scope was checked.
func TestJobReadsOverAStoreWithoutReadsAreTypedUnsupportedAfterScope(t *testing.T) {
	h := newHarness(t, hm(12, 3, 0))
	ctx := context.Background()
	p := h.f.project1
	if _, err := h.svc.List(ctx, h.reader(t), p, model.ID{}, 5); code(err) != model.Unsupported {
		t.Fatalf("list: %v", err)
	}
	if _, err := h.svc.View(ctx, h.reader(t), p, jobID); code(err) != model.Unsupported {
		t.Fatalf("view: %v", err)
	}
	if _, err := h.svc.List(ctx, h.writer(t), p, model.ID{}, 5); code(err) != model.Forbidden {
		t.Fatalf("scope must come before the capability check: %v", err)
	}
	if _, err := h.svc.View(ctx, h.reader(t), h.f.project2, jobID); code(err) != model.NotFound {
		t.Fatalf("scope must come before the capability check: %v", err)
	}
}

func TestRunAttemptsAreOrderedAndOwnedCopies(t *testing.T) {
	st := mustReduce(t, jobs.JobState{}, ev(runA, att2, "manual.a", 2, 2, "succeeded", hm(1, 1, 0), new(hm(1, 1, 30))))
	st = mustReduce(t, st, ev(runA, att1, "manual.a", 1, 1, "failed", hm(1, 0, 0), new(hm(1, 0, 10))))
	run, attempts, ok := st.RunAttempts(runA)
	if !ok || len(attempts) != 2 || attempts[0].ID != att1 || attempts[1].ID != att2 || run.Final != att2 {
		t.Fatalf("%+v %+v", run, attempts)
	}
	if _, none, ok := st.RunAttempts(model.ID{0xdd}); ok || none != nil {
		t.Fatal("an unknown run was found")
	}
	attempts[0].Events[0].Sequence = 99
	run.Attempts[0] = model.ID{0xff}
	again, attempts2, _ := st.RunAttempts(runA)
	if attempts2[0].Events[0].Sequence != 1 || again.Attempts[0] != att1 {
		t.Fatal("RunAttempts handed out the state's own slices")
	}
	if !bytes.Equal(again.ID[:], runA[:]) {
		t.Fatal("run identity")
	}
}

// Declared evidence loss is annotated on every read, and only this projects

// Declared evidence loss is annotated on every read, and only this project's
// loss: a verdict that rests on evidence a gap may have swallowed is unknown,
// never a clean success, and another organization's gap changes nothing here.
func TestJobReadsAnnotateOnlyThisProjectsEvidenceGaps(t *testing.T) {
	e := seedList(t)
	ctx := context.Background()
	foreign := model.EvidenceGap{Org: e.org2, Project: e.project2, Group: model.ID{0xA2}, After: 2, Through: 3, Count: 1, Start: hm(11, 2, 0), End: hm(11, 4, 0), Signals: []model.Kind{model.JobAttempt}, Reason: "exporter_connectivity", RecordedAt: hm(11, 5, 0)}
	if _, err := e.f.app.Control.RecordEvidenceGap(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	before, err := e.svc.View(ctx, e.reader, e.project, jobRecovered)
	if err != nil || before.Report.Health.Status != jobs.StatusSucceeded || len(before.Report.Intervals) != 0 {
		t.Fatalf("another organization's gap leaked: %+v %v", before.Report.Health, err)
	}
	gap, err := e.f.app.Control.RecordEvidenceGap(ctx, model.EvidenceGap{Org: e.org, Project: e.project, Group: model.ID{0xA1}, After: 2, Through: 3, Count: 1, Start: hm(11, 2, 0), End: hm(11, 4, 0), Signals: []model.Kind{model.JobAttempt}, Reason: "exporter_connectivity", RecordedAt: hm(11, 5, 0)})
	if err != nil {
		t.Fatal(err)
	}
	view, err := e.svc.View(ctx, e.reader, e.project, jobRecovered)
	if err != nil {
		t.Fatal(err)
	}
	if view.Report.Health.Status != jobs.StatusUnknown || view.Report.Health.Complete || len(view.Report.Intervals) != 1 || view.Report.Intervals[0].ID != gap.ID || len(view.Report.Health.Evidence.Gaps) != 1 {
		t.Fatalf("view does not carry the committed loss: %+v intervals %+v", view.Report.Health, view.Report.Intervals)
	}
	page, err := e.svc.List(ctx, e.reader, e.project, model.ID{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range page.Jobs {
		if s.Job == jobRecovered && (s.Health.Status != jobs.StatusUnknown || s.Health.Complete) {
			t.Fatalf("listing hides the committed loss: %+v", s.Health)
		}
	}
}

// The service filters the gaps a store returns itself: another organization's
// loss, another project's loss and loss of a signal that is not job evidence
// never annotate a job, whatever the store hands back.
type gapStore struct {
	*jobs.ControlStore
	extra []model.EvidenceGap
}

func (g gapStore) Gaps(ctx context.Context, scope auth.Scope, project model.ID) ([]model.EvidenceGap, error) {
	base, err := g.ControlStore.Gaps(ctx, scope, project)
	return append(base, g.extra...), err
}

func TestJobReadsFilterStoreGapsToThisOrgProjectAndSignal(t *testing.T) {
	e := seedList(t)
	ctx := context.Background()
	control, err := jobs.NewControlStore(e.f.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	covering := func(org, project model.ID, signals ...model.Kind) model.EvidenceGap {
		return model.EvidenceGap{ID: model.NewID(), Org: org, Project: project, Group: model.ID{0xA1}, After: 2, Through: 3, Count: 1, Start: hm(11, 2, 0), End: hm(11, 4, 0), Signals: signals, Reason: "exporter_connectivity", RecordedAt: hm(11, 5, 0)}
	}
	svc, err := jobs.New(gapStore{ControlStore: control, extra: []model.EvidenceGap{
		covering(e.org2, e.project, model.JobAttempt),
		covering(e.org, e.project2, model.JobAttempt),
		covering(e.org, e.project, model.Metric),
	}}, e.f.app.Auth, e.clock)
	if err != nil {
		t.Fatal(err)
	}
	view, err := svc.View(ctx, e.reader, e.project, jobRecovered)
	if err != nil || view.Report.Health.Status != jobs.StatusSucceeded || len(view.Report.Intervals) != 0 {
		t.Fatalf("a gap that is not this project's job evidence annotated the job: %+v %+v %v", view.Report.Health, view.Report.Intervals, err)
	}
	page, err := svc.List(ctx, e.reader, e.project, model.ID{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range page.Jobs {
		if s.Job == jobRecovered && s.Health.Status != jobs.StatusSucceeded {
			t.Fatalf("listing annotated by a foreign gap: %+v", s.Health)
		}
	}
}

// A committed book whose own state names another organization is corrupt, not
// a job of this scope: the listing refuses it instead of showing it.
func TestJobListRefusesABookWhoseStateNamesAnotherOrganization(t *testing.T) {
	e := seedList(t)
	ctx := context.Background()
	bad := model.ID{0x50, 9}
	state, err := json.Marshal(map[string]any{"version": model.Revision(1), "org": e.org2, "project": e.project, "job": bad})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := json.Marshal(ctl.JobRecord{Org: e.org, Project: e.project, Job: bad, Version: 1, State: state})
	if err != nil {
		t.Fatal(err)
	}
	if err = e.f.app.Control.Update(ctx, func(st *ctl.State) error {
		st.JobBooks[e.org.String()+":"+e.project.String()+":"+bad.String()] = rec
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = e.svc.List(ctx, e.reader, e.project, model.ID{}, 10); code(err) != model.Corrupt {
		t.Fatalf("a foreign-organization state was listed: %v", err)
	}
}
