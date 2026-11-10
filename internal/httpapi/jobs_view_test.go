// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/jobs"
	"soundpost/internal/model"
)

// These tests drive the real handlers over real HTTPS with real sessions
// against the real application's committed durable job books: the evidence is
// committed through the committed jobs.Service (ApplyAttempt / ObserveSchedule)
// exactly as a journal worker would, and read back through POST
// /api/v1/jobs/list and /api/v1/jobs/view. NOT covered here: the SDK-to-backend
// path (no committed worker turns ingested job_attempt records into job books).

type jobEnv struct {
	*isoEnv
	srv   *httptest.Server
	index uint64
}

func newJobEnv(t *testing.T, reader httpapi.JobReader, useApp bool) *jobEnv {
	t.Helper()
	e := &jobEnv{isoEnv: newIsoEnv(t)}
	if useApp {
		reader = e.app.Jobs
	}
	h := httpapi.NewJobs(reader)
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) { httpapi.RegisterJobRoutes(mux, e.app.Auth, h) }).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *jobEnv) post(who person, path string, body any) (int, []byte) {
	e.t.Helper()
	return (&evEnv{isoEnv: e.isoEnv, srv: e.srv}).post(who, path, body, nil)
}

func (e *jobEnv) list(who person, body map[string]any) (int, []byte) {
	return e.post(who, "/api/v1/jobs/list", body)
}
func (e *jobEnv) view(who person, body map[string]any) (int, []byte) {
	return e.post(who, "/api/v1/jobs/view", body)
}

func listBody(org, project model.ID) map[string]any {
	return map[string]any{"org": org.String(), "project": project.String()}
}
func viewBody(org, project, job model.ID) map[string]any {
	return map[string]any{"org": org.String(), "project": project.String(), "job": job.String()}
}

func decodeJobView(t *testing.T, raw []byte) httpapi.JobView {
	t.Helper()
	var v httpapi.JobView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("not a job view: %v\n%s", err, raw)
	}
	return v
}
func decodeJobList(t *testing.T, raw []byte) httpapi.JobsListView {
	t.Helper()
	var v httpapi.JobsListView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("not a job list: %v\n%s", err, raw)
	}
	return v
}

var jobEpoch = model.ID{0x77}

// apply commits one attempt event through the committed service as the writer.
func (e *jobEnv) apply(writer auth.Scope, project, job, run, attempt model.ID, schedule string, ordinal, seq uint64, state string, observed model.UnixNano, terminal *model.UnixNano) model.Cursor {
	e.t.Helper()
	e.index++
	ev := model.JobAttemptEvent{Job: job, Run: run, Attempt: attempt, Schedule: schedule, Ordinal: model.Uint64(ordinal), Epoch: jobEpoch, Sequence: model.Uint64(seq), State: state, Observed: observed, Terminal: terminal}
	cursor := model.Cursor{Group: model.ID{0xA7}, Index: model.Uint64(e.index)}
	if _, _, err := e.app.Jobs.ApplyAttempt(context.Background(), writer, jobs.AttemptEvidence{Project: project, Cursor: cursor, Record: model.ID{0xB7, byte(e.index)}, Event: ev}); err != nil {
		e.t.Fatalf("apply %s: %v", state, err)
	}
	return cursor
}

func at(base time.Time, d time.Duration) model.UnixNano {
	return model.UnixNano(base.Add(d).UnixNano())
}

type jobWorld struct {
	org, project, sibling                    model.ID
	reader, writer, outsider, writeOnly, ung person
	write                                    auth.Scope
	base                                     time.Time
}

// newJobWorld is one org with two projects: a reader and a writer on `project`,
// a user granted nothing on `sibling`, and an outsider in another org.
func newJobWorld(e *jobEnv) *jobWorld {
	w := &jobWorld{project: model.NewID(), sibling: model.NewID(), base: time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)}
	w.org = e.org("jobs org", w.project, w.sibling)
	w.reader = e.user(w.org, "jobs-reader@example.test")
	e.grant(w.org, w.reader, w.project, true, auth.Read)
	w.writer = e.user(w.org, "jobs-writer@example.test")
	e.grant(w.org, w.writer, w.project, true, auth.PolicyWrite)
	w.writeOnly = w.writer
	w.ung = e.user(w.org, "jobs-ungranted@example.test")
	w.outsider = e.user(e.org("jobs other org", model.NewID()), "jobs-outsider@example.test")
	var err error
	if w.write, err = e.scope(w.writer, w.org, w.project, auth.PolicyWrite); err != nil {
		e.t.Fatal(err)
	}
	return w
}

var (
	jobJourney   = model.ID{0x11, 1}
	jobCancelled = model.ID{0x11, 2}
	jobStale     = model.ID{0x11, 3}
	jobOutage    = model.ID{0x11, 6}
	jobOverlap   = model.ID{0x11, 4}
	jobFold      = model.ID{0x11, 5}
	jobAdjacent  = model.ID{0x11, 8}
	run1, run2   = model.ID{0x21, 1}, model.ID{0x21, 2}
	rA, rB       = model.ID{0x21, 3}, model.ID{0x21, 4}
	att          = func(n byte) model.ID { return model.ID{0x31, n} }
)

// seedJourney commits attempt start -> failure -> retry -> success, then the
// next schedule's success, then a late failure of the earlier occurrence, and
// returns the origin cursor of the last evidence applied.
func (e *jobEnv) seedJourney(w *jobWorld) (occ1, occ2 string, last model.Cursor) {
	occ1 = jobs.OccurrenceKey("UTC", at(w.base, 0), 0)
	occ2 = jobs.OccurrenceKey("UTC", at(w.base, time.Hour), 0)
	p, j := w.project, jobJourney
	e.apply(w.write, p, j, run1, att(1), occ1, 1, 1, "started", at(w.base, 0), nil)
	e.apply(w.write, p, j, run1, att(1), occ1, 1, 2, "failed", at(w.base, 0), new(at(w.base, 10*time.Second)))
	e.apply(w.write, p, j, run1, att(2), occ1, 2, 1, "started", at(w.base, 20*time.Second), nil)
	e.apply(w.write, p, j, run1, att(2), occ1, 2, 2, "succeeded", at(w.base, 20*time.Second), new(at(w.base, 40*time.Second)))
	e.apply(w.write, p, j, run2, att(3), occ2, 1, 1, "started", at(w.base, time.Hour), nil)
	e.apply(w.write, p, j, run2, att(3), occ2, 1, 2, "succeeded", at(w.base, time.Hour), new(at(w.base, time.Hour+5*time.Second)))
	// A late failure of the FIRST occurrence: a third attempt of run 1 whose
	// result reaches the journal only after run 2 succeeded.
	last = e.apply(w.write, p, j, run1, att(4), occ1, 3, 1, "failed", at(w.base, 50*time.Second), new(at(w.base, 55*time.Second)))
	return
}

func TestJobViewReportsTheJourneyTruthfully(t *testing.T) {
	e := newJobEnv(t, nil, true)
	w := newJobWorld(e)
	occ1, occ2, last := e.seedJourney(w)

	status, raw := e.view(w.reader, viewBody(w.org, w.project, jobJourney))
	if status != 200 {
		t.Fatalf("view: %d %s", status, raw)
	}
	v := decodeJobView(t, raw)
	if v.Permission != "telemetry.read" || v.State != httpapi.StateIncomplete && v.State != httpapi.StateReady || v.Org != w.org || v.Project != w.project || v.Job != jobJourney {
		t.Fatalf("header: %s", raw)
	}
	// The committed source: job state version 7 (one per applied evidence) and
	// the origin cursor of the newest attempt evidence.
	if v.Source == nil || v.Source.Version != 7 || v.Source.Cursor == nil || *v.Source.Cursor != last {
		t.Fatalf("source %+v want version 7 cursor %+v", v.Source, last)
	}
	// Current job health comes from the newest occurrence; the late old failure
	// did not overwrite it.
	if v.Health == nil || v.Health.Status != jobs.StatusSucceeded || v.Health.Evidence.Run == nil || *v.Health.Evidence.Run != run2 || v.Health.Evidence.Occurrence != occ2 {
		t.Fatalf("health: %+v", v.Health)
	}
	if v.LatestOccurrence != occ2 || v.TotalRuns != 2 || v.TotalAttempts != 4 || len(v.Runs) != 2 || v.RunsTruncation != nil {
		t.Fatalf("runs: latest %q total %d/%d shown %d", v.LatestOccurrence, v.TotalRuns, v.TotalAttempts, len(v.Runs))
	}
	byID := map[model.ID]httpapi.RunView{}
	for _, r := range v.Runs {
		byID[r.ID] = r
	}
	newer, older := byID[run2], byID[run1]
	if v.Runs[0].ID != run2 || newer.Status != jobs.RunSucceeded || !newer.BasisOfHealth || newer.SupersededBy != "" {
		t.Fatalf("newest run: %+v", newer)
	}
	// The older run's own status stays failed (its final attempt failed late),
	// it is history, not the basis of health, and a newer occurrence supersedes it.
	if older.Status != jobs.RunFailed || older.Recovered || older.BasisOfHealth || older.SupersededBy != occ2 || older.AttemptCount != 3 || older.FailedAttempts != 2 || older.Occurrence.Key != occ1 || !older.Occurrence.Scheduled {
		t.Fatalf("older run: %+v", older)
	}

	// The selected run lists every attempt: the failed ones stay failed.
	body := viewBody(w.org, w.project, jobJourney)
	body["run"] = run1.String()
	status, raw = e.view(w.reader, body)
	if status != 200 {
		t.Fatalf("run view: %d %s", status, raw)
	}
	rv := decodeJobView(t, raw)
	if rv.Run == nil || rv.Run.ID != run1 || len(rv.Run.Attempts) != 3 {
		t.Fatalf("run detail: %s", raw)
	}
	states := []jobs.AttemptState{}
	for _, a := range rv.Run.Attempts {
		states = append(states, a.Effective)
	}
	if states[0] != jobs.AttemptFailed || states[1] != jobs.AttemptSucceeded || states[2] != jobs.AttemptFailed || rv.Run.Attempts[0].Ordinal != 1 || rv.Run.Attempts[2].Ordinal != 3 {
		t.Fatalf("attempts %v", states)
	}
	first, last3 := rv.Run.Attempts[0], rv.Run.Attempts[2]
	if first.Terminal == nil || first.Terminal.State != jobs.AttemptFailed || first.Final || !last3.Final || first.EventsAccepted != 2 || len(first.Corrections) != 0 {
		t.Fatalf("first attempt: %+v", first)
	}
	if first.AfterNewerOccurrence || last3.AfterNewerOccurrence {
		t.Fatal("event times of the older occurrence are before the newer occurrence, yet flagged after it")
	}

	// Redelivery of an applied (epoch, sequence) under a new record counts nothing.
	e.index++
	dup := model.JobAttemptEvent{Job: jobJourney, Run: run1, Attempt: att(1), Schedule: occ1, Ordinal: 1, Epoch: jobEpoch, Sequence: 2, State: "failed", Observed: at(w.base, 0), Terminal: new(at(w.base, 10*time.Second))}
	if _, outcome, err := e.app.Jobs.ApplyAttempt(context.Background(), w.write, jobs.AttemptEvidence{Project: w.project, Cursor: model.Cursor{Group: model.ID{0xA7}, Index: model.Uint64(e.index)}, Record: model.ID{0xB7, byte(e.index)}, Event: dup}); err != nil || outcome != jobs.Duplicate {
		t.Fatalf("redelivery: %v %v", outcome, err)
	}
	status, raw = e.view(w.reader, body)
	again := decodeJobView(t, raw)
	if status != 200 || again.TotalAttempts != 4 || len(again.Run.Attempts) != 3 || again.Run.Attempts[0].EventsAccepted != 2 {
		t.Fatalf("a duplicate delivery was counted: %s", raw)
	}
	if again.Source.Version != 7 {
		t.Fatalf("a duplicate moved the committed version: %d", again.Source.Version)
	}
}

func TestJobViewCancellationOutageOverlapAndFold(t *testing.T) {
	e := newJobEnv(t, nil, true)
	w := newJobWorld(e)
	p := w.project
	// Explicit cancellation.
	e.apply(w.write, p, jobCancelled, run1, att(1), "manual.c", 1, 1, "cancelled", at(w.base, 0), new(at(w.base, time.Second)))
	// An observer that stopped reporting (outage): its last word is an hour old.
	def := jobs.Definition{Revision: 1, EffectiveFrom: at(w.base, -24*time.Hour), Schedule: &jobs.Schedule{Cron: "0 * * * *", Timezone: "UTC"}}
	old := at(time.Now(), -time.Hour)
	loss := jobs.Interval{ID: model.ID{0x44}, Start: at(w.base, 0), End: at(w.base, time.Minute), Reason: "exporter_disconnected"}
	if _, err := e.app.Jobs.ObserveSchedule(context.Background(), w.write, jobs.ScheduleEvidence{CommandID: model.NewID(), Project: p, Job: jobStale, Observer: model.ID{7}, ObservedAt: old, CompleteThrough: old, Healthy: true, Definition: &def, Incomplete: []jobs.Interval{loss}}); err != nil {
		t.Fatal(err)
	}
	recent := at(time.Now(), -time.Minute)
	if _, err := e.app.Jobs.ObserveSchedule(context.Background(), w.write, jobs.ScheduleEvidence{CommandID: model.NewID(), Project: p, Job: jobOutage, Observer: model.ID{7}, ObservedAt: recent, CompleteThrough: at(time.Now(), -3*time.Hour), Healthy: true, Definition: &def}); err != nil {
		t.Fatal(err)
	}
	// Overlap: run B starts while run A is still running.
	e.apply(w.write, p, jobOverlap, rA, att(1), "manual.a", 1, 1, "started", at(w.base, 0), nil)
	e.apply(w.write, p, jobOverlap, rB, att(2), "manual.b", 1, 1, "started", at(w.base, time.Minute), nil)
	e.apply(w.write, p, jobOverlap, rA, att(1), "manual.a", 1, 2, "succeeded", at(w.base, 0), new(at(w.base, 5*time.Minute)))
	e.apply(w.write, p, jobOverlap, rB, att(2), "manual.b", 1, 2, "succeeded", at(w.base, time.Minute), new(at(w.base, 2*time.Minute)))
	e.apply(w.write, p, jobAdjacent, rA, att(1), "manual.a", 1, 1, "succeeded", at(w.base, 0), new(at(w.base, 10*time.Minute)))
	e.apply(w.write, p, jobAdjacent, rB, att(2), "manual.b", 1, 1, "succeeded", at(w.base, 10*time.Minute), new(at(w.base, 20*time.Minute)))
	// The second instance of a repeated local time.
	foldKey := jobs.OccurrenceKey("America/New_York", at(w.base, 0), 1)
	e.apply(w.write, p, jobFold, run1, att(1), foldKey, 1, 1, "succeeded", at(w.base, 0), new(at(w.base, time.Second)))

	get := func(job model.ID) httpapi.JobView {
		t.Helper()
		status, raw := e.view(w.reader, viewBody(w.org, p, job))
		if status != 200 {
			t.Fatalf("%v: %d %s", job, status, raw)
		}
		return decodeJobView(t, raw)
	}
	if v := get(jobCancelled); v.Health.Status != jobs.StatusCancelled || v.Runs[0].Status != jobs.RunCancelled || v.Observer.ExpectedSchedule || v.Observer.State != "none" || v.Definition != nil || v.DefinitionRevisions != 0 {
		t.Fatalf("cancelled job: %+v %+v definition %+v", v.Health, v.Runs, v.Definition)
	}
	st := get(jobStale)
	// The observer's own (hour-old) word is external evidence that an occurrence was missed; the view passes
	// that verdict through but labels it incomplete and the observer stale.
	if st.Health.Status != jobs.StatusMissed || st.Health.Complete || st.Observer.State != "stale" || !st.Observer.ExpectedSchedule || st.Observer.Evidence == nil || !st.Observer.Evidence.Stale || st.Health.Evidence.Observer == nil {
		t.Fatalf("a stale observer's verdict must be labelled incomplete with stale evidence: %+v %+v", st.Health, st.Observer)
	}
	if st.State != httpapi.StateIncomplete || st.Reason != httpapi.ReasonJobEvidenceIncomplete {
		t.Fatalf("stale observer view state %q/%q", st.State, st.Reason)
	}
	// An outage of the data path: the observer is fresh but cannot attest completeness, so absence is
	// unproven and the job reads unknown, never missed and never recovered.
	out := get(jobOutage)
	if out.Health.Status != jobs.StatusUnknown || out.Health.Complete || out.Observer.State != "fresh" || len(out.Runs) != 0 {
		t.Fatalf("a data-path outage must read unknown: %+v %+v", out.Health, out.Observer)
	}
	absent := false
	for _, r := range out.Health.Reasons {
		absent = absent || r == jobs.ReasonNoEvidence || r == jobs.ReasonAbsenceIncomplete
	}
	if !absent {
		t.Fatalf("outage reasons %v", out.Health.Reasons)
	}
	if st.Loss == nil || st.Loss.Total != 1 || len(st.Loss.Intervals) != 1 || st.Loss.Intervals[0].Reason != "exporter_disconnected" || len(st.Runs) != 0 {
		t.Fatalf("loss: %+v", st.Loss)
	}
	if st.Definition == nil || st.Definition.Schedule == nil || st.Definition.Schedule.Timezone != "UTC" || st.Definition.Overlap != "allow" && st.Definition.Overlap != "" {
		t.Fatalf("definition: %+v", st.Definition)
	}
	ov := get(jobOverlap)
	if len(ov.Runs) != 2 || ov.Runs[0].OverlapCount != 1 || ov.Runs[1].OverlapCount != 1 || ov.Runs[0].Overlaps[0] != ov.Runs[1].ID || ov.Runs[1].Overlaps[0] != ov.Runs[0].ID {
		t.Fatalf("overlap: %+v", ov.Runs)
	}
	if one := get(jobCancelled); one.Runs[0].OverlapCount != 0 || len(one.Runs[0].Overlaps) != 0 {
		t.Fatalf("a lone run overlaps: %+v", one.Runs[0])
	}
	// Runs that merely touch (one ends the instant the next starts) do not overlap.
	if adj := get(jobAdjacent); len(adj.Runs) != 2 || adj.Runs[0].OverlapCount != 0 || adj.Runs[1].OverlapCount != 0 {
		t.Fatalf("touching runs overlap: %+v", adj.Runs)
	}
	if f := get(jobFold); len(f.Runs) != 1 || f.Runs[0].Occurrence.Fold != 1 || !f.Runs[0].Occurrence.Scheduled || f.Runs[0].Occurrence.At == nil {
		t.Fatalf("fold: %+v", f.Runs)
	}
	status, raw := e.list(w.reader, listBody(w.org, w.project))
	l := decodeJobList(t, raw)
	if status != 200 || len(l.Jobs) != 6 {
		t.Fatalf("list: %d %s", status, raw)
	}
	listed := map[model.ID]*jobs.Definition{}
	for _, j := range l.Jobs {
		listed[j.Job] = j.Definition
	}
	if listed[jobStale] == nil || listed[jobOutage] == nil || listed[jobStale].Schedule == nil || listed[jobCancelled] != nil || listed[jobOverlap] != nil || listed[jobFold] != nil {
		t.Fatalf("listed definitions must exist exactly for the jobs an observer defined: %s", raw)
	}
}

func TestJobListIsScopedBoundedAndPaged(t *testing.T) {
	e := newJobEnv(t, nil, true)
	w := newJobWorld(e)
	e.seedJourney(w)
	e.apply(w.write, w.project, jobCancelled, run1, att(1), "manual.c", 1, 1, "cancelled", at(w.base, 0), new(at(w.base, time.Second)))
	e.apply(w.write, w.project, jobOverlap, rA, att(1), "manual.a", 1, 1, "started", at(w.base, 0), nil)

	status, raw := e.list(w.reader, listBody(w.org, w.project))
	if status != 200 {
		t.Fatalf("list: %d %s", status, raw)
	}
	l := decodeJobList(t, raw)
	if l.State != httpapi.StateReady || l.Permission != "telemetry.read" || len(l.Jobs) != 3 || l.More || l.Truncation != nil {
		t.Fatalf("list: %s", raw)
	}
	for _, j := range l.Jobs {
		if j.Definition != nil {
			t.Fatalf("a job with only attempt evidence has no definition (omitted, never a zero one): %s", raw)
		}
	}
	for i := 1; i < len(l.Jobs); i++ {
		if string(l.Jobs[i-1].Job.String()) >= l.Jobs[i].Job.String() {
			t.Fatalf("not in job ID order: %s", raw)
		}
	}
	// Pages are bounded and say so with a typed truncation that resumes exactly.
	body := listBody(w.org, w.project)
	body["limit"] = 2
	_, raw = e.list(w.reader, body)
	first := decodeJobList(t, raw)
	if len(first.Jobs) != 2 || !first.More || first.Truncation == nil || first.Truncation.Reason != "page_limit" || first.Truncation.Shown != 2 || first.Truncation.Next == nil || *first.Truncation.Next != first.Jobs[1].Job {
		t.Fatalf("first page: %s", raw)
	}
	body["after"] = first.Truncation.Next.String()
	_, raw = e.list(w.reader, body)
	second := decodeJobList(t, raw)
	if len(second.Jobs) != 1 || second.More || second.Truncation != nil || second.Jobs[0].Job != l.Jobs[2].Job {
		t.Fatalf("second page: %s", raw)
	}
	for _, limit := range []int{-1, httpapi.MaxJobsPage + 1, 1 << 30} {
		body["limit"] = limit
		if status, raw = e.list(w.reader, body); status != 400 {
			t.Fatalf("limit %d: %d %s", limit, status, raw)
		}
	}
	// An authorized project with no jobs is an empty state, not an error.
	_, raw = e.list(w.reader, listBody(w.org, w.project))
	_ = raw
	other := e.user(w.org, "jobs-sibling-reader@example.test")
	e.grant(w.org, other, w.sibling, true, auth.Read)
	status, raw = e.list(other, listBody(w.org, w.sibling))
	if empty := decodeJobList(t, raw); status != 200 || empty.State != httpapi.StateEmpty || empty.Reason != httpapi.ReasonJobNoJobs || len(empty.Jobs) != 0 {
		t.Fatalf("empty project: %d %s", status, raw)
	}

	// Runs are bounded the same way.
	vb := viewBody(w.org, w.project, jobJourney)
	vb["runs_limit"] = 1
	_, raw = e.view(w.reader, vb)
	v := decodeJobView(t, raw)
	if len(v.Runs) != 1 || v.Runs[0].ID != run2 || v.RunsTruncation == nil || v.RunsTruncation.Reason != "runs_limit" || v.RunsTruncation.Shown != 1 || v.RunsTruncation.Total == nil || *v.RunsTruncation.Total != 2 || v.TotalRuns != 2 {
		t.Fatalf("bounded runs: %s", raw)
	}
	for _, limit := range []int{-1, httpapi.MaxJobRuns + 1} {
		vb["runs_limit"] = limit
		if status, raw = e.view(w.reader, vb); status != 400 {
			t.Fatalf("runs_limit %d: %d %s", limit, status, raw)
		}
	}
	// A selected run that does not exist is the same not-found as a missing job.
	delete(vb, "runs_limit")
	vb["run"] = model.NewID().String()
	status, raw = e.view(w.reader, vb)
	missingRun := denial(t, status, raw)
	status, raw = e.view(w.reader, viewBody(w.org, w.project, model.NewID()))
	if status != 404 || denial(t, status, raw) != missingRun {
		t.Fatalf("missing run vs missing job: %q vs %q", missingRun, denial(t, status, raw))
	}
}

// Scope first: every wrong-scope variant is one indistinguishable not-found, and
// a body cannot widen what the credential grants.
func TestJobReadsAreScopeFirstIndistinguishableAndNeverWidened(t *testing.T) {
	e := newJobEnv(t, nil, true)
	w := newJobWorld(e)
	e.seedJourney(w)
	other := e.user(w.org, "jobs-other-reader@example.test")
	e.grant(w.org, other, w.sibling, true, auth.Read)

	type target struct {
		who      person
		org, prj model.ID
		job      model.ID
	}
	var want string
	for name, c := range map[string]target{
		"other org's member naming org A": {w.outsider, w.org, w.project, jobJourney},
		"ungranted sibling project":       {w.reader, w.org, w.sibling, jobJourney},
		"member without any grant":        {w.ung, w.org, w.project, jobJourney},
		"policy.write without read":       {w.writeOnly, w.org, w.project, jobJourney},
		"guessed project":                 {w.reader, w.org, model.NewID(), jobJourney},
		"guessed org":                     {w.reader, model.NewID(), w.project, jobJourney},
		"project under another org":       {w.reader, w.outsider.Session.User, w.project, jobJourney},
		"missing job":                     {w.reader, w.org, w.project, model.NewID()},
		"sibling reader on A's project":   {other, w.org, w.project, jobJourney},
		"job of A under the sibling":      {other, w.org, w.sibling, jobJourney},
	} {
		for route, call := range map[string]func() (int, []byte){
			"view": func() (int, []byte) { return e.view(c.who, viewBody(c.org, c.prj, c.job)) },
			"list": func() (int, []byte) { return e.list(c.who, listBody(c.org, c.prj)) },
		} {
			if name == "job of A under the sibling" {
				continue // a granted project: an absent job / empty listing there is not a denial; the missing-job case below covers it
			}
			status, raw := call()
			if route == "list" && name == "missing job" {
				continue
			}
			if status != 404 {
				t.Fatalf("%s %s: %d %s", route, name, status, raw)
			}
			got := denial(t, status, raw)
			if want == "" {
				want = got
			} else if got != want {
				t.Fatalf("%s %s distinguishable: %q vs %q", route, name, got, want)
			}
		}
	}
	// An absent job in a project the caller does read is that same not-found.
	status, raw := e.view(other, viewBody(w.org, w.sibling, jobJourney))
	if status != 404 || denial(t, status, raw) != want {
		t.Fatalf("absent job in a readable project: %d %s", status, raw)
	}
	// A session without credentials is unauthenticated, not not-found.
	if status, _ = e.view(person{}, viewBody(w.org, w.project, jobJourney)); status != 401 {
		t.Fatalf("anonymous: %d", status)
	}

	// A body cannot name another scope, widen the permission or elevate.
	for name, mutate := range map[string]func(map[string]any){
		"permission":   func(b map[string]any) { b["permission"] = "org.admin" },
		"policy.write": func(b map[string]any) { b["permission"] = "policy.write" },
		"raw":          func(b map[string]any) { b["permission"] = "raw.read" },
		"elevation":    func(b map[string]any) { b["elevation"] = model.NewID().String() },
		"projects":     func(b map[string]any) { b["projects"] = []string{w.project.String(), w.sibling.String()} },
		"source":       func(b map[string]any) { b["source"] = model.NewID().String() },
		"scope":        func(b map[string]any) { b["scope"] = map[string]any{"org": w.org.String()} },
		"principal":    func(b map[string]any) { b["principal"] = w.writer.ID.String() },
		"zero job":     func(b map[string]any) { b["job"] = model.ID{}.String() },
		"no project":   func(b map[string]any) { delete(b, "project") },
		"no org":       func(b map[string]any) { delete(b, "org") },
	} {
		body := viewBody(w.org, w.project, jobJourney)
		mutate(body)
		if status, raw = e.view(w.reader, body); status == 200 {
			t.Fatalf("%s: accepted: %s", name, raw)
		}
		lb := listBody(w.org, w.project)
		mutate(lb)
		if _, listable := lb["job"]; !listable {
			if status, raw = e.list(w.reader, lb); status == 200 && name != "zero job" {
				t.Fatalf("list %s: accepted: %s", name, raw)
			}
		}
	}
	// Revoking the grant ends the very next read.
	e.grant(w.org, w.reader, w.project, false, auth.Read)
	if status, raw = e.view(w.reader, viewBody(w.org, w.project, jobJourney)); status != 404 {
		t.Fatalf("revoked reader: %d %s", status, raw)
	}
}

type fakeJobReader struct {
	calls  int
	err    error
	view   jobs.View
	onRead func()
}

func (f *fakeJobReader) List(context.Context, auth.Scope, model.ID, model.ID, int) (jobs.ListPage, error) {
	f.calls++
	if f.onRead != nil {
		f.onRead()
	}
	return jobs.ListPage{}, f.err
}
func (f *fakeJobReader) View(context.Context, auth.Scope, model.ID, model.ID) (jobs.View, error) {
	f.calls++
	if f.onRead != nil {
		f.onRead()
	}
	return f.view, f.err
}

func TestJobViewsAreTypedNotAvailableAfterScope(t *testing.T) {
	for name, reader := range map[string]httpapi.JobReader{"unwired": nil, "unreadable store": &fakeJobReader{err: model.Fail(model.Unsupported)}} {
		e := newJobEnv(t, reader, false)
		p := model.NewID()
		org := e.org("jobs states", p)
		u := e.user(org, "jobs-states@example.test")
		e.grant(org, u, p, true, auth.Read)
		outsider := e.user(e.org("jobs states other", model.NewID()), "jobs-states-out@example.test")
		wantReason := httpapi.ReasonJobServiceNotWired
		if name != "unwired" {
			wantReason = httpapi.ReasonJobStoreNotReadable
		}
		status, raw := e.list(u, listBody(org, p))
		if l := decodeJobList(t, raw); status != 200 || l.State != httpapi.StateNotAvailable || l.Reason != wantReason || len(l.Jobs) != 0 {
			t.Fatalf("%s list: %d %s", name, status, raw)
		}
		status, raw = e.view(u, viewBody(org, p, model.NewID()))
		if v := decodeJobView(t, raw); status != 200 || v.State != httpapi.StateNotAvailable || v.Reason != wantReason || v.Health != nil {
			t.Fatalf("%s view: %d %s", name, status, raw)
		}
		if status, _ = e.view(outsider, viewBody(org, p, model.NewID())); status != 404 {
			t.Fatalf("%s: not_available must not weaken scope: %d", name, status)
		}
		if status, _ = e.list(outsider, listBody(org, p)); status != 404 {
			t.Fatalf("%s: list not_available must not weaken scope: %d", name, status)
		}
	}
	// A reader fault other than unsupported is a typed error, never an empty page.
	f := &fakeJobReader{err: model.Fail(model.Corrupt)}
	e := newJobEnv(t, f, false)
	p := model.NewID()
	org := e.org("jobs fault", p)
	u := e.user(org, "jobs-fault@example.test")
	e.grant(org, u, p, true, auth.Read)
	if status, raw := e.list(u, listBody(org, p)); status == 200 {
		t.Fatalf("a corrupt store read answered 200: %s", raw)
	}
}

// The wire carries only closed, structural keys: nothing that could hold raw
// exception, message or telemetry text, and cause links are IDs only.
func TestJobViewsCarryNoRawTextOnlyClosedStructure(t *testing.T) {
	e := newJobEnv(t, nil, true)
	w := newJobWorld(e)
	e.seedJourney(w)
	cause, errID := model.NewID(), model.NewID()
	e.index++
	ev := model.JobAttemptEvent{Job: jobCancelled, Run: run1, Attempt: att(1), Schedule: "manual.c", Ordinal: 1, Epoch: jobEpoch, Sequence: 1, State: "failed", Observed: at(w.base, 0), Terminal: new(at(w.base, time.Second)), CauseTrace: &cause, CauseError: &errID}
	if _, _, err := e.app.Jobs.ApplyAttempt(context.Background(), w.write, jobs.AttemptEvidence{Project: w.project, Cursor: model.Cursor{Group: model.ID{0xA7}, Index: model.Uint64(e.index)}, Record: model.ID{0xB7, byte(e.index)}, Event: ev}); err != nil {
		t.Fatal(err)
	}
	// A correction carries the operator's reason; it is the only free text.
	if _, err := e.app.Jobs.Correct(context.Background(), w.write, jobs.Correction{CommandID: model.NewID(), Project: w.project, Job: jobCancelled, ExpectedVersion: 1, Attempt: att(1), Version: 1, State: jobs.AttemptSucceeded, Reason: "verified manually <b>ok</b>"}); err != nil {
		t.Fatal(err)
	}
	vb := viewBody(w.org, w.project, jobCancelled)
	vb["run"] = run1.String()
	status, raw := e.view(w.reader, vb)
	if status != 200 {
		t.Fatalf("%d %s", status, raw)
	}
	v := decodeJobView(t, raw)
	a := v.Run.Attempts[0]
	if a.CauseTrace == nil || *a.CauseTrace != cause || a.CauseError == nil || *a.CauseError != errID {
		t.Fatalf("cause links must be IDs: %+v", a)
	}
	if a.Terminal == nil || a.Terminal.State != jobs.AttemptFailed || a.Effective != jobs.AttemptSucceeded || len(a.Corrections) != 1 || a.Corrections[0].Reason != "verified manually <b>ok</b>" || a.Corrections[0].Actor != w.writer.ID {
		t.Fatalf("a correction keeps the original terminal and is audited: %+v", a)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for _, k := range strings.Fields(`org project job state reason permission evaluated_at_ns source version cursor group index erased definition revision effective_from_ns schedule cron timezone
grace_ns max_runtime_ns observer_stale_after_ns overlap definition_revisions health status as_of_ns complete reasons evidence occurrence run attempt attempt_state attempt_count
expected_at_ns window_end_ns cause_trace cause_error definition_revision observer gaps skipped_local_times observed_at_ns complete_through_ns healthy stale expected_schedule loss intervals id start_ns end_ns total
affects_current_health truncation shown next total_runs total_attempts compaction runs through_ns latest_occurrence runs_truncation sections name
key scheduled at_ns fold status recovered first_started_ns final_attempt attempt_count failed_attempts basis_of_health superseded_by overlaps overlap_count attempts ordinal started observed_ns terminal at_ns effective corrections
actor command events_accepted final after_newer_occurrence`) {
		allowed[k] = true
	}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if !allowed[k] {
					t.Fatalf("unexpected key %q at %s", k, path)
				}
				walk(path+"."+k, child)
			}
		case []any:
			for _, child := range x {
				walk(path+"[]", child)
			}
		}
	}
	walk("$", doc)
	if strings.Contains(string(raw), "stack") || strings.Contains(string(raw), "exception") || strings.Contains(string(raw), "message") {
		t.Fatalf("raw text vocabulary in a job view: %s", raw)
	}
}

// An erased history is an honest empty state; and the response is fenced once
// more after the read: a grant revoked while the view was being produced ends
// in the same not-found, never in the data.
func TestJobViewErasedHistoryAndFinalRevalidation(t *testing.T) {
	f := &fakeJobReader{}
	e := newJobEnv(t, f, false)
	p := model.NewID()
	org := e.org("jobs fence", p)
	u := e.user(org, "jobs-fence@example.test")
	e.grant(org, u, p, true, auth.Read)
	job := model.NewID()
	f.view = jobs.View{Erased: true, Report: jobs.Report{Version: 3, State: jobs.JobState{Version: 3, Org: org, Project: p, Job: job}, Health: jobs.Health{Status: jobs.StatusUnknown, Reasons: []jobs.Reason{jobs.ReasonNoEvidence}}}}
	status, raw := e.view(u, viewBody(org, p, job))
	v := decodeJobView(t, raw)
	if status != 200 || v.State != httpapi.StateEmpty || v.Reason != httpapi.ReasonJobHistoryErased || !v.Erased || len(v.Runs) != 0 || v.Source == nil || v.Source.Version != 3 {
		t.Fatalf("erased history: %d %s", status, raw)
	}
	f.onRead = func() { e.grant(org, u, p, false, auth.Read) }
	if status, raw = e.view(u, viewBody(org, p, job)); status != 404 {
		t.Fatalf("a grant revoked during the read still released the view: %d %s", status, raw)
	}
	e.grant(org, u, p, true, auth.Read)
	if status, raw = e.list(u, listBody(org, p)); status != 404 {
		t.Fatalf("a grant revoked during the listing still released it: %d %s", status, raw)
	}
}
