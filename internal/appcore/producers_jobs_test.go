// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// jobRig is a served node with a real source credential for one project, a
// human reader (telemetry.read) and the real HTTP surface (ingest and job views).
type jobRig struct {
	*workerNode
	server   *httptest.Server
	source   string
	sourceID model.ID
	producer model.ID
	resource model.Resource
	csrf     string
	session  string
	base     time.Time
	epoch    model.ID
}

func newJobRig(t *testing.T) *jobRig {
	t.Helper()
	n := newWorkerNode(t)
	r := &jobRig{workerNode: n, producer: model.NewID(), base: time.Now().Add(-time.Hour).Truncate(time.Second), epoch: model.NewID(), sourceID: model.NewID()}
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	r.resource = model.Resource{Service: service, Environment: environment, Build: build, Instance: "job-host", Labels: model.Labels{}}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.JobAttempt}, Resources: model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"job-host"}}, RetentionDays: map[model.Kind]uint32{model.JobAttempt: 30}, MaxBytes: 8 << 20, MaxSeries: 100, Expires: model.UnixNano(time.Now().Add(20 * time.Minute).UnixNano())}
	issued, err := n.app.Auth.OnboardSource(n.ctx, n.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: n.org, Project: n.project, Source: r.sourceID, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "job producer wiring"})
	if err != nil {
		t.Fatal(err)
	}
	r.source = issued.Credential
	session, err := n.app.Auth.Login(n.ctx, "workers@example.test", "worker wiring password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	r.session, r.csrf = session.Token, session.CSRF
	r.server = httptest.NewTLSServer(httpapi.NewServer("", n.app.Auth, nil, n.app.Register).Handler)
	t.Cleanup(r.server.Close)
	return r
}

func (r *jobRig) at(d time.Duration) model.UnixNano { return model.UnixNano(r.base.Add(d).UnixNano()) }

// event builds one attempt event; the terminal instant is set for terminal states.
func (r *jobRig) event(job, run, attempt model.ID, occurrence string, ordinal, sequence uint64, state string, observed time.Duration, terminal time.Duration) model.JobAttemptEvent {
	e := model.JobAttemptEvent{Job: job, Run: run, Attempt: attempt, Schedule: occurrence, Ordinal: model.Uint64(ordinal), Epoch: r.epoch, Sequence: model.Uint64(sequence), State: state, Observed: r.at(observed)}
	if state != "started" {
		t := r.at(terminal)
		e.Terminal = &t
	}
	return e
}

// ingest sends one event as its own batch through the real ingest route with the
// source credential. Every call is a new batch and a new record ID, like an SDK
// retry that re-sends an event it never saw acknowledged.
func (r *jobRig) ingest(e model.JobAttemptEvent) {
	r.t.Helper()
	if status, body := r.send(e); status != 200 {
		r.t.Fatalf("ingest answered %d: %s", status, body)
	}
}

// send is ingest without the success requirement: it returns the HTTP status.
func (r *jobRig) send(e model.JobAttemptEvent) (int, []byte) {
	r.t.Helper()
	record := model.Record{ID: model.NewID(), Kind: model.JobAttempt, ObservedAt: e.Observed, Resource: r.resource, Payload: model.Payload{Job: &e}}
	batch := model.Batch{Version: 1, Project: r.project, Source: model.ID{}, Producer: r.producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{record}}
	var err error
	batch.Source = r.sourceID
	batch.RouteSlot, err = model.OwnerSlot(r.org, r.project, batch.Source, r.producer, record)
	if err != nil {
		r.t.Fatal(err)
	}
	raw, _ := json.Marshal(batch)
	req, _ := http.NewRequest("POST", r.server.URL+"/ingest/v1/batches", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+r.source)
	resp, err := r.server.Client().Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func (r *jobRig) post(path string, body any) (int, []byte) {
	r.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", r.server.URL+path, bytes.NewReader(raw))
	req.Header.Set("Cookie", "__Host-soundpost="+r.session)
	req.Header.Set("X-CSRF-Token", r.csrf)
	req.Header.Set("Origin", r.server.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.server.Client().Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (r *jobRig) list() httpapi.JobsListView {
	r.t.Helper()
	code, raw := r.post("/api/v1/jobs/list", map[string]any{"org": r.org.String(), "project": r.project.String()})
	var v httpapi.JobsListView
	if code != 200 || json.Unmarshal(raw, &v) != nil {
		r.t.Fatalf("jobs/list %d: %s", code, raw)
	}
	return v
}

func (r *jobRig) view(job, run model.ID) httpapi.JobView {
	r.t.Helper()
	body := map[string]any{"org": r.org.String(), "project": r.project.String(), "job": job.String()}
	if run != (model.ID{}) {
		body["run"] = run.String()
	}
	code, raw := r.post("/api/v1/jobs/view", body)
	var v httpapi.JobView
	if code != 200 || json.Unmarshal(raw, &v) != nil {
		r.t.Fatalf("jobs/view %d: %s", code, raw)
	}
	return v
}

// commands lists the committed job commands of the project with their principals.
func (r *jobRig) commands() []control.JobCommandEntry {
	r.t.Helper()
	var out []control.JobCommandEntry
	err := r.app.Control.View(r.ctx, func(st model.ControlState) error {
		for _, raw := range st.JobBooks {
			var rec control.JobRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				return err
			}
			if rec.Org == r.org && rec.Project == r.project {
				out = append(out, rec.Commands...)
			}
		}
		return nil
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return out
}

func (r *jobRig) humanRead() auth.Scope {
	r.t.Helper()
	cred, err := r.app.Auth.Authenticate(r.ctx, r.token)
	if err != nil {
		r.t.Fatal(err)
	}
	scope, err := r.app.Auth.Authorize(r.ctx, cred, r.org, []model.ID{r.project}, auth.Read)
	if err != nil {
		r.t.Fatal(err)
	}
	return scope
}

// scenario ingests: run1 attempt1 started -> failed, attempt2 (retry) started ->
// succeeded; run2 attempt3 started -> cancelled; and a redelivery of attempt2's
// terminal event in a new batch. It returns the ids.
type jobScenario struct{ job, run1, run2, att1, att2, att3 model.ID }

const scenarioApplied = 6 // distinct events; the redelivery is the 7th journal row

func (r *jobRig) ingestScenario() jobScenario {
	s := jobScenario{job: model.NewID(), run1: model.NewID(), run2: model.NewID(), att1: model.NewID(), att2: model.NewID(), att3: model.NewID()}
	r.ingest(r.event(s.job, s.run1, s.att1, "job-run-1", 1, 1, "started", 0, 0))
	r.ingest(r.event(s.job, s.run1, s.att1, "job-run-1", 1, 2, "failed", 0, 2*time.Second))
	r.ingest(r.event(s.job, s.run1, s.att2, "job-run-1", 2, 1, "started", 3*time.Second, 0))
	succeeded := r.event(s.job, s.run1, s.att2, "job-run-1", 2, 2, "succeeded", 3*time.Second, 5*time.Second)
	r.ingest(succeeded)
	r.ingest(succeeded)
	r.ingest(r.event(s.job, s.run2, s.att3, "job-run-2", 1, 1, "started", 10*time.Second, 0))
	r.ingest(r.event(s.job, s.run2, s.att3, "job-run-2", 1, 2, "cancelled", 10*time.Second, 11*time.Second))
	return s
}

func (r *jobRig) workers(extra ...appcore.Producer) *appcore.Workers {
	r.t.Helper()
	w, err := r.app.NewWorkers(r.config(func(c *appcore.WorkerConfig) { c.Producers = extra }))
	if err != nil {
		r.t.Fatal(err)
	}
	return w
}

func TestJobProducerTurnsIngestedAttemptsIntoJobBooks(t *testing.T) {
	r := newJobRig(t)
	s := r.ingestScenario()
	if got := r.list(); len(got.Jobs) != 0 {
		t.Fatalf("setup: jobs exist before any pass: %+v", got.Jobs)
	}
	w := r.workers(r.app.JobProducer())
	first := r.tick(w)
	if !first.Leader || first.Produced != scenarioApplied {
		t.Fatalf("first pass produced %d, want %d (the redelivery must not count): %+v", first.Produced, scenarioApplied, first)
	}

	list := r.list()
	if len(list.Jobs) != 1 || list.Jobs[0].Job != s.job || list.Jobs[0].Runs != 2 || list.Jobs[0].Attempts != 3 {
		t.Fatalf("job list does not show the ingested job: %+v", list.Jobs)
	}
	view := r.view(s.job, model.ID{})
	if view.TotalRuns != 2 || view.TotalAttempts != 3 || len(view.Runs) != 2 || view.Health == nil {
		t.Fatalf("job view: %+v", view)
	}
	byID := map[model.ID]httpapi.RunView{}
	for _, run := range view.Runs {
		byID[run.ID] = run
	}
	if run := byID[s.run1]; !run.Recovered || run.AttemptCount != 2 || run.FailedAttempts != 1 || run.FinalAttempt != s.att2 {
		t.Fatalf("run 1 should be a retry that recovered: %+v", run)
	}
	detail := r.view(s.job, s.run2)
	if detail.Run == nil || len(detail.Run.Attempts) != 1 || detail.Run.Attempts[0].ID != s.att3 || detail.Run.Attempts[0].Effective != jobs.AttemptCancelled || detail.Run.Attempts[0].EventsAccepted != 2 {
		t.Fatalf("run 2 should hold one cancelled attempt: %+v", detail.Run)
	}
	retry := r.view(s.job, s.run1)
	if retry.Run == nil || len(retry.Run.Attempts) != 2 {
		t.Fatalf("run 1 attempts: %+v", retry.Run)
	}
	for _, a := range retry.Run.Attempts {
		want := jobs.AttemptFailed
		if a.ID == s.att2 {
			want = jobs.AttemptSucceeded
		}
		if a.Effective != want || a.EventsAccepted != 2 {
			t.Fatalf("attempt %s: effective %s events %d, want %s with 2 events (a redelivery must not double count)", a.ID, a.Effective, a.EventsAccepted, want)
		}
	}
	report, err := r.app.Jobs.Health(r.ctx, r.humanRead(), r.project, s.job)
	if err != nil {
		t.Fatal(err)
	}
	if report.Health.Status != list.Jobs[0].Health.Status || report.Health.Status == "" || len(report.State.Attempts) != 3 {
		t.Fatalf("Health %q disagrees with the listed %q: %+v", report.Health.Status, list.Jobs[0].Health.Status, report.State.Attempts)
	}

	// Every committed job command is the runner's, never a person's.
	commands := r.commands()
	if len(commands) != scenarioApplied {
		t.Fatalf("committed %d job commands, want %d", len(commands), scenarioApplied)
	}
	for _, c := range commands {
		if c.Principal != auth.SystemPrincipal(r.org) || c.Kind != "attempt" || c.Origin == nil {
			t.Fatalf("job command not owned by the system principal with its origin cursor: %+v", c)
		}
	}

	// A second pass changes nothing.
	version := report.State.Version
	second := r.tick(w)
	if second.Produced != 0 {
		t.Fatalf("second pass produced %d", second.Produced)
	}
	again, err := r.app.Jobs.Health(r.ctx, r.humanRead(), r.project, s.job)
	if err != nil || again.State.Version != version || len(r.commands()) != scenarioApplied {
		t.Fatalf("second pass changed the job book: version %d -> %d err %v commands %d", version, again.State.Version, err, len(r.commands()))
	}
}

// A pass is bounded: each call reads at most the bound, and the next call resumes
// after what the previous one covered, so the whole journal is served in full.
func TestJobProducerResumesAfterTheRowsItAlreadyCovered(t *testing.T) {
	r := newJobRig(t)
	s := r.ingestScenario()
	w := r.workers(appcore.NewJobProducerForTest(r.app, 2))
	total := 0
	for i := range 8 {
		rep := r.tick(w)
		if rep.Produced > 2 {
			t.Fatalf("pass %d produced %d, over the bound of 2", i, rep.Produced)
		}
		total += rep.Produced
	}
	if total != scenarioApplied {
		t.Fatalf("bounded passes produced %d in total, want %d", total, scenarioApplied)
	}
	if view := r.view(s.job, model.ID{}); view.TotalAttempts != 3 || view.TotalRuns != 2 {
		t.Fatalf("bounded passes did not reach the whole journal: %+v", view)
	}
}

// Rows can reach the journal behind the frontier (an SDK retry of an old event):
// the next pass finds them.
func TestJobProducerFindsEvidenceBehindTheFrontier(t *testing.T) {
	r := newJobRig(t)
	s := r.ingestScenario()
	w := r.workers(appcore.NewJobProducerForTest(r.app, 256))
	if rep := r.tick(w); rep.Produced != scenarioApplied {
		t.Fatalf("first pass: %+v", rep)
	}
	late := model.NewID()
	r.ingest(r.event(s.job, s.run1, late, "job-run-1", 3, 1, "started", -time.Minute, 0))
	if rep := r.tick(w); rep.Produced != 1 {
		t.Fatalf("an attempt that reached the journal behind the frontier was not applied: %+v", rep)
	}
	if view := r.view(s.job, model.ID{}); view.TotalAttempts != 4 {
		t.Fatalf("late attempt missing: %+v", view)
	}
}

// An attempt that finished is never left reading "started": its terminal event is stamped with the attempt's start and
// reaches the journal after rows of later-started attempts were already covered.
func TestJobProducerAppliesAFinishedAttemptThatArrivedBehindTheFrontier(t *testing.T) {
	r := newJobRig(t)
	w := r.workers(appcore.NewJobProducerForTest(r.app, 256))
	slow, other := model.ID{0x71, 1}, model.ID{0x71, 2}
	runSlow, runOther, attSlow, attOther := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	r.ingest(r.event(slow, runSlow, attSlow, "manual.slow", 1, 1, "started", 20*time.Second, 0))
	r.ingest(r.event(other, runOther, attOther, "manual.other", 1, 1, "started", time.Minute, 0))
	if rep := r.tick(w); rep.Produced != 2 {
		t.Fatalf("first pass: %+v", rep)
	}
	if got := r.view(slow, runSlow).Run.Attempts[0].Effective; got != jobs.AttemptStarted {
		t.Fatalf("before its result arrives the attempt is %v", got)
	}
	// The result of the slow attempt is delivered now, out of order: stamped 20 s, behind the covered row at 60 s.
	r.ingest(r.event(slow, runSlow, attSlow, "manual.slow", 1, 2, "failed", 20*time.Second, 30*time.Second))
	if rep := r.tick(w); rep.Produced != 1 {
		t.Fatalf("the finished attempt that arrived behind the frontier was not applied on the next pass: %+v", rep)
	}
	if got := r.view(slow, runSlow).Run.Attempts[0].Effective; got != jobs.AttemptFailed {
		t.Fatalf("a finished attempt still reads %v", got)
	}
	// Covered rows are not re-applied or re-counted by later passes.
	if rep := r.tick(w); rep.Produced != 0 {
		t.Fatalf("a pass over covered rows produced %d", rep.Produced)
	}
}

// A result that reaches the journal HOURS behind the newest event time is applied by the very next pass: the position is an
// origin cursor, so how far back the event is stamped does not matter (there is no lookback window and no sweep to wait for).
func TestJobProducerAppliesEvidenceStampedHoursBehindTheFrontierOnTheNextPass(t *testing.T) {
	r := newJobRig(t)
	w := r.workers(appcore.NewJobProducerForTest(r.app, 256))
	slow, other := model.ID{0x72, 1}, model.ID{0x72, 2}
	runSlow, runOther, attSlow, attOther := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	r.ingest(r.event(slow, runSlow, attSlow, "manual.slow", 1, 1, "started", -4*time.Hour, 0))
	r.ingest(r.event(other, runOther, attOther, "manual.other", 1, 1, "started", -time.Minute, 0))
	if rep := r.tick(w); rep.Produced != 2 {
		t.Fatalf("first pass: %+v", rep)
	}
	r.ingest(r.event(slow, runSlow, attSlow, "manual.slow", 1, 2, "failed", -4*time.Hour, -4*time.Hour+30*time.Second))
	if rep := r.tick(w); rep.Produced != 1 {
		t.Fatalf("the result stamped four hours behind the frontier was not applied on the next pass: %+v", rep)
	}
	if got := r.view(slow, runSlow).Run.Attempts[0].Effective; got != jobs.AttemptFailed {
		t.Fatalf("the attempt still reads %v", got)
	}
	if rep := r.tick(w); rep.Produced != 0 {
		t.Fatalf("a pass over covered rows produced %d", rep.Produced)
	}
}

func TestJobProducerProducesNothingForARetiredProject(t *testing.T) {
	r := newJobRig(t)
	s := r.ingestScenario()
	if err := r.app.Control.Update(r.ctx, func(st *model.ControlState) error {
		if st.RetiredProjects == nil {
			st.RetiredProjects = map[string]model.ID{}
		}
		st.RetiredProjects[r.org.String()+":"+r.project.String()] = model.NewID()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w := r.workers(r.app.JobProducer())
	if rep := w.Tick(r.ctx); rep.Produced != 0 {
		t.Fatalf("a retired project produced: %+v", rep)
	}
	if n := len(r.commands()); n != 0 {
		t.Fatalf("a retired project has %d committed job commands", n)
	}
	scopes := appcore.NewProducerScopesForTest(r.app, r.org, r.project)
	lease, err := r.app.Control.ReplicaGroup().Fence(r.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := r.app.JobProducer().Produce(r.ctx, scopes, lease); err == nil || n != 0 {
		t.Fatalf("Produce for a retired project: %d, %v", n, err)
	}
	_ = s
}

type countingProducer struct {
	inner appcore.Producer
	calls atomic.Int64
}

func (c *countingProducer) Produce(ctx context.Context, s appcore.ProducerScopes, l replica.FenceToken) (int, error) {
	c.calls.Add(1)
	return c.inner.Produce(ctx, s, l)
}

// A node that is not the leader never reaches the producer, and a producer
// handed a lease that does not prove leadership commits nothing.
func TestJobProducerIsLeaderOnly(t *testing.T) {
	r := newJobRig(t)
	r.ingestScenario()
	fence := r.fence()
	fence.notLeader.Store(true)
	counting := &countingProducer{inner: r.app.JobProducer()}
	w, err := r.app.NewWorkers(r.config(func(c *appcore.WorkerConfig) { c.Producers = []appcore.Producer{counting}; c.Fence = fence }))
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if rep := w.Tick(r.ctx); rep.Leader || rep.Produced != 0 {
			t.Fatalf("a non-leader pass: %+v", rep)
		}
	}
	if counting.calls.Load() != 0 || len(r.commands()) != 0 {
		t.Fatalf("a non-leader reached the producer (%d calls) or committed (%d commands)", counting.calls.Load(), len(r.commands()))
	}
	scopes := appcore.NewProducerScopesForTest(r.app, r.org, r.project)
	if n, err := r.app.JobProducer().Produce(r.ctx, scopes, replica.FenceToken{}); err == nil || n != 0 {
		t.Fatalf("a producer accepted a lease that proves nothing: %d, %v", n, err)
	}
	if len(r.commands()) != 0 {
		t.Fatal("a producer committed under a lease that proves nothing")
	}
}

type wallClock struct{}

func (wallClock) Now() model.UnixNano { return model.UnixNano(time.Now().UnixNano()) }

// sdkJourney loads the Python SDK's actual output for a scheduled run whose first
// attempt fails and whose retry succeeds (sdk/python/tests/test_job_schedule.py
// regenerates and compares it), moved onto the hour before now so the real
// service clock evaluates it. The scheduled key is rebuilt with the server's own
// jobs.OccurrenceKey after proving the SDK's key was exactly that function's.
func sdkJourney(t *testing.T) (events []model.JobAttemptEvent, scheduled model.UnixNano, key string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/sdk-scheduled-retry-journey.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &events); err != nil || len(events) != 4 {
		t.Fatalf("fixture: %v (%d events)", err, len(events))
	}
	original, _, _, ok := jobs.ParseOccurrenceKey(events[0].Schedule)
	if !ok || events[0].Schedule != jobs.OccurrenceKey("UTC", original, 0) {
		t.Fatalf("the SDK's schedule_occurrence %q is not jobs.OccurrenceKey", events[0].Schedule)
	}
	scheduled = model.UnixNano(time.Now().Add(-3 * time.Minute).Truncate(time.Hour).UnixNano())
	key = jobs.OccurrenceKey("UTC", scheduled, 0)
	shift := scheduled - original
	for i := range events {
		events[i].Schedule = key
		events[i].Observed += shift
		if events[i].Terminal != nil {
			terminal := *events[i].Terminal + shift
			events[i].Terminal = &terminal
		}
	}
	return events, scheduled, key
}

// TestJobDurableRetryJourney is the 06.03 smoke: the SDK's real scheduled retry
// journey enters through the real ingest route, the journal producer commits it
// to the real control state, the exporter drops and recovers (the observer
// attests the incomplete stretch, the SDK redelivers everything), and the
// verdicts come from the committed state, also through a service that shares no
// memory with the one that wrote it.
func TestJobDurableRetryJourney(t *testing.T) {
	r := newJobRig(t)
	events, scheduled, key := sdkJourney(t)
	jobID := events[0].Job
	w := r.workers(r.app.JobProducer())
	r.command("grant", auth.AdminPayload{UserID: r.user, ProjectID: r.project, Permissions: []string{string(auth.Read), string(auth.PolicyWrite)}, Enabled: true})
	policyWrite := func() auth.Scope {
		cred, err := r.app.Auth.Authenticate(r.ctx, r.token)
		if err != nil {
			t.Fatal(err)
		}
		scope, err := r.app.Auth.Authorize(r.ctx, cred, r.org, []model.ID{r.project}, auth.PolicyWrite)
		if err != nil {
			t.Fatal(err)
		}
		return scope
	}()
	def := jobs.Definition{Revision: 1, EffectiveFrom: scheduled - model.UnixNano(30*time.Minute), Schedule: &jobs.Schedule{Cron: "0 * * * *", Timezone: "UTC"}}
	observe := func(through model.UnixNano, incomplete ...jobs.Interval) {
		t.Helper()
		_, err := r.app.Jobs.ObserveSchedule(r.ctx, policyWrite, jobs.ScheduleEvidence{CommandID: model.NewID(), Project: r.project, Job: jobID, Observer: model.ID{7}, ObservedAt: model.UnixNano(time.Now().UnixNano()), CompleteThrough: through, Healthy: true, Definition: &def, Incomplete: incomplete})
		if err != nil {
			t.Fatal(err)
		}
	}
	health := func(svc *jobs.Service) jobs.Report {
		t.Helper()
		report, err := svc.Health(r.ctx, r.humanRead(), r.project, jobID)
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	now := func() model.UnixNano { return model.UnixNano(time.Now().UnixNano()) }

	// The first attempt fails; the exporter delivered both of its events.
	r.ingest(events[0])
	r.ingest(events[1])
	observe(now())
	if rep := r.tick(w); rep.Produced != 2 {
		t.Fatalf("first pass: %+v", rep)
	}
	if got := health(r.app.Jobs); got.Health.Status != jobs.StatusFailed || got.Health.Evidence.Occurrence != key {
		t.Fatalf("a failed scheduled attempt: %+v", got.Health)
	}

	// The exporter's connectivity drops while the retry runs: the observer attests that
	// the data path is complete only through the failure and names the stretch it cannot vouch for.
	lost := jobs.Interval{ID: model.NewID(), Start: *events[1].Terminal, End: *events[3].Terminal, Reason: "exporter_connectivity"}
	observe(*events[1].Terminal, lost)
	got := health(r.app.Jobs)
	if got.Health.Status != jobs.StatusFailed || got.Health.Complete || !slices.Contains(got.Health.Reasons, jobs.ReasonEvidenceGap) || len(got.Intervals) != 1 || got.Intervals[0].ID != lost.ID {
		t.Fatalf("during the outage the known failure stands but is marked incomplete by the gap: %+v %+v", got.Health, got.Intervals)
	}

	// Connectivity returns: the SDK flushes the retry and re-sends the first attempt's
	// terminal event it never saw acknowledged (a new batch, a new record id; ingest
	// refuses an older sequence of a settled attempt, so the start is not re-sent).
	// The observer attests the path complete again.
	r.ingest(events[1])
	r.ingest(events[2])
	r.ingest(events[3])
	observe(now())
	if rep := r.tick(w); rep.Produced != 2 {
		t.Fatalf("the redelivered terminal event must not commit again, only the retry: %+v", rep)
	}
	got = health(r.app.Jobs)
	st := got.State
	if got.Health.Status != jobs.StatusSucceeded || !got.Health.Complete || !slices.Contains(got.Health.Reasons, jobs.ReasonRunRecovered) {
		t.Fatalf("the retry must recover the scheduled run: %+v", got.Health)
	}
	if len(st.Attempts) != 2 || st.Attempts[events[0].Attempt].Effective() != jobs.AttemptFailed || st.Attempts[events[2].Attempt].Effective() != jobs.AttemptSucceeded || len(st.Runs) != 1 || len(st.Occurrences[key].Runs) != 1 || !st.Occurrences[key].Scheduled || st.Occurrences[key].At != scheduled {
		t.Fatalf("the history must keep attempt 1 failed under one scheduled occurrence: %+v", st)
	}

	// Persistence: a service sharing no memory with the writer reads the same verdict from control,
	// and every attempt command is the system principal's with its origin cursor.
	store, err := jobs.NewControlStore(r.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := jobs.New(store, r.app.Auth, wallClock{})
	if err != nil {
		t.Fatal(err)
	}
	if again := health(fresh); again.Health.Status != got.Health.Status || again.State.Version != got.State.Version || len(again.State.Attempts) != 2 {
		t.Fatalf("a fresh service over control disagrees: %+v vs %+v", again.Health, got.Health)
	}
	attempts := 0
	for _, c := range r.commands() {
		if c.Kind == "attempt" {
			attempts++
			if c.Principal != auth.SystemPrincipal(r.org) || c.Origin == nil {
				t.Fatalf("attempt command not the runner's: %+v", c)
			}
		}
	}
	if attempts != 4 {
		t.Fatalf("committed %d attempt commands, want 4 (the redelivery must not double count)", attempts)
	}
	if rep := r.tick(w); rep.Produced != 0 {
		t.Fatalf("a further pass produced %d", rep.Produced)
	}
}

// The reducer's limits stay at or below the durable store's caps: a state the
// reducer produces must never be refused for its shape, or the job stalls.
func TestJobReducerBoundsFitTheDurableStore(t *testing.T) {
	b := control.JobStateBounds
	for _, c := range []struct {
		name         string
		reducer, cap int
	}{
		{"runs", jobs.MaxRetainedRuns, b.Runs},
		{"attempts", jobs.MaxRetainedAttempts, b.Attempts},
		{"occurrences (one per retained run)", jobs.MaxRetainedRuns, b.Occurrences},
		{"definition history", jobs.MaxDefinitions, b.History},
		{"intervals", jobs.MaxIntervals, b.Intervals},
	} {
		if c.reducer > c.cap {
			t.Errorf("reducer %s limit %d exceeds the control cap %d: a busy job would stall in Quota", c.name, c.reducer, c.cap)
		}
	}
}

// Decision (06.03-W4): evidence stamped more than jobs.MaxFutureSkew ahead of the
// service clock is rejected (Invalid), not stored and flagged. The journal worker
// then moves past it for good, so one skewed host never wedges the others.
func TestJobEvidenceFromAClockSkewedHostIsRejectedAndDoesNotWedgeTheJournal(t *testing.T) {
	r := newJobRig(t)
	job, run, skewed, good := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	r.ingest(r.event(job, run, skewed, "job-run-skew", 1, 1, "started", time.Hour+10*time.Minute, 0))
	r.ingest(r.event(job, model.NewID(), good, "job-run-good", 1, 1, "started", 10*time.Second, 0))
	w := r.workers(r.app.JobProducer())
	if rep := r.tick(w); rep.Produced != 1 {
		t.Fatalf("only the sane host's evidence may commit: %+v", rep)
	}
	report, err := r.app.Jobs.Health(r.ctx, r.humanRead(), r.project, job)
	if err != nil || len(report.State.Attempts) != 1 || report.State.Attempts[good].Effective() == "" {
		t.Fatalf("the skewed attempt must not be in the state: %v %+v", err, report.State.Attempts)
	}
	if _, ok := report.State.Attempts[skewed]; ok {
		t.Fatal("a future-stamped attempt was stored")
	}
	if rep := r.tick(w); rep.Produced != 0 {
		t.Fatalf("the rejected row was retried: %+v", rep)
	}
}

// Decision (06.03 ingest finding): a re-sent OLDER "started" event of an attempt
// that already has a terminal event is an idempotent duplicate (200), because the
// SDK that never saw the ack must be able to drain its queue (design: "duplicate
// retry is identical", "idempotent retries do not count twice"). A different
// terminal for the attempt stays a 409 conflict, and the late duplicate never
// regresses the stored marker that the conflict check compares against.
func TestJobIngestAcceptsALateResendOfAnOlderEventOfASettledAttempt(t *testing.T) {
	r := newJobRig(t)
	job, run, attempt := model.NewID(), model.NewID(), model.NewID()
	started := r.event(job, run, attempt, "job-run-late", 1, 1, "started", 10*time.Second, 0)
	failed := r.event(job, run, attempt, "job-run-late", 1, 2, "failed", 10*time.Second, 20*time.Second)
	r.ingest(started)
	r.ingest(failed)
	if status, body := r.send(started); status != 200 {
		t.Fatalf("a re-sent older started event of a failed attempt answered %d: %s", status, body)
	}
	other := r.event(job, run, attempt, "job-run-late", 1, 2, "failed", 10*time.Second, 25*time.Second)
	if status, _ := r.send(other); status != 409 {
		t.Fatalf("a different terminal at the same sequence answered %d, want 409 (the late duplicate must not have regressed the marker)", status)
	}
	if status, body := r.send(failed); status != 200 {
		t.Fatalf("the identical terminal re-sent answered %d: %s", status, body)
	}
	older := r.event(job, run, attempt, "job-run-late", 1, 1, "failed", 10*time.Second, 20*time.Second)
	if status, _ := r.send(older); status != 409 {
		t.Fatalf("an older terminal event answered %d, want 409", status)
	}
	w := r.workers(r.app.JobProducer())
	r.tick(w)
	report, err := r.app.Jobs.Health(r.ctx, r.humanRead(), r.project, job)
	if err != nil || len(report.State.Attempts) != 1 || report.State.Attempts[attempt].Terminal == nil || len(report.State.Attempts[attempt].Events) != 2 {
		t.Fatalf("the attempt must hold its two distinct events once: %v %+v", err, report.State.Attempts)
	}
}

func (r *jobRig) catalogueScope() auth.Scope {
	r.t.Helper()
	_, cred := r.member("job-author@example.test", auth.Read, auth.PolicyWrite)
	return r.scopeOf(cred, auth.PolicyWrite)
}

// The job producer is the observer of the jobs the catalogue defines: a defined job is observed with its
// definition under the runner's clock, at a bounded cadence and never after it is retired, and what is attested
// as complete is only what the product's own journal delivered (the newest event time less the late allowance):
// the source of a job that went silent is never read as having missed its runs.
func TestJobProducerObservesTheJobsTheCatalogueDefines(t *testing.T) {
	r := newJobRig(t)
	wall := model.UnixNano(time.Now().UnixNano())
	r.clock.v.Store(int64(wall))
	s := r.ingestScenario()
	catalogue, err := r.app.JobCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	author := r.catalogueScope()
	def := jobs.Definition{Revision: 1, EffectiveFrom: wall - model.UnixNano(24*time.Hour), Schedule: &jobs.Schedule{Cron: "* * * * *", Timezone: "UTC"}, Grace: jobs.Duration(time.Minute), ObserverStaleAfter: jobs.Duration(8 * time.Minute)}
	if _, err = catalogue.Save(r.ctx, author, jobs.SaveCommand{CommandID: model.NewID(), Project: r.project, Job: s.job, ExpectedRevision: 0, Definition: def, Reason: "schedule"}); err != nil {
		t.Fatal(err)
	}
	w := r.workers(r.app.JobProducer())
	if rep := r.tick(w); rep.Produced != scenarioApplied+1 {
		t.Fatalf("first pass produced %d, want %d attempts + 1 observation: %+v", rep.Produced, scenarioApplied, rep)
	}
	rep, err := r.app.Jobs.Health(r.ctx, r.humanRead(), r.project, s.job)
	if err != nil {
		t.Fatal(err)
	}
	st := rep.State
	if st.Definition.Revision != 1 || st.Definition.Schedule == nil || st.Definition.Schedule.Cron != "* * * * *" {
		t.Fatalf("the definition was not adopted: %+v", st.Definition)
	}
	if st.Observer == nil || !st.Observer.Healthy || st.Observer.ObservedAt != wall {
		t.Fatalf("observation: %+v, want healthy at the runner's clock %d", st.Observer, wall)
	}
	// Complete through the newest event of the journal (stamped 10 s after the base, an hour ago) less the 15 minute allowance.
	newest := r.at(10 * time.Second)
	if want := newest - model.UnixNano(15*time.Minute); st.Observer.CompleteThrough != want {
		t.Fatalf("complete through %d, want %d (newest event %d less the late allowance)", st.Observer.CompleteThrough, want, newest)
	}
	version := st.Version
	// Within a quarter of the staleness bound (2 min) nothing is observed again; after it, once.
	r.clock.v.Store(int64(wall + model.UnixNano(time.Minute)))
	if rep := r.tick(w); rep.Produced != 0 {
		t.Fatalf("a pass within the cadence produced %d", rep.Produced)
	}
	r.clock.v.Store(int64(wall + model.UnixNano(3*time.Minute)))
	if rep := r.tick(w); rep.Produced != 1 {
		t.Fatalf("a pass after the cadence produced %d, want the one observation", rep.Produced)
	}
	if again, _ := r.app.Jobs.Health(r.ctx, r.humanRead(), r.project, s.job); again.State.Version != version+1 || again.State.Observer.ObservedAt != wall+model.UnixNano(3*time.Minute) {
		t.Fatalf("the second observation: %+v", again.State.Observer)
	}
	// A retired definition is observed no more.
	entries, err := catalogue.List(r.ctx, r.humanRead(), r.project)
	if err != nil || len(entries) != 1 {
		t.Fatalf("catalogue: %v %v", entries, err)
	}
	if _, err = catalogue.Retire(r.ctx, author, jobs.RetireCommand{CommandID: model.NewID(), Project: r.project, Job: s.job, ExpectedRevision: entries[0].Revision, Reason: "retire"}); err != nil {
		t.Fatal(err)
	}
	r.clock.v.Store(int64(wall + model.UnixNano(10*time.Minute)))
	if rep := r.tick(w); rep.Produced != 0 {
		t.Fatalf("a retired job was observed: %+v", rep)
	}
}

// A pass costs what arrived since the committed position, not the journal: with nothing new a pass reads no page at all,
// and one new row costs a read of that row's page only (the rows at or below the position are skipped at the index).
func TestJobProducerReadsOnlyWhatArrivedSinceItsPosition(t *testing.T) {
	r := newJobRig(t)
	s := r.ingestScenario()
	w := r.workers(appcore.NewJobProducerForTest(r.app, 256))
	r.tick(w)
	pages := func() uint64 { return r.app.Storage.Stats().PagesRead }
	before := pages()
	if rep := r.tick(w); rep.Produced != 0 {
		t.Fatalf("an idle pass produced %d", rep.Produced)
	}
	if got := pages() - before; got != 0 {
		t.Fatalf("an idle pass read %d pages of a %d-row journal", got, scenarioApplied+1)
	}
	r.ingest(r.event(s.job, s.run2, model.NewID(), "job-run-2", 2, 1, "started", 20*time.Second, 0))
	before = pages()
	if rep := r.tick(w); rep.Produced != 1 {
		t.Fatalf("the pass after one new row produced %d", rep.Produced)
	}
	if got := pages() - before; got > 2 {
		t.Fatalf("one new row cost %d pages of a %d-row journal: the position is not a seek", got, scenarioApplied+2)
	}
}

// What the journal attests is per source: the job of a source that fell silent is attested only through that source's
// own newest event, however far another source has moved on, so the silence is never read as a missed run.
func TestJobProducerAttestsEachJobOnlyThroughItsOwnSource(t *testing.T) {
	r := newJobRig(t)
	wall := model.UnixNano(time.Now().UnixNano())
	r.clock.v.Store(int64(wall))
	silent, live := model.NewID(), model.NewID()
	r.ingest(r.event(silent, model.NewID(), model.NewID(), "manual.a", 1, 1, "started", 10*time.Second, 0))
	// A second source, with its own credential, delivers a later event of another job.
	firstSource, firstID := r.source, r.sourceID
	r.sourceID = model.NewID()
	issued, err := r.app.Auth.OnboardSource(r.ctx, r.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: r.org, Project: r.project, Source: r.sourceID, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()),
		Policy: model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.JobAttempt}, Resources: model.ResourceRegistry{Services: []model.ID{r.resource.Service}, Environments: []model.ID{r.resource.Environment}, Builds: []model.ID{r.resource.Build}, Instances: []string{"job-host"}},
			RetentionDays: map[model.Kind]uint32{model.JobAttempt: 30}, MaxBytes: 8 << 20, MaxSeries: 100, Expires: model.UnixNano(time.Now().Add(20 * time.Minute).UnixNano())}, Reason: "second source"})
	if err != nil {
		t.Fatal(err)
	}
	r.source = issued.Credential
	r.ingest(r.event(live, model.NewID(), model.NewID(), "manual.b", 1, 1, "started", 40*time.Minute, 0))
	r.source, r.sourceID = firstSource, firstID

	catalogue, err := r.app.JobCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	author := r.catalogueScope()
	for _, job := range []model.ID{silent, live} {
		def := jobs.Definition{Revision: 1, EffectiveFrom: wall - model.UnixNano(24*time.Hour), Schedule: &jobs.Schedule{Cron: "* * * * *", Timezone: "UTC"}, Grace: jobs.Duration(time.Minute)}
		if _, err = catalogue.Save(r.ctx, author, jobs.SaveCommand{CommandID: model.NewID(), Project: r.project, Job: job, Definition: def, Reason: "schedule"}); err != nil {
			t.Fatal(err)
		}
	}
	w := r.workers(r.app.JobProducer())
	r.tick(w)
	for job, want := range map[model.ID]model.UnixNano{silent: r.at(10*time.Second) - model.UnixNano(15*time.Minute), live: r.at(40*time.Minute) - model.UnixNano(15*time.Minute)} {
		rep, err := r.app.Jobs.Health(r.ctx, r.humanRead(), r.project, job)
		if err != nil || rep.State.Observer == nil || rep.State.Observer.CompleteThrough != want {
			t.Fatalf("job %s: observer %+v err %v, want complete through %d", job, rep.State.Observer, err, want)
		}
	}
}
