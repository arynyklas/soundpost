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
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/httpapi"
	"soundpost/internal/jobs"
	"soundpost/internal/model"
	"soundpost/internal/replica"
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
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		r.t.Fatalf("ingest answered %d: %s", resp.StatusCode, body)
	}
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
	w := r.workers(appcore.NewJobProducerForTest(r.app, 2, time.Hour))
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
// the sweep over the journal behind the tail finds them.
func TestJobProducerSweepFindsEvidenceBehindTheFrontier(t *testing.T) {
	r := newJobRig(t)
	s := r.ingestScenario()
	w := r.workers(appcore.NewJobProducerForTest(r.app, 256, 0))
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
