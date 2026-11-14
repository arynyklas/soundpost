// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package jobs_test

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
)

// These tests run jobs.Service over the real adapter on a real control store
// (appcore.Open: real auth, real Raft). The shared fixture app serves the tests
// that use a job of their own (a fresh job ID per test, so nothing collides in
// the shared control state); the tests that restart the application or declare
// project-wide evidence gaps open an application of their own.

var bindOnce sync.Once

// bindJobs installs the KindUpdateJob handler; the application composition will
// do it itself once the parent wires it, in which case it is already bound.
func bindJobs(t *testing.T, c *control.Store) {
	t.Helper()
	if err := c.BindJobUpdate(); err != nil && code(err) != model.Conflict {
		t.Fatal(err)
	}
}

type realH struct {
	f     *fixture
	store *jobs.ControlStore
	clock *fakeClock
	svc   *jobs.Service
	job   model.ID
}

func newRealH(t *testing.T, now model.UnixNano) *realH {
	t.Helper()
	f := getFixture(t)
	bindOnce.Do(func() { bindJobs(t, f.app.Control) })
	return newRealHFor(t, f, now, model.NewID())
}

func newRealHFor(t *testing.T, f *fixture, now model.UnixNano, job model.ID) *realH {
	t.Helper()
	store, err := jobs.NewControlStore(f.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	h := &realH{f: f, store: store, clock: &fakeClock{at: now}, job: job}
	h.svc = h.service(t)
	return h
}

func (h *realH) service(t *testing.T) *jobs.Service {
	t.Helper()
	svc, err := jobs.New(h.store, h.f.app.Auth, h.clock)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func (h *realH) writer(t *testing.T) auth.Scope {
	return h.f.scope(t, "writer1@example.test", h.f.org1, h.f.project1, auth.PolicyWrite)
}
func (h *realH) reader(t *testing.T) auth.Scope {
	return h.f.scope(t, "reader1@example.test", h.f.org1, h.f.project1, auth.Read)
}

// ev is an attempt event of this harness's job.
func (h *realH) ev(run, attempt model.ID, schedule string, ordinal, seq uint64, state string, observed model.UnixNano, terminal *model.UnixNano) model.JobAttemptEvent {
	e := ev(run, attempt, schedule, ordinal, seq, state, observed, terminal)
	e.Job = h.job
	return e
}

func (h *realH) load(t *testing.T, scope auth.Scope) jobs.JobState {
	t.Helper()
	st, found, err := h.store.Load(context.Background(), scope, h.f.project1, h.job)
	if err != nil || !found {
		t.Fatalf("load: found=%v err=%v", found, err)
	}
	return st
}

func apply(t *testing.T, svc *jobs.Service, w auth.Scope, e jobs.AttemptEvidence) (jobs.JobState, jobs.Outcome) {
	t.Helper()
	st, outcome, err := svc.ApplyAttempt(context.Background(), w, e)
	if err != nil {
		t.Fatalf("apply %v: %v", e.Record, err)
	}
	return st, outcome
}

func TestControlStoreConstructionAndScopes(t *testing.T) {
	if _, err := jobs.NewControlStore(nil); code(err) != model.Invalid {
		t.Fatalf("nil control accepted: %v", err)
	}
	h := newRealH(t, hm(12, 0, 0))
	ctx := context.Background()
	w, r := h.writer(t), h.reader(t)
	p := h.f.project1
	if _, found, err := h.store.Load(ctx, w, p, h.job); err != nil || found {
		t.Fatalf("a job without state: found=%v err=%v", found, err)
	}
	if _, _, err := h.svc.ApplyAttempt(ctx, w, record(p, 1, h.ev(runA, att1, "manual.a", 1, 1, "failed", hm(11, 0, 0), new(hm(11, 0, 5))))); err != nil {
		t.Fatal(err)
	}
	// The same job in another organization's scope, or outside the scope's
	// projects, is NotFound exactly like a job that does not exist.
	w2 := h.f.scope(t, "writer2@example.test", h.f.org2, h.f.project2, auth.PolicyWrite)
	_, _, foreign := h.store.Load(ctx, w2, p, h.job)
	_, _, otherProject := h.store.Load(ctx, w, h.f.project1b, h.job)
	_, _, missingProject := h.store.Load(ctx, w, model.NewID(), h.job)
	for name, err := range map[string]error{"foreign org": foreign, "other project": otherProject, "missing project": missingProject} {
		if code(err) != model.NotFound || err.Error() != foreign.Error() {
			t.Fatalf("%s: %v vs %v", name, err, foreign)
		}
	}
	if _, found, err := h.store.Load(ctx, r, p, h.job); err != nil || !found {
		t.Fatalf("telemetry.read cannot load: %v", err)
	}
	if _, _, err := h.store.Load(ctx, auth.Scope{}, p, h.job); err == nil {
		t.Fatal("zero scope loaded")
	}
	// Writes need policy.write on the project.
	st := h.load(t, w)
	next, _, err := jobs.ReduceEvent(st, h.ev(runA, att2, "manual.a", 2, 2, "started", hm(11, 1, 0), nil))
	if err != nil {
		t.Fatal(err)
	}
	cmd := jobs.UpdateCommand{CommandID: model.NewID(), Kind: jobs.UpdateAttempt, Project: p, Job: h.job, ExpectedVersion: st.Version, InputDigest: model.Hash{1}, Next: next, Origin: &model.Cursor{Group: model.ID{0xA1}, Index: 2}}
	if _, err = h.store.Update(ctx, r, cmd); code(err) != model.Forbidden {
		t.Fatalf("read scope wrote: %v", err)
	}
	if _, err = h.store.Update(ctx, w2, cmd); code(err) != model.Invalid && code(err) != model.NotFound {
		t.Fatalf("foreign scope wrote: %v", err)
	}
	if _, err = h.store.Update(ctx, auth.Scope{}, cmd); err == nil {
		t.Fatal("zero scope wrote")
	}
	// A state for another job or project is refused before it reaches control.
	bad := cmd
	bad.Job = model.NewID()
	if _, err = h.store.Update(ctx, w, bad); code(err) != model.Invalid {
		t.Fatalf("state of another job: %v", err)
	}
	if _, err = h.store.Update(ctx, w, jobs.UpdateCommand{}); code(err) != model.Invalid {
		t.Fatalf("empty command: %v", err)
	}
	if got := h.load(t, w); !reflect.DeepEqual(got, st) {
		t.Fatal("refused updates changed the job")
	}
}

func TestControlStoreVersionCompareAndSetAndCommandIdentity(t *testing.T) {
	h := newRealH(t, hm(12, 0, 0))
	ctx := context.Background()
	w := h.writer(t)
	p := h.f.project1
	build := func(base jobs.JobState, e model.JobAttemptEvent) jobs.UpdateCommand {
		next, _, err := jobs.ReduceEvent(base, e)
		if err != nil {
			t.Fatal(err)
		}
		return jobs.UpdateCommand{CommandID: model.NewID(), Kind: jobs.UpdateAttempt, Project: p, Job: h.job, ExpectedVersion: base.Version, InputDigest: model.Hash{byte(e.Sequence)}, Next: next, Origin: &model.Cursor{Group: model.ID{0xA1}, Index: e.Sequence}}
	}
	first := build(jobs.JobState{Org: h.f.org1, Project: p, Job: h.job}, h.ev(runA, att1, "manual.a", 1, 1, "started", hm(11, 0, 0), nil))
	res, err := h.store.Update(ctx, w, first)
	if err != nil || res.Version != 1 || res.Replayed {
		t.Fatalf("first update: %+v %v", res, err)
	}
	afterFirst := h.load(t, w)
	second := build(afterFirst, h.ev(runA, att1, "manual.a", 1, 2, "failed", hm(11, 0, 0), new(hm(11, 0, 5))))
	if res, err = h.store.Update(ctx, w, second); err != nil || res.Version != 2 {
		t.Fatalf("second update: %+v %v", res, err)
	}
	// A third writer that read version 1 loses with Stale, whose detail carries
	// the current version.
	stale := build(afterFirst, h.ev(runA, att2, "manual.a", 2, 3, "started", hm(11, 1, 0), nil))
	var fault *model.Fault
	if _, err = h.store.Update(ctx, w, stale); !errors.As(err, &fault) || fault.Code != model.Stale || fault.SafeDetail != control.JobVersionConflict+" current=2" {
		t.Fatalf("stale update: %v", err)
	}
	// Retrying the first command (reordered behind the second) is a replay.
	if res, err = h.store.Update(ctx, w, first); err != nil || !res.Replayed || res.Version != 1 {
		t.Fatalf("replay of the first command: %+v %v", res, err)
	}
	// The same command ID with another input digest is a conflict.
	other := first
	other.InputDigest = model.Hash{0x77}
	if _, err = h.store.Update(ctx, w, other); code(err) != model.Conflict {
		t.Fatalf("command reused with another digest: %v", err)
	}
	if got := h.load(t, w); got.Version != 2 || got.Attempts[att1].Effective() != jobs.AttemptFailed || len(got.Attempts) != 1 {
		t.Fatalf("state %+v", got)
	}
}

// Late old completion cannot overwrite newer health: the reducer's rule, through
// the real store end to end, across a service restart and in either delivery order.
func TestLateOldCompletionCannotOverwriteNewerHealthThroughTheStore(t *testing.T) {
	ctx := context.Background()
	key1 := jobs.OccurrenceKey("UTC", hm(1, 0, 0), 0)
	key2 := jobs.OccurrenceKey("UTC", hm(2, 0, 0), 0)
	run1, run2 := model.ID{21}, model.ID{22}
	h := newRealH(t, hm(2, 30, 0))
	w, r := h.writer(t), h.reader(t)
	p := h.f.project1
	newer := []jobs.AttemptEvidence{
		record(p, 1, h.ev(run2, att2, key2, 1, 1, "started", hm(2, 0, 1), nil)),
		record(p, 2, h.ev(run2, att2, key2, 1, 2, "succeeded", hm(2, 0, 1), new(hm(2, 0, 5)))),
	}
	older := []jobs.AttemptEvidence{
		record(p, 3, h.ev(run1, att1, key1, 1, 1, "started", hm(1, 0, 1), nil)),
		record(p, 4, h.ev(run1, att1, key1, 1, 2, "failed", hm(1, 0, 1), new(hm(1, 0, 9)))),
	}
	for _, e := range newer {
		apply(t, h.svc, w, e)
	}
	report, err := h.svc.Health(ctx, r, p, h.job)
	if err != nil || report.Health.Status != jobs.StatusSucceeded {
		t.Fatalf("newer success: %v %+v", err, report.Health)
	}
	// The late old failure arrives through a restarted service.
	restarted := h.service(t)
	apply(t, restarted, w, older[0])
	_, outcome := apply(t, restarted, w, older[1])
	if outcome != jobs.Applied {
		t.Fatalf("late old failure: %v", outcome)
	}
	report, err = restarted.Health(ctx, r, p, h.job)
	st := report.State
	if err != nil || report.Health.Status != jobs.StatusSucceeded || report.Health.Evidence.Occurrence != key2 || st.LatestScheduleKey != key2 {
		t.Fatalf("late old failure overwrote newer health: %v %+v latest %q", err, report.Health, st.LatestScheduleKey)
	}
	if st.Attempts[att1].Effective() != jobs.AttemptFailed || st.Runs[run1].Status != jobs.RunFailed || len(st.Attempts) != 2 {
		t.Fatal("the late old failure was dropped from history")
	}
	// What is stored is what the service answered, and redelivery changes nothing.
	if got := h.load(t, w); !reflect.DeepEqual(got, st) {
		t.Fatal("stored state differs from the service's state")
	}
	for _, e := range append(newer, older...) {
		if _, outcome := apply(t, restarted, w, e); outcome != jobs.Duplicate {
			t.Fatalf("redelivery: %v", outcome)
		}
	}
	if got := h.load(t, w); got.Version != st.Version {
		t.Fatalf("redelivery moved the version %d -> %d", st.Version, got.Version)
	}
	// The same job in the opposite delivery order reaches the same verdict.
	h2 := newRealHFor(t, h.f, hm(2, 30, 0), model.NewID())
	for _, e := range append(append([]jobs.AttemptEvidence(nil), older...), newer...) {
		e.Event.Job = h2.job
		apply(t, h2.svc, w, e)
	}
	a, b := h.load(t, w).CurrentHealth, h2.load(t, w).CurrentHealth
	if a.Status != b.Status || a.Evidence.Occurrence != b.Evidence.Occurrence || b.Status != jobs.StatusSucceeded {
		t.Fatalf("delivery order changed the verdict: %+v vs %+v", a, b)
	}
}

// Shuffled and duplicated delivery persists exactly what folding each record once
// through the reducer computes.
func TestControlStoreExactlyOnceUnderReorderedRetries(t *testing.T) {
	h := newRealH(t, hm(12, 0, 0))
	w := h.writer(t)
	p := h.f.project1
	var journal []jobs.AttemptEvidence
	idx := uint64(0)
	for i := range 6 {
		attempt := model.ID{0xC0, byte(i)}
		key := jobsKey(hm(10+i/3, 0, 0))
		run := model.ID{0xD0, byte(i / 3)}
		idx++
		journal = append(journal, record(p, idx, h.ev(run, attempt, key, uint64(i%3+1), uint64(2*i+1), "started", hm(10, i, 0), nil)))
		idx++
		journal = append(journal, record(p, idx, h.ev(run, attempt, key, uint64(i%3+1), uint64(2*i+2), "failed", hm(10, i, 0), new(hm(10, i, 30)))))
	}
	// Fold the journal in order locally for the reference.
	ref := jobs.JobState{Org: h.f.org1, Project: p, Job: h.job}
	for _, e := range journal {
		var err error
		if ref, _, err = jobs.ReduceEvent(ref, e.Event); err != nil {
			t.Fatal(err)
		}
	}
	// Deliver in a shuffled order, every record several times, from a few workers.
	rng := rand.New(rand.NewPCG(7, 11))
	var deliveries []jobs.AttemptEvidence
	for _, e := range journal {
		for range 3 {
			deliveries = append(deliveries, e)
		}
	}
	rng.Shuffle(len(deliveries), func(i, j int) { deliveries[i], deliveries[j] = deliveries[j], deliveries[i] })
	// Records of one attempt may be delivered out of order; the reducer decides
	// whether that is applied, so compare with an in-order pass over the same
	// store content below instead of assuming it.
	var applied int
	for _, e := range deliveries {
		_, outcome, err := h.svc.ApplyAttempt(context.Background(), w, e)
		if err != nil {
			t.Fatalf("delivery of %v: %v", e.Record, err)
		}
		if outcome == jobs.Applied {
			applied++
		}
	}
	got := h.load(t, w)
	if int(got.Version) != applied {
		t.Fatalf("version %d but %d applications", got.Version, applied)
	}
	// A second pass in canonical order applies whatever the shuffle left unapplied
	// and nothing twice; afterwards the state is the in-order fold.
	for _, e := range journal {
		if _, _, err := h.svc.ApplyAttempt(context.Background(), w, e); err != nil {
			t.Fatal(err)
		}
	}
	final := h.load(t, w)
	if len(final.Attempts) != len(ref.Attempts) || len(final.Runs) != len(ref.Runs) {
		t.Fatalf("attempts %d/%d runs %d/%d", len(final.Attempts), len(ref.Attempts), len(final.Runs), len(ref.Runs))
	}
	for id, a := range ref.Attempts {
		if g := final.Attempts[id]; g.Effective() != a.Effective() || len(g.Events) != len(a.Events) {
			t.Fatalf("attempt %v: %+v vs %+v", id, g, a)
		}
	}
	before := final.Version
	for _, e := range journal {
		if _, outcome := apply(t, h.svc, w, e); outcome != jobs.Duplicate {
			t.Fatalf("redelivery: %v", outcome)
		}
	}
	if after := h.load(t, w).Version; after != before {
		t.Fatalf("redelivery moved the version %d -> %d", before, after)
	}
}

func TestControlStoreConcurrentWorkersLoseNothing(t *testing.T) {
	h := newRealH(t, hm(12, 0, 0))
	w := h.writer(t)
	p := h.f.project1
	const attempts = 24
	var wg sync.WaitGroup
	errs := make(chan error, 8*attempts)
	var mu sync.Mutex
	applied := 0
	deliver := func(e jobs.AttemptEvidence) {
		for range 400 {
			_, outcome, err := h.svc.ApplyAttempt(context.Background(), w, e)
			if err == nil {
				if outcome == jobs.Applied {
					mu.Lock()
					applied++
					mu.Unlock()
				}
				return
			}
			var fault *model.Fault
			if !errors.As(err, &fault) || !fault.Retryable {
				errs <- err
				return
			}
		}
		errs <- errors.New("retries exhausted")
	}
	for i := range attempts {
		attempt := model.ID{0xC0, byte(i)}
		start := record(p, uint64(100+2*i), h.ev(runA, attempt, "manual.a", uint64(i+1), uint64(2*i+1), "started", hm(11, 0, i), nil))
		fail := record(p, uint64(101+2*i), h.ev(runA, attempt, "manual.a", uint64(i+1), uint64(2*i+2), "failed", hm(11, 0, i), new(hm(11, 0, i)+5)))
		wg.Add(1)
		go func() {
			defer wg.Done()
			deliver(start)
			deliver(fail)
		}()
		// The first record is also delivered concurrently by a second worker.
		wg.Add(1)
		go func() {
			defer wg.Done()
			deliver(start)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	st := h.load(t, w)
	if len(st.Attempts) != attempts || len(st.Runs[runA].Attempts) != attempts || int(st.Version) != 2*attempts || applied != 2*attempts {
		t.Fatalf("lost or duplicated updates: attempts %d version %d applied %d", len(st.Attempts), st.Version, applied)
	}
	for id, a := range st.Attempts {
		if a.Terminal == nil || !a.Started || len(a.Events) != 2 {
			t.Fatalf("attempt %v incomplete: %+v", id, a)
		}
	}
}

func TestControlStoreHoldsNoTelemetryText(t *testing.T) {
	h := newRealH(t, hm(12, 0, 0))
	w := h.writer(t)
	p := h.f.project1
	apply(t, h.svc, w, record(p, 1, h.ev(runA, att1, "manual.a", 1, 1, "failed", hm(11, 0, 0), new(hm(11, 0, 5)))))
	var raw string
	if err := h.f.app.Control.View(context.Background(), func(st control.State) error {
		raw = string(st.JobBooks[h.f.org1.String()+":"+p.String()+":"+h.job.String()])
		return nil
	}); err != nil || raw == "" {
		t.Fatalf("no record: %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatal(err)
	}
	state, _ := rec["state"].(map[string]any)
	allowed := map[string]bool{"version": true, "org": true, "project": true, "job": true, "definition": true, "history": true, "current_health": true, "latest_schedule_key": true,
		"occurrences": true, "runs": true, "attempts": true, "incomplete_intervals": true, "observer": true, "compaction": true}
	for k := range state {
		if !allowed[k] {
			t.Fatalf("unexpected state key %q", k)
		}
	}
	for _, word := range []string{"message", "exception", "stack", "payload", "body", "password", "secret", "token"} {
		if strings.Contains(strings.ToLower(raw), word) {
			t.Fatalf("stored record names %q: %s", word, raw)
		}
	}
}

func TestControlStoreLoadRefusesInconsistentRecord(t *testing.T) {
	h := newRealH(t, hm(12, 0, 0))
	w := h.writer(t)
	p := h.f.project1
	good := func(job model.ID, version model.Revision) json.RawMessage {
		raw, _ := json.Marshal(map[string]any{"version": version, "org": h.f.org1, "project": p, "job": job})
		return raw
	}
	seed := func(job model.ID, rec control.JobRecord) {
		raw, _ := json.Marshal(rec)
		if err := h.f.app.Control.Update(context.Background(), func(st *control.State) error {
			if st.JobBooks == nil {
				st.JobBooks = map[string]json.RawMessage{}
			}
			st.JobBooks[h.f.org1.String()+":"+p.String()+":"+job.String()] = raw
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	// The record says version 4, its state says 3.
	seed(h.job, control.JobRecord{Org: h.f.org1, Project: p, Job: h.job, Version: 4, State: good(h.job, 3)})
	if _, _, err := h.store.Load(context.Background(), w, p, h.job); code(err) != model.Corrupt {
		t.Fatalf("version mismatch: %v", err)
	}
	// The state names another job.
	other := model.NewID()
	seed(other, control.JobRecord{Org: h.f.org1, Project: p, Job: other, Version: 1, State: good(model.NewID(), 1)})
	if _, _, err := h.store.Load(context.Background(), w, p, other); code(err) != model.Corrupt {
		t.Fatalf("state of another job: %v", err)
	}
	// Garbage state.
	third := model.NewID()
	seed(third, control.JobRecord{Org: h.f.org1, Project: p, Job: third, Version: 1, State: json.RawMessage(`"x"`)})
	if _, _, err := h.store.Load(context.Background(), w, p, third); code(err) != model.Corrupt {
		t.Fatalf("garbage state: %v", err)
	}
	// The state names another organization.
	fourth := model.NewID()
	foreign, _ := json.Marshal(map[string]any{"version": model.Revision(1), "org": model.NewID(), "project": p, "job": fourth})
	seed(fourth, control.JobRecord{Org: h.f.org1, Project: p, Job: fourth, Version: 1, State: foreign})
	if _, _, err := h.store.Load(context.Background(), w, p, fourth); code(err) != model.Corrupt {
		t.Fatalf("state of another organization: %v", err)
	}
}

// ---------------------------------------------------------- own application

type ownApp struct {
	*fixture
	dir   string
	actor auth.Credential // the organization-wide administrator that built the fixture
}

func openOwn(t *testing.T) *ownApp {
	t.Helper()
	dir := t.TempDir()
	app, err := appcore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	o := &ownApp{fixture: &fixture{app: app, org1: model.NewID(), project1: model.NewID(), org2: model.NewID(), project2: model.NewID(), project1b: model.NewID(), passwords: "jobs own password 2026"}, dir: dir}
	t.Cleanup(func() { o.app.Close() })
	bindJobs(t, app.Control)
	boot, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	session, err := app.Auth.Bootstrap(ctx, boot, "jobs-own@example.test", o.passwords)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	o.actor = actor
	step := func(org model.ID, kind string, p auth.AdminPayload) {
		t.Helper()
		if err := admin(o.fixture, actor, org, kind, p); err != nil {
			t.Fatal(err)
		}
	}
	step(o.org1, "create_org", auth.AdminPayload{Name: "own"})
	step(o.org1, "create_project", auth.AdminPayload{ID: o.project1, Name: "application"})
	for _, u := range []struct{ email, perm string }{{"writer1@example.test", "policy.write"}, {"reader1@example.test", "telemetry.read"}} {
		id := model.NewID()
		step(o.org1, "create_user", auth.AdminPayload{ID: id, Email: u.email, Password: o.passwords})
		step(o.org1, "membership", auth.AdminPayload{UserID: id, Enabled: true})
		step(o.org1, "grant", auth.AdminPayload{UserID: id, ProjectID: o.project1, Permissions: []string{u.perm}, Enabled: true})
	}
	return o
}

// restart closes the whole application and opens it again over the same
// directory, as a process restart would.
func (o *ownApp) restart(t *testing.T) {
	t.Helper()
	if err := o.app.Close(); err != nil {
		t.Fatal(err)
	}
	app, err := appcore.Open(o.dir)
	if err != nil {
		t.Fatal(err)
	}
	o.app = app
	bindJobs(t, app.Control)
}

func TestJobServiceOverDurableControlAcrossRestartsAndErasure(t *testing.T) {
	ctx := context.Background()
	o := openOwn(t)
	h := newRealHFor(t, o.fixture, hm(11, 10, 0), jobID)
	w, r := h.writer(t), h.reader(t)
	p := o.project1
	def := hourly()
	key := jobsKey(hm(11, 0, 0))
	journal := []jobs.AttemptEvidence{
		record(p, 1, ev(runA, att1, key, 1, 1, "started", hm(11, 0, 5), nil)),
		record(p, 2, ev(runA, att1, key, 1, 2, "failed", hm(11, 0, 5), new(hm(11, 0, 20)))),
		record(p, 3, ev(runA, att2, key, 2, 3, "started", hm(11, 1, 0), nil)),
		record(p, 4, ev(runA, att2, key, 2, 4, "succeeded", hm(11, 1, 0), new(hm(11, 1, 30)))),
	}
	apply(t, h.svc, w, journal[0])
	apply(t, h.svc, w, journal[1])
	if _, err := h.svc.ObserveSchedule(ctx, w, jobs.ScheduleEvidence{CommandID: model.NewID(), Project: p, Job: jobID, Observer: model.ID{7}, ObservedAt: hm(11, 10, 0), CompleteThrough: hm(11, 10, 0), Healthy: true, Definition: &def}); err != nil {
		t.Fatal(err)
	}
	if report, err := h.svc.Health(ctx, r, p, jobID); err != nil || report.Health.Status != jobs.StatusFailed {
		t.Fatalf("failed attempt: %v %+v", err, report.Health)
	}
	// Connectivity drops: the loss is committed as an evidence gap in control.
	gap, err := o.app.Control.RecordEvidenceGap(ctx, model.EvidenceGap{Org: o.org1, Project: p, Group: model.ID{0xA1}, After: 2, Through: 3, Count: 1, Start: hm(11, 0, 30), End: hm(11, 0, 50), Signals: []model.Kind{model.JobAttempt}, Reason: "exporter_connectivity", RecordedAt: hm(11, 5, 0)})
	if err != nil {
		t.Fatal(err)
	}
	apply(t, h.svc, w, journal[2])
	if report, _ := h.svc.Health(ctx, r, p, jobID); report.Health.Status != jobs.StatusRunning || !report.Health.Complete {
		t.Fatalf("retry running after the gap: %+v", report.Health)
	}
	// The whole application restarts and the journal is redelivered.
	o.restart(t)
	h = newRealHFor(t, o.fixture, hm(11, 10, 0), jobID)
	w, r = h.writer(t), h.reader(t)
	for i, e := range journal {
		_, outcome := apply(t, h.svc, w, e)
		if i < 3 && outcome != jobs.Duplicate || i == 3 && outcome != jobs.Applied {
			t.Fatalf("journal record %d after restart: %v", i+1, outcome)
		}
	}
	for _, e := range journal {
		if _, outcome := apply(t, h.svc, w, e); outcome != jobs.Duplicate {
			t.Fatal("second redelivery not absorbed")
		}
	}
	report, err := h.svc.Health(ctx, r, p, jobID)
	if err != nil {
		t.Fatal(err)
	}
	st := report.State
	if report.Health.Status != jobs.StatusSucceeded || !report.Health.Complete || !hasReason(report.Health, jobs.ReasonRunRecovered) || st.Runs[runA].Status != jobs.RunRecovered {
		t.Fatalf("run not reconciled as recovered: %+v", report.Health)
	}
	if st.Attempts[att1].Effective() != jobs.AttemptFailed || st.Attempts[att2].Effective() != jobs.AttemptSucceeded || len(st.Attempts) != 2 || st.Version != 5 {
		t.Fatalf("attempt history: %+v version %d", st.Attempts, st.Version)
	}
	if len(report.Intervals) != 1 || report.Intervals[0].ID != gap.ID {
		t.Fatalf("the unknown interval is not annotated: %+v", report.Intervals)
	}
	// A correction commits its audit atomically with the state.
	fix := jobs.Correction{CommandID: model.NewID(), Project: p, Job: jobID, ExpectedVersion: st.Version, Attempt: att1, Version: 1, State: jobs.AttemptSucceeded, Reason: "data owner confirmed the output"}
	if _, err = h.svc.Correct(ctx, w, jobs.Correction{CommandID: model.NewID(), Project: p, Job: jobID, ExpectedVersion: st.Version + 3, Attempt: att1, Version: 1, State: jobs.AttemptSucceeded, Reason: "x"}); code(err) != model.Conflict {
		t.Fatalf("stale expected version: %v", err)
	}
	corrected, err := h.svc.Correct(ctx, w, fix)
	if err != nil || corrected.Version != st.Version+1 || corrected.Attempts[att1].Effective() != jobs.AttemptSucceeded {
		t.Fatalf("correction: %v", err)
	}
	if retry, err := h.svc.Correct(ctx, w, fix); err != nil || retry.Version != corrected.Version {
		t.Fatalf("retry of a committed correction: %v", err)
	}
	var audits []model.ControlAudit
	_ = o.app.Control.View(ctx, func(s control.State) error {
		for _, a := range s.Audits {
			if a.Action == "jobs.correct" {
				audits = append(audits, a)
			}
		}
		return nil
	})
	if len(audits) != 1 || audits[0].Principal != w.PrincipalID() || audits[0].Reason != fix.Reason || !reflect.DeepEqual(audits[0].Targets, []model.ID{jobID, att1}) {
		t.Fatalf("audits %+v", audits)
	}
	// Determinism: another restart reads back exactly the state that was answered.
	before, err := h.svc.Health(ctx, r, p, jobID)
	if err != nil {
		t.Fatal(err)
	}
	var liveBooks string
	_ = o.app.Control.View(ctx, func(s control.State) error {
		raw, _ := json.Marshal(s.JobBooks)
		liveBooks = string(raw)
		return nil
	})
	seed, _, err := o.app.Control.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	imported, err := control.OpenSeed(filepath.Join(t.TempDir(), "imported"), seed)
	if err != nil {
		t.Fatal(err)
	}
	var importedBooks string
	_ = imported.View(ctx, func(s control.State) error {
		raw, _ := json.Marshal(s.JobBooks)
		importedBooks = string(raw)
		return nil
	})
	imported.Close()
	if importedBooks != liveBooks {
		t.Fatalf("snapshot import changed the job books:\n%s\n%s", liveBooks, importedBooks)
	}
	o.restart(t)
	h = newRealHFor(t, o.fixture, hm(11, 10, 0), jobID)
	w, r = h.writer(t), h.reader(t)
	after, err := h.svc.Health(ctx, r, p, jobID)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("restart changed the answer: %v\n%+v\n%+v", err, before, after)
	}

	// Erasure drops the payload and keeps identity, version and command memory:
	// the job reads as no evidence at the same version, redelivery cannot bring
	// the erased history back, and new evidence builds on the preserved version.
	var dropped int
	if err = o.app.Control.Update(ctx, func(s *control.State) (e error) {
		dropped, e = control.DropRetiredJobBooks(s, o.org1, p, model.ID{0xdd, 1})
		return
	}); err != nil || dropped != 1 {
		t.Fatalf("erasure dropped %d: %v", dropped, err)
	}
	erased, err := h.svc.Health(ctx, r, p, jobID)
	if err != nil || erased.Version != corrected.Version || len(erased.State.Attempts) != 0 || erased.Health.Status != jobs.StatusUnknown || erased.Health.Complete {
		t.Fatalf("erased job: %v %+v", err, erased)
	}
	if _, outcome := apply(t, h.svc, w, journal[0]); outcome != jobs.Duplicate {
		t.Fatalf("redelivery after erasure: %v", outcome)
	}
	if got := h.load(t, w); len(got.Attempts) != 0 || got.Version != corrected.Version {
		t.Fatalf("redelivery resurrected erased evidence: %+v", got)
	}
	fresh := record(p, 5, ev(model.ID{0xD1}, model.ID{0xC9}, "manual.z", 1, 1, "started", hm(11, 5, 0), nil))
	now, outcome := apply(t, h.svc, w, fresh)
	if outcome != jobs.Applied || now.Version != corrected.Version+1 || len(now.Attempts) != 1 {
		t.Fatalf("new evidence after erasure: %v %+v", outcome, now)
	}
	if got := h.load(t, w); !reflect.DeepEqual(got, now) {
		t.Fatal("stored state differs after the first update over a tombstone")
	}
}
