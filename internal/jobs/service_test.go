// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package jobs_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/jobs"
	"soundpost/internal/model"
)

// ---------------------------------------------------------------- fixture
//
// Scopes come from the real auth service (appcore.Open); persistence is a fake
// jobs.Store that round-trips every state through JSON, so nothing that could
// not be persisted can pass. One application serves the whole test binary
// because opening it is the slow part.

type fixture struct {
	app                           *appcore.App
	org1, org2                    model.ID
	project1, project1b, project2 model.ID
	passwords                     string
}

var (
	shared     *fixture
	sharedOnce sync.Once
	sharedErr  error
	sharedDir  string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if shared != nil && shared.app != nil {
		shared.app.Close()
	}
	if sharedDir != "" {
		os.RemoveAll(sharedDir)
	}
	os.Exit(code)
}

func admin(f *fixture, actor auth.Credential, org model.ID, kind string, p auth.AdminPayload) error {
	p.Reason = "jobs behavior fixture"
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	var revision model.Revision
	if err := f.app.Control.View(context.Background(), func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		return err
	}
	_, err = f.app.Auth.AdminCommand(context.Background(), actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw})
	if err != nil {
		return fmt.Errorf("%s: %w", kind, err)
	}
	return nil
}

func getFixture(t *testing.T) *fixture {
	t.Helper()
	sharedOnce.Do(func() {
		f := &fixture{org1: model.NewID(), org2: model.NewID(), project1: model.NewID(), project1b: model.NewID(), project2: model.NewID(), passwords: "jobs fixture password 2026"}
		dir, err := os.MkdirTemp("", "jobs-fixture")
		if err != nil {
			sharedErr = err
			return
		}
		sharedDir = dir
		if f.app, err = appcore.Open(dir); err != nil {
			sharedErr = err
			return
		}
		shared = f
		ctx := context.Background()
		bootstrap, err := f.app.Control.BootstrapToken()
		if err != nil {
			sharedErr = err
			return
		}
		session, err := f.app.Auth.Bootstrap(ctx, bootstrap, "jobs-admin@example.test", f.passwords)
		if err != nil {
			sharedErr = err
			return
		}
		actor, err := f.app.Auth.Authenticate(ctx, session.Token)
		if err != nil {
			sharedErr = err
			return
		}
		steps := []func() error{
			func() error { return admin(f, actor, f.org1, "create_org", auth.AdminPayload{Name: "jobs one"}) },
			func() error {
				return admin(f, actor, f.org1, "create_project", auth.AdminPayload{ID: f.project1, Name: "application"})
			},
			func() error {
				return admin(f, actor, f.org1, "create_project", auth.AdminPayload{ID: f.project1b, Name: "second application"})
			},
			func() error { return admin(f, actor, f.org2, "create_org", auth.AdminPayload{Name: "jobs two"}) },
			func() error {
				return admin(f, actor, f.org2, "create_project", auth.AdminPayload{ID: f.project2, Name: "other application"})
			},
		}
		users := []struct {
			email   string
			org     model.ID
			project model.ID
			perm    string
		}{{"writer1@example.test", f.org1, f.project1, "policy.write"}, {"reader1@example.test", f.org1, f.project1, "telemetry.read"}, {"writer2@example.test", f.org2, f.project2, "policy.write"}, {"reader2@example.test", f.org2, f.project2, "telemetry.read"}}
		for _, u := range users {
			id := model.NewID()
			u := u
			steps = append(steps,
				func() error {
					return admin(f, actor, u.org, "create_user", auth.AdminPayload{ID: id, Email: u.email, Password: f.passwords})
				},
				func() error {
					return admin(f, actor, u.org, "membership", auth.AdminPayload{UserID: id, Enabled: true})
				},
				func() error {
					return admin(f, actor, u.org, "grant", auth.AdminPayload{UserID: id, ProjectID: u.project, Permissions: []string{u.perm}, Enabled: true})
				})
		}
		for _, step := range steps {
			if err := step(); err != nil {
				sharedErr = err
				return
			}
		}
	})
	if sharedErr != nil {
		t.Fatal(sharedErr)
	}
	return shared
}

func (f *fixture) scope(t *testing.T, email string, org, project model.ID, permission auth.Permission) auth.Scope {
	t.Helper()
	login, err := f.app.Auth.Login(context.Background(), email, f.passwords, "")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := f.app.Auth.Authenticate(context.Background(), login.Token)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := f.app.Auth.Authorize(context.Background(), cred, org, []model.ID{project}, permission)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

// ------------------------------------------------------------------ fakes

type fakeClock struct {
	mu sync.Mutex
	at model.UnixNano
}

func (c *fakeClock) Now() model.UnixNano { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *fakeClock) set(at model.UnixNano) {
	c.mu.Lock()
	c.at = at
	c.mu.Unlock()
}

type commandRecord struct {
	digest  model.Hash
	version model.Revision
}

type fakeStore struct {
	mu       sync.Mutex
	states   map[string][]byte
	commands map[model.ID]commandRecord
	audits   []jobs.Audit
	origins  []model.Cursor
	gaps     map[string][]model.EvidenceGap
	updates  int
	loads    int
	// fault injection
	failBefore   int
	loseAck      int
	beforeUpdate func()
}

func newFakeStore() *fakeStore {
	return &fakeStore{states: map[string][]byte{}, commands: map[model.ID]commandRecord{}, gaps: map[string][]model.EvidenceGap{}}
}
func skey(org, project, job model.ID) string {
	return org.String() + ":" + project.String() + ":" + job.String()
}

func (s *fakeStore) Load(_ context.Context, scope auth.Scope, project, job model.ID) (jobs.JobState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	raw, ok := s.states[skey(scope.OrgID(), project, job)]
	if !ok {
		return jobs.JobState{}, false, nil
	}
	var st jobs.JobState
	if err := json.Unmarshal(raw, &st); err != nil {
		return jobs.JobState{}, false, err
	}
	return st, true, nil
}

func (s *fakeStore) Update(_ context.Context, scope auth.Scope, cmd jobs.UpdateCommand) (jobs.UpdateResult, error) {
	if hook := s.beforeUpdate; hook != nil {
		hook()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failBefore > 0 {
		s.failBefore--
		return jobs.UpdateResult{}, model.Fail(model.Unavailable)
	}
	if rec, ok := s.commands[cmd.CommandID]; ok {
		if rec.digest != cmd.InputDigest {
			return jobs.UpdateResult{}, model.Fail(model.Conflict)
		}
		return jobs.UpdateResult{Version: rec.version, Replayed: true}, nil
	}
	key := skey(scope.OrgID(), cmd.Project, cmd.Job)
	var stored model.Revision
	if raw, ok := s.states[key]; ok {
		var st jobs.JobState
		if err := json.Unmarshal(raw, &st); err != nil {
			return jobs.UpdateResult{}, err
		}
		stored = st.Version
	}
	if stored != cmd.ExpectedVersion {
		return jobs.UpdateResult{}, model.Fail(model.Stale)
	}
	if cmd.Next.Version != cmd.ExpectedVersion+1 || cmd.Next.Org != scope.OrgID() || cmd.Next.Project != cmd.Project || cmd.Next.Job != cmd.Job {
		return jobs.UpdateResult{}, model.Fail(model.Invalid)
	}
	raw, err := json.Marshal(cmd.Next)
	if err != nil {
		return jobs.UpdateResult{}, err
	}
	s.states[key] = raw
	s.commands[cmd.CommandID] = commandRecord{cmd.InputDigest, cmd.Next.Version}
	s.updates++
	if cmd.Audit != nil {
		s.audits = append(s.audits, *cmd.Audit)
	}
	if cmd.Origin != nil {
		s.origins = append(s.origins, *cmd.Origin)
	}
	if s.loseAck > 0 {
		s.loseAck--
		return jobs.UpdateResult{}, model.Fail(model.Unavailable)
	}
	return jobs.UpdateResult{Version: cmd.Next.Version}, nil
}

func (s *fakeStore) Gaps(_ context.Context, scope auth.Scope, project model.ID) ([]model.EvidenceGap, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.EvidenceGap(nil), s.gaps[scope.OrgID().String()+":"+project.String()]...), nil
}
func (s *fakeStore) counters() (updates, loads int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updates, s.loads
}
func (s *fakeStore) snapshot(org, project, job model.ID) jobs.JobState {
	s.mu.Lock()
	defer s.mu.Unlock()
	var st jobs.JobState
	if raw, ok := s.states[skey(org, project, job)]; ok {
		if err := json.Unmarshal(raw, &st); err != nil {
			panic(err)
		}
	}
	return st
}

type fakeAuthorizer struct{ err error }

func (a fakeAuthorizer) Revalidate(context.Context, auth.Scope) error { return a.err }

type harness struct {
	f     *fixture
	store *fakeStore
	clock *fakeClock
	svc   *jobs.Service
}

func newHarness(t *testing.T, now model.UnixNano) *harness {
	t.Helper()
	f := getFixture(t)
	h := &harness{f: f, store: newFakeStore(), clock: &fakeClock{at: now}}
	h.svc = h.service(t)
	return h
}
func (h *harness) service(t *testing.T) *jobs.Service {
	t.Helper()
	svc, err := jobs.New(h.store, h.f.app.Auth, h.clock)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}
func (h *harness) writer(t *testing.T) auth.Scope {
	return h.f.scope(t, "writer1@example.test", h.f.org1, h.f.project1, auth.PolicyWrite)
}
func (h *harness) reader(t *testing.T) auth.Scope {
	return h.f.scope(t, "reader1@example.test", h.f.org1, h.f.project1, auth.Read)
}

func record(project model.ID, idx uint64, e model.JobAttemptEvent) jobs.AttemptEvidence {
	return jobs.AttemptEvidence{Project: project, Cursor: model.Cursor{Group: model.ID{0xA1}, Index: model.Uint64(idx)}, Record: model.ID{0xB1, byte(idx)}, Event: e}
}

func TestJobServiceConstruction(t *testing.T) {
	if _, err := jobs.New(nil, fakeAuthorizer{}, &fakeClock{}); code(err) != model.Invalid {
		t.Fatal("nil store accepted")
	}
	if _, err := jobs.New(newFakeStore(), nil, &fakeClock{}); code(err) != model.Invalid {
		t.Fatal("nil authorizer accepted")
	}
	if _, err := jobs.New(newFakeStore(), fakeAuthorizer{}, nil); code(err) != model.Invalid {
		t.Fatal("nil clock accepted")
	}
}

// --------------------------------------------------- crash/retry semantics

func TestJobServiceAppliesEvidenceExactlyOnceAcrossCrashes(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, hm(12, 0, 0))
	w := h.writer(t)
	p := h.f.project1
	started := ev(runA, att1, "manual.a", 1, 1, "started", hm(11, 0, 0), nil)

	t.Run("crash before commit leaves nothing and a retry applies once", func(t *testing.T) {
		h.store.failBefore = 1
		if _, _, err := h.svc.ApplyAttempt(ctx, w, record(p, 1, started)); code(err) != model.Unavailable {
			t.Fatalf("injected crash: %v", err)
		}
		if _, ok := h.store.states[skey(h.f.org1, p, jobID)]; ok {
			t.Fatal("state exists after a crash before commit")
		}
		state, outcome, err := h.svc.ApplyAttempt(ctx, w, record(p, 1, started))
		if err != nil || outcome != jobs.Applied || state.Version != 1 || len(state.Attempts) != 1 {
			t.Fatalf("retry: %v %v %+v", outcome, err, state.Version)
		}
	})
	t.Run("lost acknowledgement after commit makes the retry a no-op", func(t *testing.T) {
		failed := ev(runA, att1, "manual.a", 1, 2, "failed", hm(11, 0, 0), new(hm(11, 0, 9)))
		h.store.loseAck = 1
		if _, _, err := h.svc.ApplyAttempt(ctx, w, record(p, 2, failed)); code(err) != model.Unavailable {
			t.Fatalf("lost ack surfaced as %v", err)
		}
		updates, _ := h.store.counters()
		state, outcome, err := h.svc.ApplyAttempt(ctx, w, record(p, 2, failed))
		after, _ := h.store.counters()
		if err != nil || outcome != jobs.Duplicate || after != updates || state.Version != 2 || len(state.Attempts[att1].Events) != 2 || state.Attempts[att1].Terminal.State != jobs.AttemptFailed {
			t.Fatalf("retry after lost ack: %v %v updates %d->%d version %d", outcome, err, updates, after, state.Version)
		}
		// The same attempt event replayed from another journal position (for
		// example after a restore) is also absorbed by attempt identity.
		_, outcome, err = h.svc.ApplyAttempt(ctx, w, record(p, 77, failed))
		again, _ := h.store.counters()
		if err != nil || outcome != jobs.Duplicate || again != updates {
			t.Fatalf("replay at another cursor: %v %v", outcome, err)
		}
	})
	t.Run("the origin cursor is committed with the state", func(t *testing.T) {
		if len(h.store.origins) != 2 || h.store.origins[0].Index != 1 || h.store.origins[1].Index != 2 {
			t.Fatalf("origins %+v", h.store.origins)
		}
	})
	t.Run("the same journal record cannot be reused for different evidence", func(t *testing.T) {
		other := ev(runA, att2, "manual.a", 2, 3, "started", hm(11, 0, 30), nil)
		before := h.store.snapshot(h.f.org1, p, jobID)
		if _, _, err := h.svc.ApplyAttempt(ctx, w, record(p, 1, other)); code(err) != model.Conflict {
			t.Fatalf("command identity reused with another payload: %v", err)
		}
		if after := h.store.snapshot(h.f.org1, p, jobID); !reflect.DeepEqual(before, after) {
			t.Fatal("state changed")
		}
	})
	t.Run("evidence that contradicts history is rejected without a write", func(t *testing.T) {
		updates, _ := h.store.counters()
		bad := ev(runA, att1, "manual.a", 1, 9, "succeeded", hm(11, 0, 0), new(hm(11, 0, 9)))
		if _, _, err := h.svc.ApplyAttempt(ctx, w, record(p, 9, bad)); code(err) != model.Conflict {
			t.Fatalf("conflicting terminal: %v", err)
		}
		if after, _ := h.store.counters(); after != updates {
			t.Fatal("a rejected event wrote")
		}
	})
	t.Run("evidence from the future is refused", func(t *testing.T) {
		future := ev(runA, att2, "manual.a", 2, 4, "started", hm(12, 0, 0)+model.UnixNano(jobs.MaxFutureSkew)+1, nil)
		if _, _, err := h.svc.ApplyAttempt(ctx, w, record(p, 10, future)); code(err) != model.Invalid {
			t.Fatalf("%v", err)
		}
		// A scheduled-form key dated in the future would outrank every real occurrence.
		dated := ev(runA, att2, jobsKey(hm(12, 0, 0)+model.UnixNano(time.Hour)), 2, 5, "started", hm(11, 59, 0), nil)
		if _, _, err := h.svc.ApplyAttempt(ctx, w, record(p, 11, dated)); code(err) != model.Invalid {
			t.Fatalf("future occurrence key accepted: %v", err)
		}
	})
}

// workerApply retries retryable errors the way a journal worker does.
func workerApply(svc *jobs.Service, scope auth.Scope, e jobs.AttemptEvidence) (jobs.Outcome, error) {
	for range 200 {
		_, outcome, err := svc.ApplyAttempt(context.Background(), scope, e)
		if err == nil {
			return outcome, nil
		}
		var fault *model.Fault
		if !asFault(err, &fault) || !fault.Retryable {
			return "", err
		}
	}
	return "", fmt.Errorf("retries exhausted")
}
func asFault(err error, out **model.Fault) bool {
	f, ok := err.(*model.Fault)
	if ok {
		*out = f
	}
	return ok
}

func TestJobServiceConcurrentWritersLoseNothing(t *testing.T) {
	h := newHarness(t, hm(12, 0, 0))
	w := h.writer(t)
	p := h.f.project1
	const attempts = 24
	var wg sync.WaitGroup
	var applied, duplicates atomic.Int64
	errs := make(chan error, 4*attempts)
	for i := range attempts {
		attempt := model.ID{0xC0, byte(i)}
		for k, e := range []model.JobAttemptEvent{
			ev(runA, attempt, "manual.a", uint64(i+1), uint64(2*i+1), "started", hm(11, 0, i), nil),
			ev(runA, attempt, "manual.a", uint64(i+1), uint64(2*i+2), "failed", hm(11, 0, i), new(hm(11, 0, i)+5)),
		} {
			// Each record is delivered twice, concurrently, from distinct worker goroutines.
			for copyN := 0; copyN < 2; copyN++ {
				wg.Add(1)
				go func(idx uint64, e model.JobAttemptEvent) {
					defer wg.Done()
					outcome, err := workerApply(h.svc, w, record(p, idx, e))
					if err != nil {
						errs <- err
						return
					}
					if outcome == jobs.Applied {
						applied.Add(1)
					} else {
						duplicates.Add(1)
					}
				}(uint64(100+2*i+k), e)
			}
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	state := h.store.snapshot(h.f.org1, p, jobID)
	if len(state.Attempts) != attempts || len(state.Runs[runA].Attempts) != attempts || state.Version != 2*attempts || applied.Load() != 2*attempts {
		t.Fatalf("lost or duplicated updates: attempts %d version %d applied %d duplicates %d", len(state.Attempts), state.Version, applied.Load(), duplicates.Load())
	}
	for id, a := range state.Attempts {
		if a.Terminal == nil || !a.Started || len(a.Events) != 2 {
			t.Fatalf("attempt %v incomplete: %+v", id, a)
		}
	}
	if updates, _ := h.store.counters(); updates != 2*attempts {
		t.Fatalf("%d commits for %d distinct records", updates, 2*attempts)
	}
}

func TestJobServiceRetriesStaleVersionOnly(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, hm(12, 0, 0))
	w := h.writer(t)
	p := h.f.project1
	// A competing writer commits between this call's read and write.
	race := ev(runA, att2, "manual.a", 2, 1, "started", hm(11, 0, 30), nil)
	var fired atomic.Bool
	h.store.beforeUpdate = func() {
		if !fired.CompareAndSwap(false, true) {
			return
		}
		if _, _, err := h.svc.ApplyAttempt(ctx, w, record(p, 50, race)); err != nil {
			t.Error(err)
		}
	}
	mine := ev(runA, att1, "manual.a", 1, 1, "started", hm(11, 0, 0), nil)
	state, outcome, err := h.svc.ApplyAttempt(ctx, w, record(p, 51, mine))
	if err != nil || outcome != jobs.Applied || len(state.Attempts) != 2 || state.Version != 2 {
		t.Fatalf("stale write was not retried over the new state: %v %v %+v", outcome, err, state.Version)
	}
	// Exhausting the retries is retryable, never a silent loss.
	h.store.beforeUpdate = func() {
		h.store.mu.Lock()
		defer h.store.mu.Unlock()
		raw := h.store.states[skey(h.f.org1, p, jobID)]
		var st jobs.JobState
		_ = json.Unmarshal(raw, &st)
		st.Version++
		raw, _ = json.Marshal(st)
		h.store.states[skey(h.f.org1, p, jobID)] = raw
	}
	_, _, err = h.svc.ApplyAttempt(ctx, w, record(p, 52, ev(runA, model.ID{0xD0}, "manual.a", 3, 1, "started", hm(11, 0, 40), nil)))
	var fault *model.Fault
	if !asFault(err, &fault) || fault.Code != model.Unavailable || !fault.Retryable {
		t.Fatalf("contention exhaustion: %v", err)
	}
}

// A second worker delivers the very same journal record between this worker's
// read and its write: the store recognizes the command, nothing is applied
// twice, and the caller is told it was a duplicate, not that it applied.
func TestJobServiceDeliveryOfOneRecordByTwoWorkers(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, hm(12, 0, 0))
	w := h.writer(t)
	p := h.f.project1
	e := record(p, 1, ev(runA, att1, "manual.a", 1, 1, "failed", hm(11, 0, 0), new(hm(11, 0, 9))))
	var fired atomic.Bool
	var other jobs.Outcome
	h.store.beforeUpdate = func() {
		if !fired.CompareAndSwap(false, true) {
			return
		}
		var err error
		if _, other, err = h.svc.ApplyAttempt(ctx, w, e); err != nil {
			t.Error(err)
		}
	}
	state, outcome, err := h.svc.ApplyAttempt(ctx, w, e)
	if err != nil || other != jobs.Applied || outcome != jobs.Duplicate || state.Version != 1 || len(state.Attempts[att1].Events) != 1 {
		t.Fatalf("second worker: %v %v (first worker %v) version %d", outcome, err, other, state.Version)
	}
	if updates, _ := h.store.counters(); updates != 1 {
		t.Fatalf("%d commits for one record", updates)
	}
}

// ------------------------------------------------------------- isolation

func TestJobServiceScopeIsolation(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, hm(12, 0, 0))
	p := h.f.project1
	w, r := h.writer(t), h.reader(t)
	w2 := h.f.scope(t, "writer2@example.test", h.f.org2, h.f.project2, auth.PolicyWrite)
	r2 := h.f.scope(t, "reader2@example.test", h.f.org2, h.f.project2, auth.Read)

	if _, _, err := h.svc.ApplyAttempt(ctx, w, record(p, 1, ev(runA, att1, "manual.a", 1, 1, "failed", hm(11, 0, 0), new(hm(11, 0, 5))))); err != nil {
		t.Fatal(err)
	}
	pristine := h.store.snapshot(h.f.org1, p, jobID)

	t.Run("permission is enforced per operation", func(t *testing.T) {
		if _, _, err := h.svc.ApplyAttempt(ctx, r, record(p, 2, ev(runA, att2, "manual.a", 2, 2, "started", hm(11, 1, 0), nil))); code(err) != model.Forbidden {
			t.Fatalf("read scope wrote evidence: %v", err)
		}
		if _, err := h.svc.ObserveSchedule(ctx, r, jobs.ScheduleEvidence{CommandID: model.NewID(), Project: p, Job: jobID, Observer: observe, ObservedAt: hm(12, 0, 0), CompleteThrough: hm(12, 0, 0), Healthy: true}); code(err) != model.Forbidden {
			t.Fatalf("read scope observed schedule: %v", err)
		}
		if _, err := h.svc.Correct(ctx, r, jobs.Correction{CommandID: model.NewID(), Project: p, Job: jobID, Attempt: att1, Version: 1, State: jobs.AttemptSucceeded, Reason: "no"}); code(err) != model.Forbidden {
			t.Fatalf("read scope corrected: %v", err)
		}
		if _, err := h.svc.Health(ctx, w, p, jobID); code(err) != model.Forbidden {
			t.Fatalf("write scope read health: %v", err)
		}
		if !reflect.DeepEqual(pristine, h.store.snapshot(h.f.org1, p, jobID)) {
			t.Fatal("denied calls changed state")
		}
	})
	t.Run("another organization's scope cannot see or touch the project", func(t *testing.T) {
		if _, err := h.svc.Health(ctx, r2, p, jobID); code(err) != model.NotFound {
			t.Fatalf("foreign read: %v", err)
		}
		if _, _, err := h.svc.ApplyAttempt(ctx, w2, record(p, 3, ev(runA, att2, "manual.a", 2, 3, "failed", hm(11, 1, 0), new(hm(11, 1, 5))))); code(err) != model.NotFound {
			t.Fatalf("foreign write: %v", err)
		}
		if !reflect.DeepEqual(pristine, h.store.snapshot(h.f.org1, p, jobID)) {
			t.Fatal("foreign write changed state")
		}
	})
	t.Run("wrong scope is indistinguishable from not found", func(t *testing.T) {
		_, foreign := h.svc.Health(ctx, r2, p, jobID)                 // exists, other org
		_, otherProject := h.svc.Health(ctx, r, h.f.project1b, jobID) // other project, same org
		_, unknownJob := h.svc.Health(ctx, r, p, model.ID{0xEE})      // inside scope, never existed
		for name, err := range map[string]error{"foreign org": foreign, "foreign project": otherProject} {
			var a, b *model.Fault
			if !asFault(err, &a) || !asFault(unknownJob, &b) || a.Code != b.Code || a.SafeDetail != b.SafeDetail || a.Retryable != b.Retryable {
				t.Fatalf("%s distinguishable from a missing job: %v vs %v", name, err, unknownJob)
			}
		}
		if code(unknownJob) != model.NotFound {
			t.Fatalf("missing job: %v", unknownJob)
		}
	})
	t.Run("the same job ID in two organizations is two independent jobs", func(t *testing.T) {
		if _, _, err := h.svc.ApplyAttempt(ctx, w2, record(h.f.project2, 1, ev(runA, att1, "manual.a", 1, 1, "succeeded", hm(11, 0, 0), new(hm(11, 0, 5))))); err != nil {
			t.Fatal(err)
		}
		mine, err := h.svc.Health(ctx, r, p, jobID)
		if err != nil || mine.Health.Status != jobs.StatusFailed {
			t.Fatalf("org one: %v %+v", err, mine.Health)
		}
		theirs, err := h.svc.Health(ctx, r2, h.f.project2, jobID)
		if err != nil || theirs.Health.Status != jobs.StatusSucceeded {
			t.Fatalf("org two: %v %+v", err, theirs.Health)
		}
	})
	t.Run("a revoked or forged scope never reaches the store", func(t *testing.T) {
		denied, err := jobs.New(h.store, fakeAuthorizer{err: model.Fail(model.NotFound)}, h.clock)
		if err != nil {
			t.Fatal(err)
		}
		_, loadsBefore := h.store.counters()
		if _, _, err := denied.ApplyAttempt(ctx, w, record(p, 4, ev(runA, att2, "manual.a", 2, 4, "started", hm(11, 2, 0), nil))); code(err) != model.NotFound {
			t.Fatalf("revoked: %v", err)
		}
		if _, err := denied.Health(ctx, r, p, jobID); code(err) != model.NotFound {
			t.Fatalf("revoked read: %v", err)
		}
		if _, _, err := h.svc.ApplyAttempt(ctx, auth.Scope{}, record(p, 5, ev(runA, att2, "manual.a", 2, 5, "started", hm(11, 2, 0), nil))); err == nil {
			t.Fatal("zero scope accepted")
		}
		if _, loadsAfter := h.store.counters(); loadsAfter != loadsBefore {
			t.Fatal("store touched before authorization")
		}
	})
}

// ------------------------------------------------------------ corrections

func TestJobServiceCorrectionIsAuditedAndScopeDerived(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, hm(12, 0, 0))
	w := h.writer(t)
	p := h.f.project1
	if _, _, err := h.svc.ApplyAttempt(ctx, w, record(p, 1, ev(runA, att1, "manual.a", 1, 1, "failed", hm(11, 0, 0), new(hm(11, 0, 5))))); err != nil {
		t.Fatal(err)
	}
	base := h.store.snapshot(h.f.org1, p, jobID)
	original := *base.Attempts[att1].Terminal
	command := model.NewID()
	fix := jobs.Correction{CommandID: command, Project: p, Job: jobID, ExpectedVersion: base.Version, Attempt: att1, Version: 1, State: jobs.AttemptSucceeded, Reason: "data owner confirmed the output"}

	if _, err := h.svc.Correct(ctx, w, func() jobs.Correction { c := fix; c.ExpectedVersion = base.Version + 5; return c }()); code(err) != model.Conflict {
		t.Fatalf("stale expected version: %v", err)
	}
	if _, err := h.svc.Correct(ctx, w, func() jobs.Correction { c := fix; c.Job = model.ID{0xEE}; return c }()); code(err) != model.NotFound {
		t.Fatalf("unknown job: %v", err)
	}
	if _, err := h.svc.Correct(ctx, w, func() jobs.Correction { c := fix; c.Attempt = model.ID{0xEE}; return c }()); code(err) != model.NotFound {
		t.Fatalf("unknown attempt: %v", err)
	}
	state, err := h.svc.Correct(ctx, w, fix)
	if err != nil {
		t.Fatal(err)
	}
	a := state.Attempts[att1]
	if *a.Terminal != original || a.Effective() != jobs.AttemptSucceeded || len(a.Corrections) != 1 || a.Corrections[0].Actor != w.PrincipalID() || a.Corrections[0].At != hm(12, 0, 0) {
		t.Fatalf("correction: %+v", a)
	}
	if len(h.store.audits) != 1 || h.store.audits[0].Principal != w.PrincipalID() || h.store.audits[0].Action != "jobs.correct" || h.store.audits[0].Reason != fix.Reason || !reflect.DeepEqual(h.store.audits[0].Targets, []model.ID{jobID, att1}) {
		t.Fatalf("audit committed with the state: %+v", h.store.audits)
	}
	// A retry of the same command after success (lost acknowledgement) is idempotent
	// even though the job version has moved on.
	updates, _ := h.store.counters()
	retried, err := h.svc.Correct(ctx, w, fix)
	if after, _ := h.store.counters(); err != nil || after != updates || retried.Version != state.Version || len(h.store.audits) != 1 {
		t.Fatalf("retry of a committed correction: %v updates %d->%d", err, updates, after)
	}
	// A newer version supersedes; the first stays in the history.
	second := fix
	second.CommandID, second.ExpectedVersion, second.Version, second.State, second.Reason = model.NewID(), state.Version, 2, jobs.AttemptCancelled, "retracted"
	newer, err := h.svc.Correct(ctx, w, second)
	if err != nil || len(newer.Attempts[att1].Corrections) != 2 || newer.Attempts[att1].Effective() != jobs.AttemptCancelled || *newer.Attempts[att1].Terminal != original {
		t.Fatalf("second correction: %v", err)
	}
	stale := fix
	stale.CommandID, stale.ExpectedVersion, stale.Version, stale.Reason = model.NewID(), newer.Version, 1, "different content under an old version"
	if _, err := h.svc.Correct(ctx, w, stale); code(err) != model.Conflict {
		t.Fatalf("older correction version: %v", err)
	}
	if got := h.store.snapshot(h.f.org1, p, jobID); !reflect.DeepEqual(got, newer) {
		t.Fatal("persisted state differs from the returned state")
	}
}

// ------------------------------------------------- observer and health reads

func TestScheduleObserverAndCurrentHealthReads(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, hm(12, 3, 0))
	w, r := h.writer(t), h.reader(t)
	p := h.f.project1
	def := hourly()
	observe := func(at, through model.UnixNano, healthy bool, d *jobs.Definition) (jobs.JobState, error) {
		return h.svc.ObserveSchedule(ctx, w, jobs.ScheduleEvidence{CommandID: model.NewID(), Project: p, Job: jobID, Observer: model.ID{7}, ObservedAt: at, CompleteThrough: through, Healthy: healthy, Definition: d})
	}

	if _, err := h.svc.Health(ctx, r, p, jobID); code(err) != model.NotFound {
		t.Fatalf("job with no state: %v", err)
	}
	if _, err := observe(hm(12, 3, 0)+model.UnixNano(jobs.MaxFutureSkew)+1, hm(12, 3, 0), true, &def); code(err) != model.Invalid {
		t.Fatalf("future observer clock accepted: %v", err)
	}
	if _, ok := h.store.states[skey(h.f.org1, p, jobID)]; ok {
		t.Fatal("rejected observation created state")
	}
	if _, err := observe(hm(12, 3, 0), hm(12, 3, 0), true, func() *jobs.Definition {
		d := def
		d.EffectiveFrom = hm(12, 3, 0) + model.UnixNano(jobs.MaxDefinitionLead) + 1
		return &d
	}()); code(err) != model.Invalid {
		t.Fatalf("definition effective unreasonably far ahead: %v", err)
	}

	t.Run("a scheduled job with only observer evidence is missed, naming its evidence", func(t *testing.T) {
		state, err := observe(hm(12, 3, 0), hm(12, 3, 0), true, &def)
		if err != nil || state.Version != 1 || state.Org != h.f.org1 {
			t.Fatalf("%v", err)
		}
		report, err := h.svc.Health(ctx, r, p, jobID)
		if err != nil || report.Health.Status != jobs.StatusMissed || report.Health.Evidence.Observer == nil || report.Version != 1 || report.EvaluatedAt != hm(12, 3, 0) {
			t.Fatalf("%v %+v", err, report.Health)
		}
	})
	t.Run("an older observation from a restarted observer does not regress anything", func(t *testing.T) {
		before := h.store.snapshot(h.f.org1, p, jobID)
		state, err := observe(hm(11, 0, 0), hm(11, 0, 0), true, nil)
		if err != nil || !reflect.DeepEqual(state, before) {
			t.Fatalf("older observation changed state: %v", err)
		}
	})
	t.Run("silence from the observer turns a success into unknown, and its return restores it", func(t *testing.T) {
		if _, _, err := h.svc.ApplyAttempt(ctx, w, record(p, 1, ev(runA, att1, jobsKey(hm(12, 0, 0)), 1, 1, "started", hm(12, 0, 1), nil))); err != nil {
			t.Fatal(err)
		}
		if _, _, err := h.svc.ApplyAttempt(ctx, w, record(p, 2, ev(runA, att1, jobsKey(hm(12, 0, 0)), 1, 2, "succeeded", hm(12, 0, 1), new(hm(12, 0, 5))))); err != nil {
			t.Fatal(err)
		}
		if report, err := h.svc.Health(ctx, r, p, jobID); err != nil || report.Health.Status != jobs.StatusSucceeded || !report.Health.Complete {
			t.Fatalf("%v %+v", err, report.Health)
		}
		h.clock.set(hm(12, 14, 0))
		report, err := h.svc.Health(ctx, r, p, jobID)
		if err != nil || report.Health.Status != jobs.StatusUnknown || !hasReason(report.Health, jobs.ReasonObserverStale) {
			t.Fatalf("observer outage: %v %+v", err, report.Health)
		}
		if _, err := observe(hm(12, 13, 0), hm(12, 13, 0), true, nil); err != nil {
			t.Fatal(err)
		}
		if report, err := h.svc.Health(ctx, r, p, jobID); err != nil || report.Health.Status != jobs.StatusSucceeded || !report.Health.Complete {
			t.Fatalf("observer back: %v %+v", err, report.Health)
		}
	})
	t.Run("committed project evidence gaps make the read unknown", func(t *testing.T) {
		gapKey := h.f.org1.String() + ":" + p.String()
		gap := func(org, project model.ID, signals ...model.Kind) model.EvidenceGap {
			return model.EvidenceGap{ID: model.NewID(), Org: org, Project: project, Group: model.ID{0xA1}, After: 1, Through: 9, Count: 8, Start: hm(12, 1, 0), End: hm(12, 2, 0), Signals: signals, Reason: "expired", RecordedAt: hm(12, 14, 0)}
		}
		h.store.gaps[gapKey] = []model.EvidenceGap{gap(h.f.org1, p, model.Log), gap(h.f.org2, p), gap(h.f.org1, h.f.project1b)}
		report, err := h.svc.Health(ctx, r, p, jobID)
		if err != nil || report.Health.Status != jobs.StatusSucceeded || len(report.Intervals) != 0 {
			t.Fatalf("an unrelated gap (other signal, org or project) changed the verdict: %v %+v", err, report.Health)
		}
		relevant := gap(h.f.org1, p, model.JobAttempt)
		h.store.gaps[gapKey] = append(h.store.gaps[gapKey], relevant)
		report, err = h.svc.Health(ctx, r, p, jobID)
		if err != nil || report.Health.Status != jobs.StatusUnknown || !hasReason(report.Health, jobs.ReasonEvidenceGap) || !reflect.DeepEqual(report.Health.Evidence.Gaps, []model.ID{relevant.ID}) || len(report.Intervals) != 1 {
			t.Fatalf("job-attempt gap: %v %+v", err, report.Health)
		}
		// A gap with no signal list affects every signal, including jobs.
		h.store.gaps[gapKey] = []model.EvidenceGap{gap(h.f.org1, p)}
		if report, err = h.svc.Health(ctx, r, p, jobID); err != nil || report.Health.Status != jobs.StatusUnknown {
			t.Fatalf("all-signal gap: %v", err)
		}
	})
}

// --------------------------------------------------------- journey

// TestJobDurableRetryJourney replays the 06.03 retry journey through the real
// scope authority and a persisting fake store: a failed attempt, a retry that
// succeeds, a dropped exporter connection recorded as an evidence gap, a
// service restart that redelivers the whole journal, and reconciliation. It is
// not the SDK/scheduler/control-persistence smoke (no such production binding
// exists yet); see docs/user/jobs.md.
func TestJobDurableRetryJourney(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, hm(11, 10, 0))
	w, r := h.writer(t), h.reader(t)
	p := h.f.project1
	def := hourly()
	key := jobsKey(hm(11, 0, 0))
	journal := []jobs.AttemptEvidence{
		record(p, 1, ev(runA, att1, key, 1, 1, "started", hm(11, 0, 5), nil)),
		record(p, 2, ev(runA, att1, key, 1, 2, "failed", hm(11, 0, 5), new(hm(11, 0, 20)))),
		// The exporter loses connectivity here: nothing arrives from 11:00:30 to 11:00:50.
		record(p, 3, ev(runA, att2, key, 2, 3, "started", hm(11, 1, 0), nil)),
		record(p, 4, ev(runA, att2, key, 2, 4, "succeeded", hm(11, 1, 0), new(hm(11, 1, 30)))),
	}
	apply := func(svc *jobs.Service, e jobs.AttemptEvidence) jobs.Outcome {
		t.Helper()
		_, outcome, err := svc.ApplyAttempt(ctx, w, e)
		if err != nil {
			t.Fatal(err)
		}
		return outcome
	}
	apply(h.svc, journal[0])
	apply(h.svc, journal[1])
	if _, err := h.svc.ObserveSchedule(ctx, w, jobs.ScheduleEvidence{CommandID: model.NewID(), Project: p, Job: jobID, Observer: model.ID{7}, ObservedAt: hm(11, 10, 0), CompleteThrough: hm(11, 10, 0), Healthy: true, Definition: &def}); err != nil {
		t.Fatal(err)
	}
	if report, _ := h.svc.Health(ctx, r, p, jobID); report.Health.Status != jobs.StatusFailed {
		t.Fatalf("failed attempt: %+v", report.Health)
	}

	// Connectivity drops: the loss is committed as an evidence gap before the retry's start arrives.
	gap := model.EvidenceGap{ID: model.NewID(), Org: h.f.org1, Project: p, Group: model.ID{0xA1}, After: 2, Through: 2, Count: 1, Start: hm(11, 0, 30), End: hm(11, 0, 50), Signals: []model.Kind{model.JobAttempt}, Reason: "exporter_connectivity", RecordedAt: hm(11, 5, 0)}
	h.store.gaps[h.f.org1.String()+":"+p.String()] = []model.EvidenceGap{gap}
	apply(h.svc, journal[2])
	if report, _ := h.svc.Health(ctx, r, p, jobID); report.Health.Status != jobs.StatusRunning || !report.Health.Complete {
		// The gap is before the retry started: it cannot hide anything about the running attempt.
		t.Fatalf("retry running after the gap: %+v", report.Health)
	}

	// The service restarts and the journal is redelivered from the start.
	restarted := h.service(t)
	for i, e := range journal {
		outcome := apply(restarted, e)
		if i < 3 && outcome != jobs.Duplicate || i == 3 && outcome != jobs.Applied {
			t.Fatalf("journal record %d after restart: %v", i+1, outcome)
		}
	}
	updates, _ := h.store.counters()
	for _, e := range journal {
		if apply(restarted, e) != jobs.Duplicate {
			t.Fatal("second redelivery not absorbed")
		}
	}
	if after, _ := h.store.counters(); after != updates {
		t.Fatal("redelivery wrote")
	}

	report, err := restarted.Health(ctx, r, p, jobID)
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
	if len(report.Intervals) != 1 || report.Intervals[0].ID != gap.ID || report.Intervals[0].End != hm(11, 0, 50) {
		t.Fatalf("the unknown interval is not annotated: %+v", report.Intervals)
	}

	// A later gap, after the retry's result, can hide a newer failure: unknown again.
	later := model.EvidenceGap{ID: model.NewID(), Org: h.f.org1, Project: p, Group: model.ID{0xA1}, After: 4, Through: 9, Count: 5, Start: hm(11, 2, 0), End: hm(11, 3, 0), Signals: []model.Kind{model.JobAttempt}, Reason: "exporter_connectivity", RecordedAt: hm(11, 5, 0)}
	h.store.gaps[h.f.org1.String()+":"+p.String()] = []model.EvidenceGap{gap, later}
	report, err = restarted.Health(ctx, r, p, jobID)
	if err != nil || report.Health.Status != jobs.StatusUnknown || !hasReason(report.Health, jobs.ReasonEvidenceGap) || len(report.Intervals) != 2 {
		t.Fatalf("gap after the result: %v %+v", err, report.Health)
	}
	if st.Attempts[att1].Effective() != jobs.AttemptFailed {
		t.Fatal("history changed")
	}

}
