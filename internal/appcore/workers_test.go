// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/notify"
	"soundpost/internal/replica"
	"soundpost/internal/rules"
	"soundpost/profiles"
)

// workerNow is the fixed instant of every worker test: 90 seconds into a minute
// grid, so exactly one grid point (the minute before) is due.
const (
	workerGrid = model.UnixNano(1_800_000_000_000_000_000 + int64(time.Hour)) // 1.8e18 ns is a whole number of minutes
	workerNow  = workerGrid + model.UnixNano(30*time.Second)
)

type fixedClock struct{ v atomic.Int64 }

func (c *fixedClock) Now() model.UnixNano { return model.UnixNano(c.v.Load()) }

// switchFence is the leadership fence a test controls: Fence is refused while
// notLeader is set, and ValidateFence is refused once deposed is set.
type switchFence struct {
	inner     appcore.LeaderFence
	notLeader atomic.Bool
	deposed   atomic.Bool
	broken    atomic.Bool
	fences    atomic.Int64
}

func (f *switchFence) Fence(ctx context.Context) (replica.FenceToken, error) {
	f.fences.Add(1)
	if f.notLeader.Load() {
		return replica.FenceToken{}, replica.ErrStale
	}
	return f.inner.Fence(ctx)
}

func (f *switchFence) ValidateFence(ctx context.Context, t replica.FenceToken) error {
	if f.deposed.Load() {
		return replica.ErrStale
	}
	if f.broken.Load() {
		return model.Fail(model.Unavailable)
	}
	return f.inner.ValidateFence(ctx, t)
}

type staticRules []rules.Rule

func (s staticRules) Rules(context.Context, auth.Scope, model.ID) ([]rules.Rule, error) {
	return append([]rules.Rule(nil), s...), nil
}

type hookRouting struct {
	binding appcore.NotificationBinding
	onCall  func()
}

func (r hookRouting) Routing(context.Context, auth.Scope, model.ID) (appcore.NotificationBinding, bool, error) {
	if r.onCall != nil {
		r.onCall()
	}
	return r.binding, true, nil
}

type countingSender struct {
	mu    sync.Mutex
	calls int
}

func (s *countingSender) Send(context.Context, auth.Scope, notify.Delivery) (notify.Outcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return notify.Outcome{Kind: notify.OutcomeAccepted, ProviderID: "provider-message-1"}, nil
}

func (s *countingSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type workerNode struct {
	t       *testing.T
	ctx     context.Context
	app     *appcore.App
	org     model.ID
	project model.ID
	dest    model.ID
	token   string
	clock   *fixedClock
	feature string
	actor   auth.Credential
	user    model.ID
}

func (n *workerNode) command(kind string, p auth.AdminPayload) {
	n.t.Helper()
	var revision model.Revision
	if err := n.app.Control.View(n.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		n.t.Fatal(err)
	}
	p.Reason = "workers wiring"
	raw, _ := json.Marshal(p)
	if _, err := n.app.Auth.AdminCommand(n.ctx, n.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: n.org, Kind: kind, Payload: raw}); err != nil {
		n.t.Fatal(kind, err)
	}
}

// addProject creates a project and grants the worker principal telemetry.read on it.
func (n *workerNode) addProject(id model.ID) {
	n.t.Helper()
	n.command("create_project", auth.AdminPayload{ID: id, Name: "workers wiring"})
	n.command("grant", auth.AdminPayload{UserID: n.user, ProjectID: id, Permissions: []string{string(auth.Read)}, Enabled: true})
}

func newWorkerNode(t *testing.T) *workerNode {
	t.Helper()
	ctx := context.Background()
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	boot, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(ctx, boot, "workers@example.test", "worker wiring password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	n := &workerNode{t: t, ctx: ctx, app: app, actor: actor, user: session.User, org: model.NewID(), project: model.NewID(), dest: model.NewID(), clock: &fixedClock{}}
	n.clock.v.Store(int64(workerNow))
	n.command("create_org", auth.AdminPayload{Name: "workers wiring"})
	n.command("membership", auth.AdminPayload{UserID: session.User, Enabled: true})
	n.addProject(n.project)
	cfg := `{"type":"webhook","endpoint":"https://hooks.example.test/notify","enabled":true}`
	n.command("destination", auth.AdminPayload{ID: n.dest, Config: json.RawMessage(cfg), Secret: "SECRET-DESTINATION-TEXT-71c2"})
	n.token = session.Token
	n.feature = featureSetOf(t, "promql-prometheus-3.13.5")
	return n
}

func featureSetOf(t *testing.T, profileID string) string {
	t.Helper()
	files, err := profiles.Query()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := fs.ReadFile(files, profileID+".json")
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		FeatureSets []struct {
			ID string `json:"id"`
		} `json:"feature_sets"`
	}
	if json.Unmarshal(raw, &p) != nil || len(p.FeatureSets) == 0 {
		t.Fatal("no feature set")
	}
	return p.FeatureSets[0].ID
}

// alertRule is a rule that fires on its first evaluation: vector(1) is a
// non-empty vector at every instant, with no stored telemetry needed.
func (n *workerNode) alertRule() rules.Rule { return n.alertRuleIn(n.project) }

func (n *workerNode) alertRuleIn(project model.ID) rules.Rule {
	return rules.Rule{ID: model.NewID(), Project: project, Version: 1, Kind: rules.KindAlert, Profile: "promql-prometheus-3.13.5", FeatureSet: n.feature,
		Expression: "vector(1)", Interval: time.Minute, Severity: "critical"}
}

func (n *workerNode) config(extra func(*appcore.WorkerConfig)) appcore.WorkerConfig {
	cfg := appcore.WorkerConfig{
		Orgs:     []model.ID{n.org},
		Clock:    n.clock,
		Interval: 10 * time.Millisecond,
	}
	if extra != nil {
		extra(&cfg)
	}
	return cfg
}

func (n *workerNode) fence() *switchFence {
	return &switchFence{inner: n.app.Control.ReplicaGroup()}
}

func (n *workerNode) admin() auth.Scope { return n.adminFor(n.project) }

func (n *workerNode) adminFor(project model.ID) auth.Scope {
	n.t.Helper()
	cred, err := n.app.Auth.Authenticate(n.ctx, n.token)
	if err != nil {
		n.t.Fatal(err)
	}
	scope, err := n.app.Auth.Authorize(n.ctx, cred, n.org, []model.ID{project}, auth.OrgAdmin)
	if err != nil {
		n.t.Fatal(err)
	}
	return scope
}

func (n *workerNode) book(rule rules.Rule) (control.RuleBook, bool) {
	n.t.Helper()
	book, found, err := n.app.Control.RuleBook(n.ctx, n.adminFor(rule.Project), rule.Project, rule.ID)
	if err != nil {
		n.t.Fatal(err)
	}
	return book, found
}

func (n *workerNode) deliveries(phase string) []control.DeliveryRecord {
	n.t.Helper()
	recs, err := n.app.Control.Deliveries(n.ctx, n.admin(), n.project, phase, n.clock.Now(), 0)
	if err != nil {
		n.t.Fatal(err)
	}
	return recs
}

func (n *workerNode) tick(w *appcore.Workers) appcore.PassReport {
	n.t.Helper()
	rep := w.Tick(n.ctx)
	if len(rep.Errors) > 0 {
		n.t.Fatalf("pass errors: %+v", rep.Errors)
	}
	return rep
}

func TestWorkersCommitADueRuleEvaluationExactlyOnce(t *testing.T) {
	n := newWorkerNode(t)
	rule := n.alertRule()
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) { c.Rules = staticRules{rule} }))
	if err != nil {
		t.Fatal(err)
	}
	if _, found := n.book(rule); found {
		t.Fatal("setup: the rule has a committed book before any tick")
	}
	first := n.tick(w)
	if !first.Leader || first.Evaluated != 1 {
		t.Fatalf("first tick: %+v", first)
	}
	book, found := n.book(rule)
	if !found || len(book.Versions) != 1 || book.Versions[0].Last == nil || book.Versions[0].Last.At != workerGrid {
		t.Fatalf("the evaluation was not committed at the grid point %d: found=%v %+v", workerGrid, found, book)
	}
	revision := book.Versions[0].StateRevision
	second := n.tick(w)
	if second.Evaluated != 0 {
		t.Fatalf("second tick evaluated again: %+v", second)
	}
	again, _ := n.book(rule)
	if len(again.Versions[0].Recent) != 1 || again.Versions[0].StateRevision != revision {
		t.Fatalf("the evaluation was committed more than once: %+v", again.Versions[0])
	}
}

func TestWorkersNonLeaderCommitsNothing(t *testing.T) {
	n := newWorkerNode(t)
	rule := n.alertRule()
	fence := n.fence()
	fence.notLeader.Store(true)
	sender := &countingSender{}
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) { c.Rules = staticRules{rule}; c.Fence = fence; c.Sender = sender }))
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if rep := w.Tick(n.ctx); rep.Leader || rep.Evaluated != 0 || len(rep.Errors) != 0 {
			t.Fatalf("a non-leader acted: %+v", rep)
		}
	}
	if _, found := n.book(rule); found {
		t.Fatal("a node without the fence committed a rule evaluation")
	}
	if sender.count() != 0 {
		t.Fatal("a node without the fence sent")
	}
}

// conditionNode drives the whole chain: a rule fires, the condition is consumed,
// the notification is decided into the outbox and sent.
func (n *workerNode) conditionConfig(rule rules.Rule, sender notify.Sender, fence appcore.LeaderFence, onRouting func()) appcore.WorkerConfig {
	return n.config(func(c *appcore.WorkerConfig) {
		c.Rules = staticRules{rule}
		c.Sender = sender
		c.Fence = fence
		c.Routing = hookRouting{binding: appcore.NotificationBinding{Policy: model.ID{0xf1}, Revision: 1, Config: notify.DefaultConfig(), Recipients: []model.ID{n.dest}}, onCall: onRouting}
	})
}

func TestWorkersConsumeAConditionAndSendItsNotificationOnce(t *testing.T) {
	n := newWorkerNode(t)
	rule := n.alertRule()
	sender := &countingSender{}
	w, err := n.app.NewWorkers(n.conditionConfig(rule, sender, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	first := n.tick(w)
	if first.Consumed != 1 || first.Submitted == 0 {
		t.Fatalf("the condition was not consumed and decided: %+v", first)
	}
	if sender.count() != 1 {
		t.Fatalf("sender calls after the first tick = %d, want 1 (report %+v)", sender.count(), first)
	}
	accepted := n.deliveries(control.DeliveryAccepted)
	if len(accepted) != 1 || accepted[0].Provider != "provider-message-1" || accepted[0].Recipient == nil || *accepted[0].Recipient != n.dest {
		t.Fatalf("the send was not recorded as accepted for the destination: %+v", accepted)
	}
	n.clock.v.Add(int64(time.Second))
	n.tick(w)
	n.tick(w)
	if sender.count() != 1 {
		t.Fatalf("a repeated pass re-sent: %d calls", sender.count())
	}
	if again := n.deliveries(control.DeliveryAccepted); len(again) != 1 {
		t.Fatalf("accepted deliveries after repeats: %d", len(again))
	}
}

func TestWorkersDeposedLeaderSendsNothing(t *testing.T) {
	n := newWorkerNode(t)
	rule := n.alertRule()
	// Tick one is the leader's, with no sender: the notification is decided and
	// queued, nothing leaves the node.
	w1, err := n.app.NewWorkers(n.conditionConfig(rule, nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if rep := n.tick(w1); rep.Consumed != 1 || rep.Submitted == 0 || rep.Attempted != 0 {
		t.Fatalf("setup tick: %+v", rep)
	}
	pending := len(n.deliveries(control.DeliveryPending))
	if pending == 0 {
		t.Fatal("setup: no delivery is waiting")
	}
	// Tick two is a node that holds the lease at the start of the pass and loses
	// it mid-pass, after the stages before the send have run.
	fence := n.fence()
	sender := &countingSender{}
	w2, err := n.app.NewWorkers(n.conditionConfig(rule, sender, fence, func() { fence.deposed.Store(true) }))
	if err != nil {
		t.Fatal(err)
	}
	rep := w2.Tick(n.ctx)
	if !rep.Leader || !rep.Deposed || rep.Attempted != 0 {
		t.Fatalf("a deposed pass: %+v", rep)
	}
	if sender.count() != 0 {
		t.Fatalf("a deposed leader sent %d notifications", sender.count())
	}
	if got := len(n.deliveries(control.DeliveryPending)); got != pending {
		t.Fatalf("pending deliveries changed from %d to %d under a deposed leader", pending, got)
	}
	if len(n.deliveries(control.DeliveryAccepted)) != 0 {
		t.Fatal("a delivery was accepted under a deposed leader")
	}
}

func TestWorkersRunStopsOnCancelWithoutLeakingGoroutines(t *testing.T) {
	n := newWorkerNode(t)
	rule := n.alertRule()
	before := runtime.NumGoroutine()
	var passes atomic.Int64
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) {
		c.Rules = staticRules{rule}
		c.Observe = func(appcore.PassReport) { passes.Add(1) }
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(n.ctx)
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	deadline := time.Now().Add(30 * time.Second)
	for passes.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if passes.Load() < 2 {
		t.Fatalf("the runner ran %d passes", passes.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the runner did not stop after cancellation")
	}
	stopped := passes.Load()
	time.Sleep(100 * time.Millisecond)
	if passes.Load() != stopped {
		t.Fatal("the runner kept passing after it returned")
	}
	deadline = time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := runtime.NumGoroutine(); got > before {
		t.Fatalf("goroutines before=%d after=%d", before, got)
	}
	if _, found := n.book(rule); !found {
		t.Fatal("the running workers never evaluated the rule")
	}
}

func TestWorkersBoundRulesPerPassAndRotate(t *testing.T) {
	n := newWorkerNode(t)
	set := staticRules{n.alertRule(), n.alertRule(), n.alertRule()}
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) { c.Rules = set; c.MaxRules = 1 }))
	if err != nil {
		t.Fatal(err)
	}
	for i := range set {
		if rep := n.tick(w); rep.Evaluated != 1 {
			t.Fatalf("tick %d evaluated %d rules, want exactly 1 (the per-pass bound)", i, rep.Evaluated)
		}
	}
	for _, r := range set {
		if _, found := n.book(r); !found {
			t.Fatalf("rule %s was starved by the rotation", r.ID)
		}
	}
	if rep := n.tick(w); rep.Evaluated != 0 {
		t.Fatalf("a fourth tick re-evaluated: %+v", rep)
	}
}

// An organization that does not exist, or that has been retired, yields no system
// scope: the pass reports the closed auth error and commits nothing.
func TestWorkersServeNoOrganizationThatEnded(t *testing.T) {
	n := newWorkerNode(t)
	rule := n.alertRule()
	for name, org := range map[string]model.ID{"unknown": model.NewID(), "retired": n.org} {
		if name == "retired" {
			if err := n.app.Control.Update(n.ctx, func(st *model.ControlState) error {
				if st.RetiredOrgs == nil {
					st.RetiredOrgs = map[string]model.ID{}
				}
				st.RetiredOrgs[n.org.String()] = model.NewID()
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		cfg := n.config(func(c *appcore.WorkerConfig) { c.Rules = staticRules{rule}; c.Orgs = []model.ID{org} })
		w, err := n.app.NewWorkers(cfg)
		if err != nil {
			t.Fatal(err)
		}
		rep := w.Tick(n.ctx)
		if !rep.Leader || len(rep.Errors) == 0 || rep.Evaluated != 0 || rep.Consumed != 0 {
			t.Fatalf("%s: report %+v", name, rep)
		}
		for _, e := range rep.Errors {
			if e.Stage != appcore.StageAuth || e.Code != string(model.NotFound) {
				t.Fatalf("%s: error %+v", name, e)
			}
		}
		if _, found := n.book(rule); found {
			t.Fatalf("%s: a worker committed for an organization that ended", name)
		}
	}
}

// The scope is re-derived every pass: a rule evaluated while the organization was live
// is followed by nothing once it is retired.
func TestWorkersStopAtTheNextPassWhenTheOrganizationIsRetired(t *testing.T) {
	n := newWorkerNode(t)
	rule := n.alertRule()
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) { c.Rules = staticRules{rule}; c.Orgs = nil }))
	if err != nil {
		t.Fatal(err)
	}
	if rep := n.tick(w); rep.Evaluated != 1 {
		t.Fatalf("first pass: %+v", rep)
	}
	n.clock.v.Add(int64(time.Minute))
	if err = n.app.Control.Update(n.ctx, func(st *model.ControlState) error {
		if st.RetiredOrgs == nil {
			st.RetiredOrgs = map[string]model.ID{}
		}
		st.RetiredOrgs[n.org.String()] = model.NewID()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rep := w.Tick(n.ctx)
	if rep.Evaluated != 0 || len(rep.Errors) != 0 {
		t.Fatalf("a pass after the organization was retired: %+v", rep)
	}
	book, found := n.book(rule)
	if !found || len(book.Versions) != 1 || len(book.Versions[0].Recent) != 1 {
		t.Fatalf("book after retirement: found=%t %+v", found, book)
	}
}

// With no organization configured the runner serves every organization in control state,
// and everything it commits is audited as the system principal, never as a human.
func TestWorkersServeEveryOrganizationAsTheSystemPrincipal(t *testing.T) {
	n := newWorkerNode(t)
	rule := n.alertRule()
	cfg := n.config(func(c *appcore.WorkerConfig) { c.Rules = staticRules{rule}; c.Orgs = nil })
	w, err := n.app.NewWorkers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	before := n.auditCount()
	if rep := n.tick(w); rep.Evaluated != 1 || rep.Consumed != 1 {
		t.Fatalf("pass: %+v", rep)
	}
	system, human := 0, 0
	if err = n.app.Control.View(n.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits[before:] {
			switch a.Principal {
			case auth.SystemPrincipal(n.org):
				system++
			case n.user:
				human++
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if system == 0 || human != 0 {
		t.Fatalf("audits since the pass began: %d by %s, %d by a human", system, auth.SystemRunner, human)
	}
}

func (n *workerNode) auditCount() int {
	n.t.Helper()
	var count int
	if err := n.app.Control.View(n.ctx, func(st model.ControlState) error { count = len(st.Audits); return nil }); err != nil {
		n.t.Fatal(err)
	}
	return count
}

func TestNewWorkersValidatesItsConfiguration(t *testing.T) {
	n := newWorkerNode(t)
	for name, cfg := range map[string]appcore.WorkerConfig{
		"zero org":                   {Orgs: []model.ID{{}}},
		"zero org beside a real one": {Orgs: []model.ID{n.org, {}}},
	} {
		if _, err := n.app.NewWorkers(cfg); err == nil {
			t.Fatalf("%s: accepted", name)
		} else {
			var f *model.Fault
			if !errors.As(err, &f) || f.Code != model.Invalid {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
}

func TestWorkersServeProjectsInRotationWithinTheBound(t *testing.T) {
	n := newWorkerNode(t)
	second := model.NewID()
	n.addProject(second)
	set := staticRules{n.alertRuleIn(n.project), n.alertRuleIn(second)}
	// One source of rules for both projects, filtered to the project asked about.
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) { c.Rules = byProject(set); c.MaxProjects = 1 }))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if rep := n.tick(w); rep.Projects != 1 || rep.Evaluated != 1 {
			t.Fatalf("tick %d: %+v, want one project and one evaluation", i, rep)
		}
	}
	for _, r := range set {
		if _, found := n.book(r); !found {
			t.Fatalf("project %s was starved by the rotation", r.Project)
		}
	}
}

type byProject staticRules

func (b byProject) Rules(_ context.Context, _ auth.Scope, project model.ID) ([]rules.Rule, error) {
	var out []rules.Rule
	for _, r := range b {
		if r.Project == project {
			out = append(out, r)
		}
	}
	return out, nil
}

func TestWorkersBoundConsumptionPerPass(t *testing.T) {
	n := newWorkerNode(t)
	set := staticRules{n.alertRule(), n.alertRule()}
	sender := &countingSender{}
	cfg := n.conditionConfig(set[0], sender, nil, nil)
	cfg.Rules = set
	cfg.ConsumeLimit = 1
	w, err := n.app.NewWorkers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := n.tick(w)
	if first.Evaluated != 2 || first.Consumed != 1 || first.Submitted != 2 || sender.count() != 1 {
		t.Fatalf("first tick (two conditions, consume limit 1): %+v, sends %d", first, sender.count())
	}
	second := n.tick(w)
	if second.Evaluated != 0 || second.Consumed != 1 || second.Submitted != 2 || sender.count() != 2 {
		t.Fatalf("second tick: %+v, sends %d", second, sender.count())
	}
	if third := n.tick(w); third.Consumed != 0 || third.Submitted != 0 || sender.count() != 2 {
		t.Fatalf("third tick did more work: %+v, sends %d", third, sender.count())
	}
}

func TestWorkersBoundNotificationDecisionsPerPass(t *testing.T) {
	n := newWorkerNode(t)
	set := staticRules{n.alertRule(), n.alertRule()}
	sender := &countingSender{}
	cfg := n.conditionConfig(set[0], sender, nil, nil)
	cfg.Rules = set
	cfg.NotifyLimit = 1
	w, err := n.app.NewWorkers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := n.tick(w)
	if first.Consumed != 2 || first.Submitted != 2 || sender.count() != 1 {
		t.Fatalf("first tick (two conditions, notify limit 1): %+v, sends %d", first, sender.count())
	}
	second := n.tick(w)
	if second.Consumed != 0 || second.Submitted != 2 || sender.count() != 2 {
		t.Fatalf("second tick: %+v, sends %d", second, sender.count())
	}
	if third := n.tick(w); third.Submitted != 0 || sender.count() != 2 {
		t.Fatalf("third tick did more work: %+v, sends %d", third, sender.count())
	}
}

func TestWorkersRunBacksOffWhilePassesFail(t *testing.T) {
	n := newWorkerNode(t)
	var passes atomic.Int64
	cfg := n.config(func(c *appcore.WorkerConfig) {
		c.Interval = 10 * time.Millisecond
		c.MaxBackoff = 400 * time.Millisecond
		c.Observe = func(appcore.PassReport) { passes.Add(1) }
	})
	cfg.Orgs = []model.ID{model.NewID()}
	w, err := n.app.NewWorkers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(n.ctx, 700*time.Millisecond)
	defer cancel()
	w.Run(ctx)
	// Without backoff this would be about 70 passes; doubling from 10ms gives 7.
	if got := passes.Load(); got < 3 || got > 12 {
		t.Fatalf("%d passes in 700ms with every pass failing: not backing off", got)
	}
}

func TestWorkersBringDeliveryStatesToTheCutoverMode(t *testing.T) {
	n := newWorkerNode(t)
	rule := n.alertRule()
	sender := &countingSender{}
	// The shadow phase is seeded as committed control state (the barrier
	// evidence flow is notify's own concern, tested there).
	record, err := json.Marshal(control.CutoverRecord{Org: n.org, Project: n.project, ID: model.NewID(), Old: model.ID{0x01}, New: model.ID{0x02}, Revision: 1, Phase: control.CutoverShadow, Epoch: 1, EnteredAt: n.clock.Now(),
		Frontier: []control.CutoverFrontier{{Source: model.ID{0x03}, Version: 1, Cursor: model.Cursor{Group: model.ID{0x04}, Index: 1}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = n.app.Control.Update(n.ctx, func(st *control.State) error {
		if st.CutoverBooks == nil {
			st.CutoverBooks = map[string]json.RawMessage{}
		}
		st.CutoverBooks[n.org.String()+":"+n.project.String()] = record
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w, err := n.app.NewWorkers(n.conditionConfig(rule, sender, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	n.tick(w)
	recs, err := n.app.Control.PolicyRecords(n.ctx, n.admin(), n.project)
	if err != nil || len(recs) != 1 {
		t.Fatalf("policy records: %d %v", len(recs), err)
	}
	var state notify.PolicyState
	if err = json.Unmarshal(recs[0].State, &state); err != nil {
		t.Fatal(err)
	}
	if state.Mode != notify.ModeShadow {
		t.Fatalf("the delivery state is %q in the shadow phase", state.Mode)
	}
	if sender.count() != 0 {
		t.Fatalf("a shadow project sent %d notifications", sender.count())
	}
}

func TestWorkersRefuseAnotherProjectsRule(t *testing.T) {
	n := newWorkerNode(t)
	other := model.NewID()
	n.addProject(other)
	// The source hands the same rule to every project it is asked about; only the
	// rule's own project may run it.
	rule := n.alertRuleIn(other)
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) { c.Rules = staticRules{rule} }))
	if err != nil {
		t.Fatal(err)
	}
	rep := w.Tick(n.ctx)
	if rep.Projects != 2 || rep.Evaluated != 1 || len(rep.Errors) != 1 || rep.Errors[0].Stage != appcore.StageRules || rep.Errors[0].Code != string(model.Invalid) || rep.Errors[0].Project == other {
		t.Fatalf("report: %+v", rep)
	}
	if _, found := n.book(rule); !found {
		t.Fatal("the rule was not evaluated in its own project")
	}
	if _, found, err := n.app.Control.RuleBook(n.ctx, n.admin(), n.project, rule.ID); err != nil || found {
		t.Fatalf("the rule has a book under another project: found=%v err=%v", found, err)
	}
}

type countingRules struct{ calls atomic.Int64 }

func (c *countingRules) Rules(context.Context, auth.Scope, model.ID) ([]rules.Rule, error) {
	c.calls.Add(1)
	return nil, nil
}

func TestWorkersLeaseLostBetweenProjectsStopsBeforeTheNextProject(t *testing.T) {
	n := newWorkerNode(t)
	n.addProject(model.NewID())
	fence := n.fence()
	source := &countingRules{}
	cfg := n.conditionConfig(n.alertRule(), nil, fence, func() { fence.deposed.Store(true) })
	cfg.Rules = source
	w, err := n.app.NewWorkers(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The first project finishes with nothing to decide (no rule, no condition),
	// so no fenced effect notices that the lease went away while its routing was
	// asked; the second project must not be served at all.
	rep := w.Tick(n.ctx)
	if !rep.Leader || !rep.Deposed || rep.Projects != 2 || len(rep.Errors) != 0 {
		t.Fatalf("report: %+v", rep)
	}
	if got := source.calls.Load(); got != 1 {
		t.Fatalf("the rule source was asked %d times: a project was served after the lease was lost", got)
	}
}

func TestWorkersReportAnUnprovableLeaseAndDoNothing(t *testing.T) {
	n := newWorkerNode(t)
	rule := n.alertRule()
	fence := n.fence()
	fence.broken.Store(true)
	w, err := n.app.NewWorkers(n.config(func(c *appcore.WorkerConfig) { c.Rules = staticRules{rule}; c.Fence = fence }))
	if err != nil {
		t.Fatal(err)
	}
	rep := w.Tick(n.ctx)
	if !rep.Leader || rep.Deposed || rep.Evaluated != 0 || len(rep.Errors) != 1 || rep.Errors[0].Stage != appcore.StageFence || rep.Errors[0].Code != string(model.Unavailable) {
		t.Fatalf("report: %+v", rep)
	}
	if _, found := n.book(rule); found {
		t.Fatal("a pass that could not prove its lease committed")
	}
}
