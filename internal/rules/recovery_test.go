// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"github.com/arynyklas/soundpost/internal/replica"
)

// ctl is the real control machine (activated single-voter Raft group, the rule
// dispatcher bound, real auth scopes) the recovery tests run against: leases are
// the group's, commits go through Store.Transact, state is read back through the
// same store. Only the query engine and the data group are scripted here; the
// integration test covers those for real.
type ctl struct {
	t       *testing.T
	ctx     context.Context
	dir     string
	store   *control.Store
	svc     *auth.Service
	token   string
	cred    auth.Credential
	org     model.ID
	project model.ID
	user    model.ID
}

var authNow = time.Unix(1_800_000_000, 0)

func newCtl(t *testing.T) *ctl {
	t.Helper()
	c := &ctl{t: t, ctx: context.Background(), dir: t.TempDir(), org: model.NewID(), project: model.NewID()}
	t.Cleanup(func() {
		if c.store != nil {
			c.store.Close()
		}
	})
	c.open()
	boot, err := c.store.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.svc.Bootstrap(c.ctx, boot, "owner@example.test", "a long test password 2026")
	if err != nil {
		t.Fatal(err)
	}
	c.token = session.Token
	if c.cred, err = c.svc.Authenticate(c.ctx, c.token); err != nil {
		t.Fatal(err)
	}
	c.command("create_org", auth.AdminPayload{Name: "rules", Reason: "fixture"})
	c.command("create_project", auth.AdminPayload{ID: c.project, Name: "p1", Reason: "fixture"})
	c.user = session.User
	c.command("membership", auth.AdminPayload{UserID: session.User, Enabled: true, Reason: "fixture"})
	c.command("grant", auth.AdminPayload{UserID: session.User, ProjectID: c.project, Enabled: true, Permissions: []string{string(auth.Read)}, Reason: "fixture"})
	return c
}

func (c *ctl) open() {
	c.t.Helper()
	var err error
	if c.store, err = control.Open(c.dir); err != nil {
		c.t.Fatal(err)
	}
	if c.svc, err = auth.NewService(auth.AuthDependencies{Control: c.store, Now: func() time.Time { return authNow }}); err != nil {
		c.t.Fatal(err)
	}
	if err = c.store.EnableSingle(c.ctx, filepath.Join(c.dir, "raft-control")); err != nil {
		c.t.Fatal(err)
	}
	if err = c.store.BindRuleEvaluation(); err != nil {
		c.t.Fatal(err)
	}
	if err = c.store.BindRetention(); err != nil {
		c.t.Fatal(err)
	}
}

// reopen is a process restart: the control store closes and reopens from disk,
// with a new Raft term and a fresh authentication service.
func (c *ctl) reopen() {
	c.t.Helper()
	if err := c.store.Close(); err != nil {
		c.t.Fatal(err)
	}
	c.open()
	var err error
	if c.cred, err = c.svc.Authenticate(c.ctx, c.token); err != nil {
		c.t.Fatal(err)
	}
}

func (c *ctl) command(kind string, p auth.AdminPayload) {
	c.t.Helper()
	var revision model.Revision
	if err := c.store.View(c.ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
		c.t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	if _, err := c.svc.AdminCommand(c.ctx, c.cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: c.org, Kind: kind, Payload: raw}); err != nil {
		c.t.Fatal(kind, err)
	}
}

// admin is the project-scoped worker principal's control scope; reader its read scope.
func (c *ctl) admin() auth.Scope {
	c.t.Helper()
	s, err := c.svc.Authorize(c.ctx, c.cred, c.org, []model.ID{c.project}, auth.OrgAdmin)
	if err != nil {
		c.t.Fatal(err)
	}
	return s
}
func (c *ctl) reader() auth.Scope {
	c.t.Helper()
	s, err := c.svc.Authorize(c.ctx, c.cred, c.org, []model.ID{c.project}, auth.Read)
	if err != nil {
		c.t.Fatal(err)
	}
	return s
}
func (c *ctl) lease() replica.FenceToken {
	c.t.Helper()
	token, err := c.store.ReplicaGroup().Fence(c.ctx)
	if err != nil {
		c.t.Fatal(err)
	}
	return token
}

func (c *ctl) alert(forD, hold time.Duration) Rule {
	r := alertRule(forD, hold)
	r.ID, r.Project = model.NewID(), c.project
	return r
}

func (c *ctl) recording() Rule {
	r := recordingRule()
	r.ID, r.Project = model.NewID(), c.project
	return r
}

func (c *ctl) evaluator(exec QueryExecutor, clock Clock, options ...Option) *Evaluator {
	return NewEvaluator(exec, NewStateStore(c.store), append([]Option{WithClock(clock), WithFencer(c.store.ReplicaGroup())}, options...)...)
}
func (c *ctl) committer() *Committer { return NewCommitter(c.store, c.store.ReplicaGroup()) }

func (c *ctl) book(rule Rule) control.RuleBook {
	c.t.Helper()
	b, ok, err := c.store.RuleBook(c.ctx, c.admin(), c.project, rule.ID)
	if err != nil || !ok {
		c.t.Fatalf("rule book: %v %v", ok, err)
	}
	return b
}

func (c *ctl) outputs(rule Rule, phase string) []control.RuleOutput {
	c.t.Helper()
	out, err := c.store.RuleOutputs(c.ctx, c.admin(), c.project, rule.ID, phase, 0)
	if err != nil {
		c.t.Fatal(err)
	}
	return out
}

func (c *ctl) state(rule Rule) State {
	c.t.Helper()
	s, err := NewStateStore(c.store).Read(c.ctx, c.reader(), rule.ID)
	if err != nil {
		c.t.Fatal(err)
	}
	return s
}

type mutClock struct{ v atomic.Int64 }

func (m *mutClock) Now() model.UnixNano { return model.UnixNano(m.v.Load()) }
func (m *mutClock) set(seconds int64)   { m.v.Store(seconds * int64(time.Second)) }
func newClock(seconds int64) *mutClock  { m := &mutClock{}; m.set(seconds); return m }
func canonicalOf(t *testing.T, ev Evaluation) string {
	t.Helper()
	raw, _, err := ev.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// present reports a vector with one series while the predicate holds for the
// scheduled time.
func presentWhile(project model.ID, calls *[]int64, when func(seconds int64) bool) *fakeExec {
	return &fakeExec{fn: func(req query.Request) (query.Result, error) {
		seconds := int64(req.Evaluation.Time / sec)
		*calls = append(*calls, seconds)
		if when(seconds) {
			return vectorResult(project, elem(0, "job", "api<&>")), nil
		}
		return vectorResult(project), nil
	}}
}

// A stale lease is rejected, a replay of (rule version, at) returns the committed
// evaluation without duplicated effects, and a conflicting later payload for the
// same identity cannot overwrite the first.
func TestFenceAndIdempotentEvaluation(t *testing.T) {
	c := newCtl(t)
	rule := c.alert(0, 0)
	var calls []int64
	exec := presentWhile(c.project, &calls, func(s int64) bool { return s == 60 })
	clock := newClock(65)
	e := c.evaluator(exec, clock)
	committer := c.committer()
	lease := c.lease()

	first, err := e.Evaluate(c.ctx, c.reader(), rule, 60*sec, lease)
	if err != nil {
		t.Fatal(err)
	}
	res, err := committer.Commit(c.ctx, c.admin(), first, lease)
	if err != nil || res.Phase != "applied" {
		t.Fatalf("commit: %+v %v", res, err)
	}
	pending := c.outputs(rule, control.RulePhasePending)
	if len(pending) != 1 || pending[0].Kind != control.RuleOutputCondition || !pending[0].Notify || c.book(rule).Versions[0].StateRevision != 1 {
		t.Fatalf("effects of the first commit: %+v", pending)
	}

	// Replay: much later, with different data, the committed evaluation comes
	// back byte for byte (wall-clock observation included), nothing is queried,
	// and committing it again changes nothing.
	clock.set(9999)
	replayed, err := e.Evaluate(c.ctx, c.reader(), rule, 60*sec, lease)
	if err != nil {
		t.Fatal(err)
	}
	if canonicalOf(t, replayed) != canonicalOf(t, first) || replayed.ObservedAt != 65*sec || len(calls) != 1 {
		t.Fatalf("committed evaluation not returned verbatim (%d queries)", len(calls))
	}
	again, err := committer.Commit(c.ctx, c.admin(), replayed, lease)
	if err != nil || again.Revision != res.Revision {
		t.Fatalf("replayed commit: %+v vs %+v (%v)", again, res, err)
	}
	if got := c.outputs(rule, ""); len(got) != 1 || c.book(rule).Versions[0].StateRevision != 1 {
		t.Fatalf("a replay duplicated effects: %d outputs", len(got))
	}

	// A conflicting later payload for the same identity (here: another
	// observation, as a second evaluator that raced would produce) is rejected
	// and the committed payload is untouched.
	rival := first
	rival.ObservedAt = 70 * sec
	rival.Members = []model.Labels{}
	rival.Conditions = []ConditionIntent{}
	if _, err = committer.Commit(c.ctx, c.admin(), rival, lease); code(err) != model.Conflict {
		t.Fatalf("conflicting replay payload: %v", err)
	}
	after, err := e.Evaluate(c.ctx, c.reader(), rule, 60*sec, lease)
	if err != nil || canonicalOf(t, after) != canonicalOf(t, first) || len(c.outputs(rule, "")) != 1 {
		t.Fatalf("a conflicting payload changed the committed evaluation: %v", err)
	}

	// Stale lease: the group no longer vouches for it, so neither the evaluator
	// nor the committer acts; control rejects it too, without a fence.
	stale := lease
	stale.Term--
	if _, err = e.Evaluate(c.ctx, c.reader(), rule, 120*sec, stale); code(err) != model.Stale {
		t.Fatalf("evaluate under a stale lease: %v", err)
	}
	clock.set(125)
	next, err := e.Evaluate(c.ctx, c.reader(), rule, 120*sec, lease)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = committer.Commit(c.ctx, c.admin(), next, stale); code(err) != model.Stale {
		t.Fatalf("commit under a stale lease: %v", err)
	}
	unfenced := NewCommitter(c.store, nil)
	newer := lease
	newer.Term++
	if _, err = unfenced.Commit(c.ctx, c.admin(), next, newer); err != nil {
		t.Fatalf("a newer leader's commit: %v", err)
	}
	clock.set(185)
	third, err := e.Evaluate(c.ctx, c.reader(), rule, 180*sec, lease)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = unfenced.Commit(c.ctx, c.admin(), third, lease); code(err) != model.Stale {
		t.Fatalf("the deposed leader committed after the new leader: %v", err)
	}
	if book := c.book(rule); book.Versions[0].StateRevision != 2 || book.Fence.Term != newer.Term {
		t.Fatalf("book after fencing: %+v", book)
	}
	// Evaluation of a rule whose version was changed in place is refused.
	changed := rule
	changed.Expression = "up == 0"
	if _, err = e.Evaluate(c.ctx, c.reader(), changed, 60*sec, lease); code(err) != model.Conflict {
		t.Fatalf("version reused for another definition: %v", err)
	}
}

// admitter is a C03 stand-in with the one property recording depends on: a batch
// is identified by its ID and hash, and admitting it again returns the original
// receipt. It records what is durably "stored".
type admitter struct {
	mu          sync.Mutex
	stored      map[model.ID]model.Receipt
	batches     map[model.ID]model.Batch
	calls       int
	lookups     int
	lostResp    bool // durable, but the caller sees an error
	unavailable bool // not durable, caller sees an error
	next        uint64
}

func newAdmitter() *admitter {
	return &admitter{stored: map[model.ID]model.Receipt{}, batches: map[model.ID]model.Batch{}, next: 100}
}

func (a *admitter) Admit(_ context.Context, b model.Batch) (model.Receipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.unavailable {
		return model.Receipt{}, model.Fail(model.Unavailable)
	}
	raw, _ := model.CanonicalJSON(b)
	hash := model.HashCanonical(raw)
	r, ok := a.stored[b.ID]
	if ok && r.Hash != hash {
		return model.Receipt{}, model.Fail(model.Conflict)
	}
	if !ok {
		a.next++
		r = model.Receipt{Version: 1, BatchID: b.ID, Hash: hash, Cursor: model.Cursor{Group: model.ID{7}, Index: model.Uint64(a.next)}}
		a.stored[b.ID], a.batches[b.ID] = r, b
	}
	if a.lostResp {
		return model.Receipt{}, model.Fail(model.Timeout)
	}
	return r, nil
}

func (a *admitter) LookupReceipt(_ context.Context, b model.Batch) (model.Receipt, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lookups++
	r, ok := a.stored[b.ID]
	return r, ok, nil
}

func (a *admitter) records() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, b := range a.batches {
		n += len(b.Records)
	}
	return n
}

// crashyOutbox fails the next N settles to a phase, as a process crash between
// the two durable steps would.
type crashyOutbox struct {
	Outbox
	crash map[string]int
}

func (o *crashyOutbox) Settle(ctx context.Context, scope auth.Scope, lease replica.FenceToken, item control.RuleOutput, update control.RuleOutputApply) (control.Result, error) {
	if o.crash[update.To] > 0 {
		o.crash[update.To]--
		return control.Result{}, errors.New("process crashed")
	}
	return o.Outbox.Settle(ctx, scope, lease, item, update)
}

func recordingFixture(t *testing.T) (*ctl, Rule, *Evaluator, *Committer, *mutClock) {
	t.Helper()
	c := newCtl(t)
	rule := c.recording()
	one := model.FloatBits(math.Float64bits(1.5))
	exec := &fakeExec{fn: func(query.Request) (query.Result, error) {
		return vectorResult(c.project, query.VectorElement{Labels: labels("__name__", "up", "job", "api"), Sample: query.Sample{Float: &one}}), nil
	}}
	clock := newClock(65)
	return c, rule, c.evaluator(exec, clock, WithProducer(producer())), c.committer(), clock
}

// The durable recording ACK happens, then the process dies before the outbox
// learns of it, at either durable step. Retry preserves exactly one admitted
// batch and sample, and the stored provenance is the evaluation's input cursors.
func TestRecordingCrashAfterAdmission(t *testing.T) {
	c, rule, e, committer, _ := recordingFixture(t)
	lease := c.lease()
	ev, err := e.Evaluate(c.ctx, c.reader(), rule, 60*sec, lease)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Recording) != 1 || len(ev.Recorded) != 1 {
		t.Fatalf("recording evaluation: %d intents %d samples (%s/%s)", len(ev.Recording), len(ev.Recorded), ev.Outcome, ev.Reason)
	}
	if _, err = committer.Commit(c.ctx, c.admin(), ev, lease); err != nil {
		t.Fatal(err)
	}
	adm := newAdmitter()
	crashy := &crashyOutbox{Outbox: NewOutboxStore(c.store), crash: map[string]int{control.RulePhaseAdmitted: 1, control.RulePhaseFinalized: 1}}
	worker, err := NewOutputWorker(adm, crashy, adm, c.store.ReplicaGroup())
	if err != nil {
		t.Fatal(err)
	}

	// Crash 1: ACK durable, outbox never told.
	if _, err = worker.Flush(c.ctx, c.admin(), lease, 10); err == nil {
		t.Fatal("the simulated crash was not observed")
	}
	if adm.calls != 1 || len(adm.stored) != 1 || len(c.outputs(rule, control.RulePhasePending)) != 1 {
		t.Fatalf("after crash 1: calls=%d stored=%d pending=%d", adm.calls, len(adm.stored), len(c.outputs(rule, control.RulePhasePending)))
	}
	// Crash 2: the retry re-admits (same batch, same receipt), records the
	// receipt, and dies before finalizing.
	if _, err = worker.Flush(c.ctx, c.admin(), lease, 10); err == nil {
		t.Fatal("the second simulated crash was not observed")
	}
	if adm.calls != 2 || len(adm.stored) != 1 || len(c.outputs(rule, control.RulePhaseAdmitted)) != 1 {
		t.Fatalf("after crash 2: calls=%d stored=%d admitted=%d", adm.calls, len(adm.stored), len(c.outputs(rule, control.RulePhaseAdmitted)))
	}
	// Recovery: only the finalization is left, and nothing is admitted again.
	report, err := worker.Flush(c.ctx, c.admin(), lease, 10)
	if err != nil {
		t.Fatal(err)
	}
	recordingCountAfterCrashRetry := adm.records()
	if adm.calls != 2 || len(report.Finalized) != 1 || len(report.Admitted) != 1 || len(report.Retried) != 0 || len(report.Suppressed) != 0 {
		t.Fatalf("recovery: calls=%d report=%+v", adm.calls, report)
	}
	if recordingCountAfterCrashRetry != 1 || len(adm.stored) != 1 {
		t.Fatal("unknown input recovered or recording replay duplicated")
	}
	done := c.outputs(rule, control.RulePhaseFinalized)
	if len(done) != 1 || done[0].Receipt == nil || *done[0].Receipt != report.Admitted[0] || !reflect.DeepEqual(done[0].Inputs, ev.Cursors) || done[0].Rule != rule.ID || done[0].At != 60*sec {
		t.Fatalf("stored provenance: %+v (want inputs %+v)", done, ev.Cursors)
	}
	for _, b := range adm.batches {
		m := b.Records[0].Payload.Metric
		if len(b.Records) != 1 || m.Name != rule.RecordName || m.Value == nil || *m.Value != model.FloatBits(math.Float64bits(1.5)) || b.Records[0].ObservedAt != 60*sec || b.ID != done[0].ID {
			t.Fatalf("admitted sample: %+v", b)
		}
	}
	// Nothing left to do; a further flush is a no-op.
	if report, err = worker.Flush(c.ctx, c.admin(), lease, 10); err != nil || len(report.Finalized)+len(report.Retried)+len(report.Suppressed) != 0 || adm.calls != 2 {
		t.Fatalf("idle flush: %+v %v calls=%d", report, err, adm.calls)
	}
}

// An admission whose response is lost is ambiguous: C03's authenticated receipt
// lookup decides. A found receipt finalizes without a second admission; none
// found leaves the output pending to be re-admitted.
func TestRecordingAmbiguousAdmissionUsesReceiptLookup(t *testing.T) {
	c, rule, e, committer, clock := recordingFixture(t)
	lease := c.lease()
	for _, at := range []int64{60, 120} {
		clock.set(at + 5)
		ev, err := e.Evaluate(c.ctx, c.reader(), rule, model.UnixNano(at)*sec, lease)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = committer.Commit(c.ctx, c.admin(), ev, lease); err != nil {
			t.Fatal(err)
		}
	}
	adm := newAdmitter()
	worker, err := NewOutputWorker(adm, NewOutboxStore(c.store), adm, c.store.ReplicaGroup())
	if err != nil {
		t.Fatal(err)
	}
	// Both outputs: not durable, caller sees unavailable. Nothing is finalized and
	// nothing is stored; both stay pending.
	adm.unavailable = true
	report, err := worker.Flush(c.ctx, c.admin(), lease, 1)
	if err != nil || len(report.Retried) != 1 || len(report.Finalized) != 0 || adm.lookups != 1 {
		t.Fatalf("not durable: %+v %v lookups=%d", report, err, adm.lookups)
	}
	// Durable but the ACK is lost: the lookup finds the receipt, so exactly one
	// admission of that batch happened and it is finalized.
	adm.unavailable, adm.lostResp = false, true
	calls := adm.calls
	report, err = worker.Flush(c.ctx, c.admin(), lease, 1)
	if err != nil || len(report.Finalized) != 1 || len(report.Admitted) != 1 || adm.calls != calls+1 {
		t.Fatalf("lost ACK: %+v %v calls=%d->%d", report, err, calls, adm.calls)
	}
	adm.lostResp = false
	report, err = worker.Flush(c.ctx, c.admin(), lease, 10)
	if err != nil || len(report.Finalized) != 1 {
		t.Fatalf("second output: %+v %v", report, err)
	}
	if len(adm.stored) != 2 || adm.records() != 2 || len(c.outputs(rule, control.RulePhaseFinalized)) != 2 || len(c.outputs(rule, control.RulePhasePending)) != 0 {
		t.Fatalf("stored=%d records=%d", len(adm.stored), adm.records())
	}
}

// Missed grid points are recorded, evaluated late in order at their immutable
// scheduled times as backfill that cannot notify, and only an explicitly
// committed operator replay lets late evaluations notify.
func TestMissedAndBackfilledEvaluation(t *testing.T) {
	c := newCtl(t)
	rule := c.alert(120*time.Second, 0) // 60s grid
	var calls []int64
	exec := presentWhile(c.project, &calls, func(s int64) bool { return s <= 300 })
	clock := newClock(65)
	e := c.evaluator(exec, clock)
	committer := c.committer()
	scheduler := NewScheduler(e, committer, NewStateStore(c.store), WithSchedulerClock(clock))
	lease := c.lease()

	pass := func() RunReport {
		t.Helper()
		report, err := scheduler.RunOnce(c.ctx, c.reader(), c.admin(), rule, lease)
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	// On time: only the scheduled point of this interval.
	if r := pass(); !reflect.DeepEqual(r.Committed, []model.UnixNano{60 * sec}) || r.MissedRecorded {
		t.Fatalf("first pass: %+v", r)
	}
	if r := pass(); len(r.Committed) != 0 {
		t.Fatalf("the same grid point scheduled twice: %+v", r)
	}

	// The scheduler is down for 4 intervals.
	clock.set(305)
	r := pass()
	wantDue := []model.UnixNano{120 * sec, 180 * sec, 240 * sec, 300 * sec}
	if !reflect.DeepEqual(r.Committed, wantDue) || !r.MissedRecorded || r.Plan.Missed == nil || r.Plan.Missed.Count != 3 {
		t.Fatalf("catch-up pass: %+v", r)
	}
	book := c.book(rule)
	if len(book.Missed) != 1 || book.Missed[0].From != 120*sec || book.Missed[0].To != 240*sec || book.Missed[0].Count != 3 || book.Missed[0].Version != 1 {
		t.Fatalf("missed interval not recorded: %+v", book.Missed)
	}
	wantModes := map[model.UnixNano]Mode{60 * sec: ModeLive, 120 * sec: ModeBackfill, 180 * sec: ModeBackfill, 240 * sec: ModeBackfill, 300 * sec: ModeLive}
	for at, mode := range wantModes {
		ev, found, err := NewStateStore(c.store).ReadEvaluation(c.ctx, c.reader(), rule.ID, 1, at)
		if err != nil || !found {
			t.Fatalf("evaluation at %d: %v %v", at/sec, found, err)
		}
		// The scheduled time is the grid point, never the wall clock it ran at.
		if ev.At != at || ev.Mode != mode {
			t.Fatalf("at %d: at=%d mode=%s want %s", at/sec, ev.At/sec, ev.Mode, mode)
		}
		if mode == ModeBackfill && ev.ObservedAt != 305*sec {
			t.Fatalf("backfill observed at %d", ev.ObservedAt/sec)
		}
	}
	// The firing transition happened during backfill (180s: 120s after pending
	// began at 60s). It is history; it must not notify.
	var conditions []control.RuleOutput
	for _, o := range c.outputs(rule, "") {
		if o.Kind == control.RuleOutputCondition {
			conditions = append(conditions, o)
		}
	}
	if len(conditions) != 2 {
		t.Fatalf("%d condition outputs, want pending and firing", len(conditions))
	}
	for _, o := range conditions {
		var intent ConditionIntent
		if err := json.Unmarshal(o.Payload, &intent); err != nil {
			t.Fatal(err)
		}
		switch intent.Event.Status {
		case "pending": // evaluated on time at 60s
			if !o.Notify || o.Mode != control.RuleModeLive {
				t.Fatalf("on-time pending: %+v", o)
			}
		case "firing":
			if o.Notify || intent.Notify || o.Mode != control.RuleModeBackfill || o.At != 180*sec {
				t.Fatalf("a backfilled firing transition notifies: %+v", o)
			}
		default:
			t.Fatalf("unexpected status %s", intent.Event.Status)
		}
	}
	// A late evaluation of an already committed time is the committed one.
	clock.set(9999)
	pinned, err := e.Evaluate(c.ctx, c.reader(), rule, 180*sec, lease)
	if err != nil || pinned.At != 180*sec || pinned.ObservedAt != 305*sec || pinned.Mode != ModeBackfill {
		t.Fatalf("scheduled time not pinned: %+v %v", pinned, err)
	}

	// Operator replay: committed first, then late evaluations inside the window
	// may notify. The series is absent from 360s on.
	if _, err = committer.DeclareReplay(c.ctx, c.admin(), rule, 360*sec, 420*sec, "reconcile after outage", 9999*sec); err != nil {
		t.Fatal(err)
	}
	if w := c.state(rule).Replays; !reflect.DeepEqual(w, []ReplayWindow{{From: 360 * sec, To: 420 * sec}}) {
		t.Fatalf("replay window not readable through the state reader: %+v", w)
	}
	clock.set(485)
	r = pass()
	if !reflect.DeepEqual(r.Committed, []model.UnixNano{360 * sec, 420 * sec, 480 * sec}) {
		t.Fatalf("second catch-up: %+v", r)
	}
	var resolved *control.RuleOutput
	for _, o := range c.outputs(rule, "") {
		var intent ConditionIntent
		if err = json.Unmarshal(o.Payload, &intent); err != nil {
			t.Fatal(err)
		}
		if intent.Event.Status == "resolved" {
			o := o
			resolved = &o
		}
	}
	if resolved == nil || !resolved.Notify || resolved.Mode != control.RuleModeReplay || resolved.At != 360*sec {
		t.Fatalf("a committed replay window did not allow notification: %+v", resolved)
	}
	if len(calls) < 8 {
		t.Fatalf("queries: %v", calls)
	}
	for _, at := range calls {
		if at%60 != 0 {
			t.Fatalf("a query ran off the evaluation grid: %v", calls)
		}
	}
}

// The same evaluations delivered in a different order, with early, late and
// duplicate retries, converge on the same committed state and outputs.
func TestReorderedRetriesConverge(t *testing.T) {
	c := newCtl(t)
	pattern := func(s int64) bool { return s == 60 || s == 120 || s == 240 }
	run := func(rule Rule, retry bool) ([]Evaluation, *mutClock) {
		var calls []int64
		exec := presentWhile(c.project, &calls, pattern)
		clock := newClock(65)
		e := c.evaluator(exec, clock)
		committer := c.committer()
		lease := c.lease()
		var evs []Evaluation
		for _, at := range []int64{60, 120, 180, 240} {
			clock.set(at + 5)
			ev, err := e.Evaluate(c.ctx, c.reader(), rule, model.UnixNano(at)*sec, lease)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = committer.Commit(c.ctx, c.admin(), ev, lease); err != nil {
				t.Fatal(err)
			}
			evs = append(evs, ev)
			if !retry {
				continue
			}
			// Duplicate and late retries of everything committed so far.
			for i := len(evs) - 1; i >= 0; i-- {
				if _, err = committer.Commit(c.ctx, c.admin(), evs[i], lease); err != nil {
					t.Fatalf("retry of %d: %v", i, err)
				}
				again, err := e.Evaluate(c.ctx, c.reader(), rule, evs[i].At, lease)
				if err != nil || canonicalOf(t, again) != canonicalOf(t, evs[i]) {
					t.Fatalf("retry of %d returned another evaluation: %v", i, err)
				}
			}
		}
		return evs, clock
	}
	plain, retried := c.alert(120*time.Second, 60*time.Second), c.alert(120*time.Second, 60*time.Second)
	run(plain, false)
	run(retried, true)
	normalize := func(rule Rule) (State, []string) {
		s := c.state(rule)
		s.Org, s.Project, s.Rule, s.Definition = model.ID{}, model.ID{}, model.ID{}, model.Hash{}
		s.Applied = &EvaluationRef{At: s.Applied.At}
		var statuses []string
		for _, o := range c.outputs(rule, "") {
			var intent ConditionIntent
			if err := json.Unmarshal(o.Payload, &intent); err != nil {
				t.Fatal(err)
			}
			statuses = append(statuses, intent.Event.Status+"@"+time.Duration(o.At).String())
		}
		sort.Strings(statuses)
		return s, statuses
	}
	a, as := normalize(plain)
	b, bs := normalize(retried)
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(as, bs) {
		t.Fatalf("retries changed the outcome:\n%+v %v\n%+v %v", a, as, b, bs)
	}
	if len(as) == 0 || a.Revision != 4 {
		t.Fatalf("fixture produced no history: %v revision=%d", as, a.Revision)
	}
}

// Committed rule state, its outputs and the evaluation identity survive a process
// restart of the control machine, and a restarted leader's lease supersedes the
// previous one.
func TestRuleStateSurvivesRestart(t *testing.T) {
	c := newCtl(t)
	rule := c.alert(0, 0)
	var calls []int64
	exec := presentWhile(c.project, &calls, func(s int64) bool { return s <= 120 })
	clock := newClock(65)
	e := c.evaluator(exec, clock)
	committer := c.committer()
	lease := c.lease()
	var evs []Evaluation
	for _, at := range []int64{60, 120} {
		clock.set(at + 5)
		ev, err := e.Evaluate(c.ctx, c.reader(), rule, model.UnixNano(at)*sec, lease)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = committer.Commit(c.ctx, c.admin(), ev, lease); err != nil {
			t.Fatal(err)
		}
		evs = append(evs, ev)
	}
	before := c.state(rule)
	beforeOutputs := len(c.outputs(rule, ""))

	c.reopen()
	after := c.state(rule)
	if !reflect.DeepEqual(before, after) || len(c.outputs(rule, "")) != beforeOutputs {
		t.Fatalf("state changed across restart:\n%+v\n%+v", before, after)
	}
	exec2 := presentWhile(c.project, &calls, func(s int64) bool { return false })
	clock.set(99999)
	e2 := c.evaluator(exec2, clock)
	committer2 := c.committer()
	newLease := c.lease()
	if newLease.Term <= lease.Term {
		t.Fatalf("restart did not start a new term: %d -> %d", lease.Term, newLease.Term)
	}
	got, err := e2.Evaluate(c.ctx, c.reader(), rule, 120*sec, newLease)
	if err != nil || canonicalOf(t, got) != canonicalOf(t, evs[1]) {
		t.Fatalf("committed evaluation after restart: %v", err)
	}
	if _, err = committer2.Commit(c.ctx, c.admin(), got, newLease); err != nil {
		t.Fatalf("committed evaluation recommitted after restart: %v", err)
	}
	if len(c.outputs(rule, "")) != beforeOutputs {
		t.Fatal("restart replay duplicated effects")
	}
	// The pre-restart lease is deposed for this rule once the new term commits.
	clock.set(185)
	next, err := e2.Evaluate(c.ctx, c.reader(), rule, 180*sec, newLease)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = committer2.Commit(c.ctx, c.admin(), next, newLease); err != nil {
		t.Fatal(err)
	}
	old := NewCommitter(c.store, nil)
	clock.set(245)
	later, err := e2.Evaluate(c.ctx, c.reader(), rule, 240*sec, newLease)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = old.Commit(c.ctx, c.admin(), later, lease); code(err) != model.Stale {
		t.Fatalf("a pre-restart lease committed: %v", err)
	}
}
