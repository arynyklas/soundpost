// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package conditions_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/conditions"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/rules"
	pb "go.etcd.io/raft/v3/raftpb"
)

// ruleFx is a real alert rule over actually admitted metrics: the committed C07
// scheduler evaluates it through the real C06 engine and commits to the real
// control store, and the condition service joins the resulting outputs.
type ruleFx struct {
	*node
	alert     rules.Rule
	clock     *fixedClock
	scheduler *rules.Scheduler
	store     rules.RuleStateReader
	crash     *crashingOutbox
	svc       *conditions.Service
	read      auth.Scope
	admin     auth.Scope
	lease     replica.FenceToken
}

// queue_depth{job="api"} is above the threshold until 210s and below from 270s.
func newRuleFx(t *testing.T) *ruleFx {
	t.Helper()
	n := newNode(t)
	for _, s := range []struct {
		at int64
		v  float64
	}{{30, 10}, {90, 10}, {150, 10}, {210, 10}, {270, 1}, {330, 1}} {
		n.put("queue_depth", labels("job", "api"), model.UnixNano(s.at)*sec, s.v)
	}
	f := &ruleFx{node: n, alert: n.rule(`queue_depth > 5`), clock: &fixedClock{}}
	if err := f.alert.Check(n.registry); err != nil {
		t.Fatal(err)
	}
	f.clock.set(65)
	f.wire()
	return f
}

// wire (re)builds everything that holds node state; a restart calls it again.
func (f *ruleFx) wire() {
	f.read, f.admin = f.scope(auth.Read), f.scope(auth.OrgAdmin)
	evaluator, committer, store := f.wiring(f.clock)
	f.store = store
	f.scheduler = rules.NewScheduler(evaluator, committer, store, rules.WithSchedulerClock(f.clock))
	f.crash = &crashingOutbox{Outbox: rules.NewOutboxStore(f.app.Control)}
	f.svc = f.service(f.clock, f.crash)
	f.lease = f.lease0()
}

func (f *ruleFx) lease0() replica.FenceToken { return f.node.lease() }

// evaluate runs the scheduler at the given wall-clock second under the lease.
func (f *ruleFx) evaluate(at int64, lease replica.FenceToken) {
	f.t.Helper()
	f.clock.set(at)
	if _, err := f.scheduler.RunOnce(f.ctx, f.read, f.admin, f.alert, lease); err != nil {
		f.t.Fatalf("evaluate at %ds: %v", at, err)
	}
}

func (f *ruleFx) outputs(phase string) []control.RuleOutput {
	f.t.Helper()
	out, err := f.app.Control.RuleOutputs(f.ctx, f.admin, f.project, f.alert.ID, phase, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *ruleFx) only() conditions.State {
	f.t.Helper()
	recs := f.conditionRecords()
	if len(recs) != 1 {
		f.t.Fatalf("%d condition records", len(recs))
	}
	return stateOf(f.t, recs[0])
}

func (f *ruleFx) consume(lease replica.FenceToken) conditions.Report {
	f.t.Helper()
	rep, err := f.svc.Consume(f.ctx, f.admin, lease, 50)
	if err != nil {
		f.t.Fatalf("consume: %v", err)
	}
	return rep
}

func statuses(t *testing.T, outs []control.RuleOutput) []string {
	t.Helper()
	var out []string
	for _, o := range outs {
		var intent rules.ConditionIntent
		if err := json.Unmarshal(o.Payload, &intent); err != nil {
			t.Fatal(err)
		}
		out = append(out, intent.Event.Status)
	}
	return out
}

// The committed rule decisions become lifecycle state exactly once, missing
// input becomes explicit unknown history without a recovery, a crash after the
// state commit but before the output is finalized loses nothing and duplicates
// nothing, and the recovery arrives only once the data is complete again.
func TestRuleConditionIntegration(t *testing.T) {
	f := newRuleFx(t)

	// 60s: the alert fires. The output is committed by the rules module and stays
	// in the one internal outbox until the condition side consumes it.
	f.evaluate(65, f.lease)
	if got := f.outputs(control.RulePhasePending); len(got) != 1 || got[0].Kind != control.RuleOutputCondition || len(f.conditionRecords()) != 0 {
		t.Fatalf("outbox before consumption: %+v, %d conditions", got, len(f.conditionRecords()))
	}
	rep := f.consume(f.lease)
	if len(rep.Applied) != 1 || len(rep.NoEffect)+len(rep.Suppressed)+len(rep.Retried) != 0 {
		t.Fatalf("first consume: %+v", rep)
	}
	s := f.only()
	if s.Phase != conditions.PhaseFiring || s.Freshness != conditions.FreshnessFresh || !s.Notify || s.Rule == nil || *s.Rule != f.alert.ID || s.RuleVersion != 1 ||
		s.Severity != "critical" || s.Arrived != 65*sec || s.EventAt != 60*sec || s.Version != 1 || len(s.Labels) != 2 || s.Labels[0].Name != "__name__" || s.Labels[1].Name != "job" || s.Labels[1].Value != "api" {
		t.Fatalf("condition after the first evaluation: %+v", s)
	}
	if got := f.outputs(control.RulePhasePending); len(got) != 0 {
		t.Fatalf("a consumed output is still pending: %+v", got)
	}
	if got := f.outputs(control.RulePhaseFinalized); len(got) != 1 {
		t.Fatalf("a consumed output is not finalized: %+v", got)
	}
	// Consuming again does nothing: one evaluation, one output, one transition.
	revision := f.revision()
	if again := f.consume(f.lease); len(again.Applied)+len(again.NoEffect)+len(again.Suppressed)+len(again.Retried) != 0 || f.revision() != revision {
		t.Fatalf("a second consume did work: %+v", again)
	}

	// 120s and 180s: still firing and healthy, nothing changes and nothing commits.
	f.evaluate(125, f.lease)
	f.evaluate(185, f.lease)
	f.consume(f.lease)
	if got := f.only(); got.Version != 1 {
		t.Fatalf("healthy evaluations of a firing condition moved its version: %+v", got)
	}

	// 240s: a shard is missing. The evaluation is unknown, emits nothing, and the
	// condition becomes explicitly unknown without leaving firing.
	f.scanner.down.Store(true)
	f.evaluate(245, f.lease)
	if got := f.outputs(control.RulePhasePending); len(got) != 0 {
		t.Fatalf("an unknown evaluation emitted an output: %+v", got)
	}
	f.clock.set(250)
	f.consume(f.lease)
	s = f.only()
	if s.Phase != conditions.PhaseFiring || s.Freshness != conditions.FreshnessUnknown || s.Reason != "unavailable" || s.Recovered() || !s.Phase.Active() || s.FreshAt != 240*sec || s.Version != 2 {
		t.Fatalf("condition while a shard is missing: %+v", s)
	}
	if f.audits("conditions.firing") != 1 || f.audits("conditions.recovered") != 0 {
		t.Fatalf("audits: firing=%d recovered=%d", f.audits("conditions.firing"), f.audits("conditions.recovered"))
	}

	// 300s: the data is back and complete, so the absence is genuine. The
	// recovery is committed by the rules module; the process dies after the
	// condition state is durable but before the output is finalized.
	f.scanner.down.Store(false)
	f.evaluate(305, f.lease)
	if got := statuses(t, f.outputs(control.RulePhasePending)); len(got) != 1 || got[0] != "resolved" {
		t.Fatalf("recovery output: %v", got)
	}
	f.crash.armed.Store(true)
	if _, err := f.svc.Consume(f.ctx, f.admin, f.lease, 50); err == nil || !f.crash.crashed.Load() {
		t.Fatalf("the crash between the state commit and the finalize was not observed: %v", err)
	}
	s = f.only()
	if !s.Recovered() || s.Version != 3 || len(f.outputs(control.RulePhasePending)) != 1 {
		t.Fatalf("after the crash: %+v with %d pending outputs", s, len(f.outputs(control.RulePhasePending)))
	}
	// Retrying the same batch: the transition is already durable, so it is a no-op
	// and only the finalize remains.
	revisionBefore := f.revision()
	rep = f.consume(f.lease)
	if len(rep.NoEffect) != 1 || len(rep.Applied) != 0 {
		t.Fatalf("retry after the crash: %+v", rep)
	}
	if got := f.only(); got.Version != 3 || f.audits("conditions.recovered") != 1 || f.audits("conditions.firing") != 1 {
		t.Fatalf("the retry duplicated the transition: %+v", got)
	}
	if len(f.outputs(control.RulePhasePending)) != 0 || len(f.outputs(control.RulePhaseFinalized)) != 2 || f.revision() != revisionBefore+1 {
		t.Fatalf("the retry did not finalize exactly once: %d pending, %d finalized, revision %d -> %d",
			len(f.outputs(control.RulePhasePending)), len(f.outputs(control.RulePhaseFinalized)), revisionBefore, f.revision())
	}
	if got := f.only(); len(got.Recent) != 2 || got.Recent[0].Status != "firing" || got.Recent[1].Status != "recovered" || got.Recent[1].Sequence != 2 {
		t.Fatalf("history: %+v", got.Recent)
	}

	// A recovered condition has nothing left to be unsure about: a later missing
	// shard marks no recovered condition unknown and writes nothing.
	f.scanner.down.Store(true)
	f.evaluate(365, f.lease)
	f.clock.set(370)
	revisionBefore = f.revision()
	f.consume(f.lease)
	if got := f.only(); !got.Recovered() || got.Version != 3 || f.revision() != revisionBefore {
		t.Fatalf("an unknown evaluation touched a recovered condition: %+v", got)
	}
}

// Leadership moves while the rule runs: a deposed leader can neither consume
// outputs nor write a condition a newer leader has written, the shard outage is
// explicit unknown history, and the recovery after it is the only one.
func TestRuleConditionIntegrationLeaderChange(t *testing.T) {
	f := newRuleFx(t)
	oldLease := f.lease
	f.evaluate(65, oldLease)
	f.consume(oldLease)
	if s := f.only(); s.Phase != conditions.PhaseFiring {
		t.Fatalf("before the leader change: %+v", s)
	}
	cid := f.only().Condition

	f.restart()
	f.wire()
	newLease := f.lease
	if newLease.Term <= oldLease.Term {
		t.Fatalf("a restart did not start a new leadership term: %d -> %d", oldLease.Term, newLease.Term)
	}
	// The deposed leader cannot consume.
	if _, err := f.svc.Consume(f.ctx, f.admin, oldLease, 10); code(err) != model.Stale {
		t.Fatalf("the deposed leader consumed outputs: %v", err)
	}

	f.evaluate(125, newLease)
	f.consume(newLease)
	// A leader that is deposed between its own fence check and the commit is
	// stopped by the control state machine: the condition already carries the new
	// term's lease.
	f.evaluate(185, newLease)
	f.scanner.down.Store(true)
	f.evaluate(245, newLease)
	f.consume(newLease)
	if s := f.only(); s.Freshness != conditions.FreshnessUnknown || s.Phase != conditions.PhaseFiring {
		t.Fatalf("while the shard is missing: %+v", s)
	}
	racing, err := conditions.New(f.app.Control, &fakeFencer{group: f.app.Control.ReplicaGroup(), token: &oldLease, skip: true}, rules.NewOutboxStore(f.app.Control), f.clock)
	if err != nil {
		t.Fatal(err)
	}
	before := f.revision()
	e := event(f.only().Epoch, uint64(f.only().Sequence)+1, 250*int64(sec), "recovered")
	e.Condition = cid
	if _, err = racing.Apply(f.ctx, f.admin, e); code(err) != model.Stale || detail(err) != control.ConditionLeaseStale {
		t.Fatalf("the deposed leader recovered the condition: %v", err)
	}
	if f.revision() != before {
		t.Fatal("a deposed leader's apply committed")
	}

	f.scanner.down.Store(false)
	f.evaluate(305, newLease)
	rep := f.consume(newLease)
	if len(rep.Applied) != 1 {
		t.Fatalf("recovery consume: %+v", rep)
	}
	s := f.only()
	if !s.Recovered() || f.audits("conditions.firing") != 1 || f.audits("conditions.recovered") != 1 || len(s.Recent) != 2 {
		t.Fatalf("after the recovery: %+v (firing audits %d)", s, f.audits("conditions.firing"))
	}
	if got := statuses(t, f.outputs(control.RulePhaseFinalized)); len(got) != 2 || got[0] != "firing" || got[1] != "resolved" {
		t.Fatalf("one output per transition: %v", got)
	}
}

// A late evaluation never carries a notification: the lifecycle records the
// transition but not the permission to notify about it.
func TestRuleConditionIntegrationBackfillNeverNotifies(t *testing.T) {
	f := newRuleFx(t)
	f.evaluate(65, f.lease)
	f.consume(f.lease)
	if s := f.only(); !s.Notify || s.Phase != conditions.PhaseFiring {
		t.Fatalf("a live firing: %+v", s)
	}
	// The worker was away: the next pass finds grid points 120..300 late.
	f.evaluate(365, f.lease)
	outs := f.outputs(control.RulePhasePending)
	if len(outs) != 1 || outs[0].Mode != control.RuleModeBackfill || outs[0].Notify {
		t.Fatalf("the late recovery output: %+v", outs)
	}
	f.consume(f.lease)
	s := f.only()
	if !s.Recovered() || s.Notify {
		t.Fatalf("a backfilled recovery may notify: %+v", s)
	}
}

// A privacy deletion or source closing that covers an output's origin suppresses
// the pending output before it can become lifecycle state.
func TestRuleConditionIntegrationClosingSuppressesPendingOutput(t *testing.T) {
	f := newRuleFx(t)
	f.evaluate(65, f.lease)
	pending := f.outputs(control.RulePhasePending)
	if len(pending) != 1 || pending[0].Obsolete {
		t.Fatalf("pending: %+v", pending)
	}
	at := model.UnixNano(f.clock.Now())
	req := control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 0, End: 100 * sec,
		Reason: "privacy deletion", At: at, PhysicalDeadline: at + model.UnixNano(24*time.Hour), BackupDeadline: at + model.UnixNano(30*24*time.Hour)}
	raw, _ := json.Marshal(req)
	if _, err := f.app.Control.Transact(f.ctx, f.orgScope(), control.Command{CommandID: model.NewID(), ExpectedRevision: f.revision(), Kind: string(control.KindDeleteScope), Payload: raw}); err != nil {
		t.Fatalf("deletion: %v", err)
	}
	if got := f.outputs(control.RulePhasePending); len(got) != 1 || !got[0].Obsolete {
		t.Fatalf("the intent was not marked obsolete: %+v", got)
	}
	rep := f.consume(f.lease)
	if len(rep.Suppressed) != 1 || len(rep.Applied) != 0 || len(f.conditionRecords()) != 0 {
		t.Fatalf("a deleted origin became lifecycle state: %+v, %d conditions", rep, len(f.conditionRecords()))
	}
	sup := f.outputs(control.RulePhaseSuppress)
	if len(sup) != 1 || sup[0].Reason != "obsolete_origin" || len(f.outputs(control.RulePhasePending)) != 0 {
		t.Fatalf("suppressed: %+v", sup)
	}
}

// A condition output the lifecycle must not apply is retired visibly, with a
// closed reason, and never blocks the outputs behind it: a recovery claimed by
// an evaluation that was not healthy, a replay of an accepted sequence with a
// different payload, and a payload that is not a condition intent.
func TestRuleConditionIntegrationSuppressesOutputsItCannotApply(t *testing.T) {
	f := newRuleFx(t)
	rule, id, epoch := model.NewID(), model.NewID(), model.NewID()
	type intent struct {
		ID     model.ID             `json:"id"`
		Event  model.ConditionEvent `json:"event"`
		Notify bool                 `json:"notify"`
		Mode   string               `json:"mode"`
	}
	ev := func(seq uint64, at int64, status string) model.ConditionEvent {
		e := event(epoch, seq, at*int64(sec), status)
		e.Condition = id
		return e
	}
	outputs := map[byte]model.ID{}
	commit := func(n int, at int64, health string, key byte, payload func(model.ID) []byte) {
		t.Helper()
		out := model.ID{0xa0, key}
		outputs[key] = out
		evalPayload := json.RawMessage(`{"state":{"reason":"timeout"}}`)
		apply := control.RuleEvaluationApply{Project: f.project, Rule: rule, Version: 1, At: model.UnixNano(at) * sec, ExpectedStateRevision: model.Revision(n), Mode: control.RuleModeLive, Health: health,
			Digest: model.Hash(sha256.Sum256(evalPayload)), Payload: evalPayload, Cursors: []model.Cursor{},
			Outputs: []control.RuleOutputIntent{{ID: out, Kind: control.RuleOutputCondition, Signal: model.Metric, Notify: true, Payload: payload(out), Inputs: []model.Cursor{}}}}
		lease := f.lease
		raw, err := json.Marshal(control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: &apply})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.app.Control.Transact(f.ctx, f.admin, control.Command{CommandID: model.NewID(), ExpectedRevision: f.revision(), Kind: string(control.KindApplyRuleEvaluation), Payload: raw}); err != nil {
			t.Fatalf("commit evaluation %d: %v", n, err)
		}
	}
	intentOf := func(e model.ConditionEvent) func(model.ID) []byte {
		return func(out model.ID) []byte {
			raw, err := json.Marshal(intent{ID: out, Event: e, Notify: true, Mode: "live"})
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
	}
	commit(0, 60, "ok", 1, intentOf(ev(1, 60, "firing")))
	commit(1, 120, "unknown", 2, intentOf(ev(2, 120, "resolved"))) // a recovery from an unknown evaluation
	commit(2, 180, "ok", 3, intentOf(ev(1, 60, "recovered")))      // seq 1 again, different payload
	commit(3, 240, "ok", 4, func(out model.ID) []byte { return []byte(`{"id":"` + out.String() + `","surprise":1}`) })
	commit(4, 300, "ok", 5, intentOf(ev(2, 300, "resolved"))) // behind all of them, and fine
	// An intent that names another output's identity is not this output's.
	commit(5, 330, "ok", 6, func(model.ID) []byte {
		raw, err := json.Marshal(intent{ID: model.ID{0xff}, Event: ev(3, 330, "firing"), Notify: true, Mode: "live"})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	})

	rep := f.consume(f.lease)
	if len(rep.Applied) != 2 || rep.Applied[0] != outputs[1] || rep.Applied[1] != outputs[5] || len(rep.Suppressed) != 4 || len(rep.Retried) != 0 {
		t.Fatalf("report: %+v", rep)
	}
	reasons := map[model.ID]string{}
	suppressed, err := f.app.Control.RuleOutputs(f.ctx, f.admin, f.project, model.ID{}, control.RulePhaseSuppress, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range suppressed {
		reasons[o.ID] = o.Reason
	}
	if reasons[outputs[2]] != "recovery_blocked" || reasons[outputs[3]] != "conflicting_event" || reasons[outputs[4]] != "malformed_intent" || reasons[outputs[6]] != "malformed_intent" {
		t.Fatalf("suppression reasons: %v", reasons)
	}
	if left, _ := f.app.Control.RuleOutputs(f.ctx, f.admin, f.project, model.ID{}, control.RulePhasePending, 0); len(left) != 0 {
		t.Fatal("an output that cannot be applied stayed pending and would block the outbox")
	}
	// The recovery from the unhealthy evaluation did not recover the condition;
	// the later healthy one did, once.
	s := f.only()
	if !s.Recovered() || s.Sequence != 2 || s.EventAt != 300*sec || s.Version != 2 || f.audits("conditions.recovered") != 1 {
		t.Fatalf("condition: %+v", s)
	}
}

// ---- three voters ----------------------------------------------------------
//
// voters is a real three-voter control group in one process (the shape of
// internal/notify's TestOutboxThreeNode* fixture, which lives in another test
// package and cannot be imported): three control stores in private directories,
// each with its own Raft group over an in-process transport delivering through
// Group.Step/ReportDelivery, opened from the genesis node's replication seed
// exactly as a distributed appcore node is. The metric data and the C06 engine
// are the genesis node's (the data groups are not part of this fixture); the
// rule scheduler, committer, outbox and condition service of every voter run over
// that voter's own control store. There are no separate processes and no mTLS: a
// "process death" closes one voter's store and group and cuts it from the mesh.

type meshMsg struct {
	from uint64
	m    *pb.Message
}

type mesh struct {
	mu      sync.Mutex
	groups  map[uint64]*replica.Group
	queues  map[uint64]chan meshMsg
	blocked map[uint64]bool
	stop    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
}

func newMesh() *mesh {
	return &mesh{groups: map[uint64]*replica.Group{}, queues: map[uint64]chan meshMsg{}, blocked: map[uint64]bool{}, stop: make(chan struct{})}
}

func (m *mesh) set(id uint64, g *replica.Group) { m.mu.Lock(); m.groups[id] = g; m.mu.Unlock() }
func (m *mesh) partition(id uint64, down bool)  { m.mu.Lock(); m.blocked[id] = down; m.mu.Unlock() }
func (m *mesh) down(id uint64) bool             { m.mu.Lock(); defer m.mu.Unlock(); return m.blocked[id] }
func (m *mesh) close()                          { m.once.Do(func() { close(m.stop) }); m.wg.Wait() }

type meshTransport struct {
	mesh *mesh
	node uint64
}

func (t meshTransport) Send(_ model.ID, message *pb.Message) error {
	if message == nil || message.GetFrom() != t.node {
		return replica.ErrInvalid
	}
	to := message.GetTo()
	t.mesh.mu.Lock()
	q := t.mesh.queues[to]
	if q == nil {
		q = make(chan meshMsg, 512)
		t.mesh.queues[to] = q
		t.mesh.wg.Add(1)
		go t.mesh.deliver(to, q)
	}
	t.mesh.mu.Unlock()
	select {
	case <-t.mesh.stop:
		return replica.ErrUnavailable
	case q <- meshMsg{from: t.node, m: message}:
		return nil
	default:
		return replica.ErrUnavailable
	}
}

func (m *mesh) deliver(to uint64, q <-chan meshMsg) {
	defer m.wg.Done()
	for {
		select {
		case <-m.stop:
			return
		case in := <-q:
			m.mu.Lock()
			dst, src := m.groups[to], m.groups[in.from]
			down := m.blocked[in.from] || m.blocked[to]
			m.mu.Unlock()
			var err error
			switch {
			case dst == nil || down:
				err = replica.ErrUnavailable
			default:
				if stepped := dst.Step(context.Background(), in.m); errors.Is(stepped, replica.ErrUnavailable) {
					err = stepped
				}
			}
			if src != nil {
				src.ReportDelivery(to, in.m.GetType() == pb.MsgSnap, err)
			}
		}
	}
}

type voters struct {
	t      *testing.T
	g      *node
	clock  *fixedClock
	mesh   *mesh
	stores map[uint64]*control.Store
	svcs   map[uint64]*auth.Service
	creds  map[uint64]auth.Credential
	alive  map[uint64]bool
}

func newVoters(t *testing.T, g *node, clock *fixedClock) *voters {
	t.Helper()
	seed, application, err := g.app.Control.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	position := g.app.Control.ReplicaGroup().Status()
	dirs := map[uint64]string{1: t.TempDir(), 2: t.TempDir(), 3: t.TempDir()}
	v := &voters{t: t, g: g, clock: clock, mesh: newMesh(), stores: map[uint64]*control.Store{}, svcs: map[uint64]*auth.Service{}, creds: map[uint64]auth.Credential{}, alive: map[uint64]bool{}}
	t.Cleanup(func() {
		for id, s := range v.stores {
			if v.alive[id] {
				s.Close()
			}
		}
		v.mesh.close()
	})
	members := replica.Members{Revision: 1}
	for id := uint64(1); id <= 3; id++ {
		members.Nodes = append(members.Nodes, replica.Member{ID: id, Address: fmt.Sprintf("https://voter%d.invalid", id), NodeIdentity: fmt.Sprintf("voter-%d", id), FailureDomain: fmt.Sprintf("disk-%d", id)})
	}
	for id := uint64(1); id <= 3; id++ {
		store, err := control.OpenSeed(dirs[id], seed)
		if err != nil {
			t.Fatal(err)
		}
		v.stores[id], v.alive[id] = store, true
		svc, err := auth.NewService(auth.AuthDependencies{Control: store, Now: time.Now})
		if err != nil {
			t.Fatal(err)
		}
		v.svcs[id] = svc
		for _, bind := range []func() error{store.BindRuleEvaluation, store.BindConditionApply} {
			if err = bind(); err != nil {
				t.Fatal(err)
			}
		}
		var installation model.ID
		if err = store.View(g.ctx, func(st control.State) error { installation = st.Installation; return nil }); err != nil {
			t.Fatal(err)
		}
		group, err := store.EnableReplication(replica.Config{ID: id, Group: installation, Directory: filepath.Join(dirs[id], "raft", "control"), TickInterval: 20 * time.Millisecond, Members: members,
			Transport: meshTransport{mesh: v.mesh, node: id}, Seed: seed, Application: application, SeedIndex: position.Applied + 1, SeedTerm: position.Term + 1})
		if err != nil {
			t.Fatal(err)
		}
		v.mesh.set(id, group)
	}
	v.leaderOf(1)
	for id := uint64(1); id <= 3; id++ {
		cred, err := v.svcs[id].Authenticate(g.ctx, g.token)
		if err != nil {
			t.Fatalf("voter %d does not know the genesis session: %v", id, err)
		}
		v.creds[id] = cred
	}
	return v
}

// leaderOf waits until voter id is the control leader and a quorum round
// succeeds on it, campaigning from it as needed (first election only).
func (v *voters) leaderOf(id uint64) {
	v.t.Helper()
	if err := v.stores[id].ReplicaGroup().Campaign(); err != nil {
		v.t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for round := 0; time.Now().Before(deadline); round++ {
		g := v.stores[id].ReplicaGroup()
		if g.Status().Leader == id {
			ctx, cancel := context.WithTimeout(v.g.ctx, 3*time.Second)
			_, err := g.Fence(ctx)
			cancel()
			if err == nil {
				return
			}
		} else if round%10 == 0 {
			_ = g.Campaign()
		}
		time.Sleep(20 * time.Millisecond)
	}
	v.t.Fatalf("voter %d never became the control leader", id)
}

// surviving waits for a leader among the running, connected voters and returns it
// once a quorum round succeeds on it.
func (v *voters) surviving() uint64 {
	v.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for round := 0; time.Now().Before(deadline); round++ {
		var candidates []uint64
		for id := uint64(1); id <= 3; id++ {
			if v.alive[id] && !v.mesh.down(id) {
				candidates = append(candidates, id)
			}
		}
		for _, id := range candidates {
			g := v.stores[id].ReplicaGroup()
			if g.Status().Leader != id {
				continue
			}
			ctx, cancel := context.WithTimeout(v.g.ctx, 3*time.Second)
			_, err := g.Fence(ctx)
			cancel()
			if err == nil {
				return id
			}
		}
		if round%10 == 0 && len(candidates) > 0 {
			_ = v.stores[candidates[0]].ReplicaGroup().Campaign()
		}
		time.Sleep(20 * time.Millisecond)
	}
	v.t.Fatal("the surviving voters never elected a leader")
	return 0
}

// kill is a process death of one voter.
func (v *voters) kill(id uint64) {
	v.t.Helper()
	v.mesh.partition(id, true)
	if err := v.stores[id].Close(); err != nil {
		v.t.Fatal(err)
	}
	v.mesh.set(id, nil)
	v.alive[id] = false
}

func (v *voters) lease(id uint64) replica.FenceToken {
	v.t.Helper()
	l, err := v.stores[id].ReplicaGroup().Fence(v.g.ctx)
	if err != nil {
		v.t.Fatalf("voter %d lease: %v", id, err)
	}
	return l
}

func (v *voters) admin(id uint64) auth.Scope {
	v.t.Helper()
	s, err := v.svcs[id].Authorize(v.g.ctx, v.creds[id], v.g.org, []model.ID{v.g.project}, auth.OrgAdmin)
	if err != nil {
		v.t.Fatalf("voter %d admin scope: %v", id, err)
	}
	return s
}

// scheduler is the rule scheduler of one voter: the shared C06 engine over the
// genesis node's data, with the voter's own control store, state, group and committer.
func (v *voters) scheduler(id uint64) *rules.Scheduler {
	store := rules.NewStateStore(v.stores[id])
	group := v.stores[id].ReplicaGroup()
	evaluator := rules.NewEvaluator(v.g.engine, store, rules.WithClock(v.clock), rules.WithFencer(group), rules.WithEvidence(rules.GapEvidence{Gaps: v.stores[id]}))
	return rules.NewScheduler(evaluator, rules.NewCommitter(v.stores[id], group), store, rules.WithSchedulerClock(v.clock))
}

func (v *voters) service(id uint64, outbox conditions.Outbox) *conditions.Service {
	v.t.Helper()
	if outbox == nil {
		outbox = rules.NewOutboxStore(v.stores[id])
	}
	svc, err := conditions.New(v.stores[id], v.stores[id].ReplicaGroup(), outbox, v.clock)
	if err != nil {
		v.t.Fatal(err)
	}
	return svc
}

func (v *voters) records(id uint64) []control.ConditionRecord {
	v.t.Helper()
	recs, err := v.stores[id].Conditions(v.g.ctx, v.admin(id), v.g.project)
	if err != nil {
		v.t.Fatal(err)
	}
	return recs
}

func (v *voters) outputs(id uint64, rule model.ID, phase string) []control.RuleOutput {
	v.t.Helper()
	out, err := v.stores[id].RuleOutputs(v.g.ctx, v.admin(id), v.g.project, rule, phase, 0)
	if err != nil {
		v.t.Fatal(err)
	}
	return out
}

// Leadership of the control group is transferred while a rule fires, loses its
// data, and recovers (06.04 criterion 11). One evaluation is one output and one
// transition no matter which leader decides it: a leader that died between the
// condition commit and the output finalize leaves exactly one effect for the
// successor to finish, the deposed term's lease can neither evaluate nor
// consume, a shard outage on the new leader is unknown history without a
// recovery, and every surviving voter converges on the same record.
func TestRuleConditionThreeVoterLeadershipTransfer(t *testing.T) {
	g := newNode(t)
	for _, s := range []struct {
		at int64
		v  float64
	}{{30, 10}, {90, 10}, {150, 10}, {210, 10}, {270, 1}, {330, 1}} {
		g.put("queue_depth", labels("job", "api"), model.UnixNano(s.at)*sec, s.v)
	}
	alert := g.rule(`queue_depth > 5`)
	if err := alert.Check(g.registry); err != nil {
		t.Fatal(err)
	}
	clock := &fixedClock{}
	clock.set(65)
	v := newVoters(t, g, clock)
	read := g.scope(auth.Read)

	// Voter 1 leads: the alert fires and the process dies after the condition state is
	// durable but before the output is finalized.
	lease1 := v.lease(1)
	if _, err := v.scheduler(1).RunOnce(g.ctx, read, v.admin(1), alert, lease1); err != nil {
		t.Fatalf("evaluation on the first leader: %v", err)
	}
	crash := &crashingOutbox{Outbox: rules.NewOutboxStore(v.stores[1])}
	crash.armed.Store(true)
	if _, err := v.service(1, crash).Consume(g.ctx, v.admin(1), lease1, 50); err == nil || !crash.crashed.Load() {
		t.Fatalf("the first leader's crash between state commit and finalize was not observed: %v", err)
	}
	if recs := v.records(1); len(recs) != 1 || stateOf(t, recs[0]).Phase != conditions.PhaseFiring || len(v.outputs(1, alert.ID, control.RulePhasePending)) != 1 {
		t.Fatalf("after the crash: %d records, %d pending outputs", len(v.records(1)), len(v.outputs(1, alert.ID, control.RulePhasePending)))
	}
	cid := stateOf(t, v.records(1)[0]).Condition
	pendingBefore := v.outputs(1, alert.ID, control.RulePhasePending)[0].ID

	// Leadership transfers: voter 1 dies, a survivor wins a later term.
	v.kill(1)
	next := v.surviving()
	if next == 1 {
		t.Fatal("the dead voter leads")
	}
	lease2 := v.lease(next)
	if lease2.Term <= lease1.Term {
		t.Fatalf("no new leadership term: %d -> %d", lease1.Term, lease2.Term)
	}
	// The deposed term's lease evaluates nothing and consumes nothing on the new leader.
	clock.set(125)
	if _, err := v.scheduler(next).RunOnce(g.ctx, read, v.admin(next), alert, lease1); err == nil {
		t.Fatal("the deposed term's lease evaluated a rule")
	}
	if _, err := v.service(next, nil).Consume(g.ctx, v.admin(next), lease1, 10); code(err) != model.Stale {
		t.Fatalf("the deposed term's lease consumed outputs: %v", err)
	}
	// The successor finishes the dead leader's work: the transition is already durable, so it
	// is a no-op and only the finalize remains. Same output identity, same single record.
	rep, err := v.service(next, nil).Consume(g.ctx, v.admin(next), lease2, 50)
	if err != nil || len(rep.NoEffect) != 1 || len(rep.Applied) != 0 || rep.NoEffect[0] != pendingBefore {
		t.Fatalf("the successor's consume: %v %+v (want the one pending output %s as a no-effect)", err, rep, pendingBefore)
	}
	if recs := v.records(next); len(recs) != 1 || stateOf(t, recs[0]).Version != 1 || len(v.outputs(next, alert.ID, control.RulePhasePending)) != 0 {
		t.Fatalf("after the successor's consume: %d records", len(v.records(next)))
	}

	// The new leader keeps evaluating. Healthy firing evaluations change nothing; a missing
	// shard is unknown history without a recovery; the recovery comes once and only after the data returns.
	sched := v.scheduler(next)
	for _, at := range []int64{125, 185} {
		clock.set(at)
		if _, err := sched.RunOnce(g.ctx, read, v.admin(next), alert, lease2); err != nil {
			t.Fatalf("evaluate at %ds: %v", at, err)
		}
	}
	g.scanner.down.Store(true)
	clock.set(245)
	if _, err := sched.RunOnce(g.ctx, read, v.admin(next), alert, lease2); err != nil {
		t.Fatalf("evaluate while the shard is missing: %v", err)
	}
	if got := v.outputs(next, alert.ID, control.RulePhasePending); len(got) != 0 {
		t.Fatalf("an unknown evaluation emitted an output: %+v", got)
	}
	clock.set(250)
	if _, err := v.service(next, nil).Consume(g.ctx, v.admin(next), lease2, 50); err != nil {
		t.Fatal(err)
	}
	if s := stateOf(t, v.records(next)[0]); s.Phase != conditions.PhaseFiring || s.Freshness != conditions.FreshnessUnknown || s.Recovered() {
		t.Fatalf("while the shard is missing: %+v", s)
	}
	g.scanner.down.Store(false)
	clock.set(305)
	if _, err := sched.RunOnce(g.ctx, read, v.admin(next), alert, lease2); err != nil {
		t.Fatal(err)
	}
	if rep, err := v.service(next, nil).Consume(g.ctx, v.admin(next), lease2, 50); err != nil || len(rep.Applied) != 1 {
		t.Fatalf("recovery consume: %v %+v", err, rep)
	}

	// One condition, one firing and one recovery, one finalized output per transition, and the
	// other surviving voter holds the same replicated state.
	for id := uint64(1); id <= 3; id++ {
		if !v.alive[id] {
			continue
		}
		recs := v.records(id)
		if len(recs) != 1 || recs[0].ID != cid {
			t.Fatalf("voter %d: %d condition records", id, len(recs))
		}
		s := stateOf(t, recs[0])
		if !s.Recovered() || len(s.Recent) != 2 || s.Recent[0].Status != "firing" || s.Recent[1].Status != "recovered" {
			t.Fatalf("voter %d condition: %+v", id, s)
		}
		if got := statuses(t, v.outputs(id, alert.ID, control.RulePhaseFinalized)); len(got) != 2 || got[0] != "firing" || got[1] != "resolved" {
			t.Fatalf("voter %d finalized outputs: %v", id, got)
		}
		if len(v.outputs(id, alert.ID, control.RulePhasePending)) != 0 {
			t.Fatalf("voter %d has pending outputs", id)
		}
	}
}
