// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"soundpost/internal/query"
	"soundpost/internal/query/profile"
	"soundpost/internal/replica"
	"soundpost/internal/rules"
	"soundpost/internal/storage"
	"soundpost/profiles"
)

// This is the in-process stand-in for the brief's real-storage/real-control
// smoke (`soundpost-querycheck smoke` does not exist): a real appcore node (real
// control Raft group, auth, C03 admission, C05 storage), the real C06 engine
// behind a scanner wrapper that can make the data unavailable, real metric data
// admitted through the production ingest path, and the rules scheduler,
// committer and output worker over them. Only the process boundary is not
// crossed: "restart" closes and reopens the node on the same directory.

const sec = model.UnixNano(time.Second)

type node struct {
	t        *testing.T
	ctx      context.Context
	dir      string
	app      *appcore.App
	token    string
	actor    auth.Credential
	org      model.ID
	project  model.ID
	source   model.ID
	issued   string
	srcCred  auth.SourceCredential
	resource model.Resource
	scanner  *flaky
	engine   *query.Engine
	registry profile.Registry
	features map[string]string
}

// flaky is the scan seam with a switch that makes the data unavailable, as a
// missing shard would: the engine must then fail, not answer from what it has.
type flaky struct {
	inner query.Scanner
	down  atomic.Bool
}

func (f *flaky) Scan(ctx context.Context, scope auth.Scope, req storage.ScanRequest) (storage.RowIterator, error) {
	if f.down.Load() {
		return nil, model.Fail(model.Unavailable)
	}
	return f.inner.Scan(ctx, scope, req)
}

func newNode(t *testing.T) *node {
	t.Helper()
	n := &node{t: t, ctx: context.Background(), dir: t.TempDir(), org: model.NewID(), project: model.NewID(), source: model.NewID(), features: map[string]string{}}
	t.Cleanup(func() {
		if n.app != nil {
			n.app.Close()
		}
	})
	files, err := profiles.Query()
	if err != nil {
		t.Fatal(err)
	}
	if n.registry, err = profile.Load(files); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"promql-prometheus-3.13.5"} {
		raw, err := fs.ReadFile(files, id+".json")
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
		n.features[id] = p.FeatureSets[0].ID
	}
	n.open()
	boot, err := n.app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := n.app.Auth.Bootstrap(n.ctx, boot, "rules-owner@example.test", "rules integration password 2026")
	if err != nil {
		t.Fatal(err)
	}
	n.token = session.Token
	n.authenticate()
	n.command("create_org", auth.AdminPayload{Name: "rules"})
	n.command("create_project", auth.AdminPayload{ID: n.project, Name: "rules"})
	n.command("membership", auth.AdminPayload{UserID: session.User, Enabled: true})
	n.command("grant", auth.AdminPayload{UserID: session.User, ProjectID: n.project, Enabled: true, Permissions: []string{string(auth.Read)}})
	n.resource = model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "rules-1", Labels: model.Labels{}}
	sourcePolicy := model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric},
		Resources:     model.ResourceRegistry{Services: []model.ID{n.resource.Service}, Environments: []model.ID{n.resource.Environment}, Builds: []model.ID{n.resource.Build}, Instances: []string{n.resource.Instance}},
		Labels:        map[string][]string{"job": {"api", "worker"}, "env": {"prod"}},
		RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 64 << 20, MaxSeries: 1000,
	}
	issued, err := n.app.Auth.OnboardSource(n.ctx, n.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: n.org, Project: n.project, Source: n.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: sourcePolicy, Reason: "rules integration"})
	if err != nil {
		t.Fatal(err)
	}
	n.issued = issued.Credential
	n.authenticateSource()
	return n
}

// open opens the node and binds the rule dispatcher. A node whose application
// wiring already binds it is accepted as it is.
func (n *node) open() {
	n.t.Helper()
	var err error
	if n.app, err = appcore.Open(n.dir); err != nil {
		n.t.Fatal(err)
	}
	if err = n.app.Control.BindRuleEvaluation(); err != nil {
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != model.Conflict {
			n.t.Fatal(err)
		}
	}
	n.scanner = &flaky{inner: n.app.Storage}
	if n.engine, err = query.New(n.scanner, n.app.Auth, n.registry, query.DefaultLimits(), query.WithDeleteGenerations(n.app.Retention)); err != nil {
		n.t.Fatal(err)
	}
}

// restart is a process restart of the whole node on the same directory.
func (n *node) restart() {
	n.t.Helper()
	if err := n.app.Close(); err != nil {
		n.t.Fatal(err)
	}
	n.app = nil
	n.open()
	n.authenticate()
	n.authenticateSource()
}

func (n *node) authenticate() {
	n.t.Helper()
	var err error
	if n.actor, err = n.app.Auth.Authenticate(n.ctx, n.token); err != nil {
		n.t.Fatal(err)
	}
}
func (n *node) authenticateSource() {
	n.t.Helper()
	var err error
	if n.srcCred, err = n.app.Auth.AuthenticateSource(n.ctx, n.issued, "", false); err != nil {
		n.t.Fatal(err)
	}
}

func (n *node) command(kind string, p auth.AdminPayload) {
	n.t.Helper()
	var revision model.Revision
	if err := n.app.Control.View(n.ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		n.t.Fatal(err)
	}
	p.Reason = "rules integration"
	raw, _ := json.Marshal(p)
	if _, err := n.app.Auth.AdminCommand(n.ctx, n.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: n.org, Kind: kind, Payload: raw}); err != nil {
		n.t.Fatal(kind, err)
	}
}

func (n *node) scope(permission auth.Permission) auth.Scope {
	n.t.Helper()
	s, err := n.app.Auth.Authorize(n.ctx, n.actor, n.org, []model.ID{n.project}, permission)
	if err != nil {
		n.t.Fatal(err)
	}
	return s
}

func lbl(pairs ...string) model.Labels {
	out := model.Labels{}
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, model.Label{Name: pairs[i], Value: pairs[i+1]})
	}
	return out
}

// put admits one metric sample through the production ingest path.
func (n *node) put(name string, labels model.Labels, at model.UnixNano, value float64) {
	n.t.Helper()
	bits := model.FloatBits(math.Float64bits(value))
	producer := model.ID{0xd1}
	record := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: at, Resource: n.resource,
		Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: labels, SampleKind: "float", Value: &bits, Unit: "1", Type: "gauge"}}}
	slot, err := model.OwnerSlot(n.org, n.project, n.source, producer, record)
	if err != nil {
		n.t.Fatal(err)
	}
	batch := model.Batch{Version: 1, Project: n.project, Source: n.source, Producer: producer, ID: model.NewID(), PolicyRevision: 1, RouteSlot: slot, Records: []model.Record{record}}
	grant, err := n.app.Ingest.ResolveSource(n.ctx, n.srcCred, batch)
	if err != nil {
		n.t.Fatal(err)
	}
	if _, err = n.app.Ingest.Admit(n.ctx, grant, batch); err != nil {
		n.t.Fatal(err)
	}
}

// stored returns every stored sample of the metric name, by observation time.
func (n *node) stored(name string) []model.UnixNano {
	n.t.Helper()
	rows, err := n.app.Storage.Scan(n.ctx, n.scope(auth.Read), storage.ScanRequest{Projects: []model.ID{n.project}, Signal: model.Metric, Start: math.MinInt64, End: math.MaxInt64})
	if err != nil {
		n.t.Fatal(err)
	}
	defer rows.Close()
	var out []model.UnixNano
	for {
		page, err := rows.Next(n.ctx)
		if err == io.EOF {
			return out
		}
		if err != nil {
			n.t.Fatal(err)
		}
		for i := range page.Len() {
			if m := page.Values[i].Metric; m != nil && m.Name == name {
				out = append(out, page.ObservedTimes[i])
			}
		}
	}
}

// ingestAdmitter is the production adapter between the output worker and C03:
// the recording source's credential, normalization against its current policy,
// and the authenticated historical receipt lookup.
type ingestAdmitter struct{ n *node }

func (a ingestAdmitter) Admit(ctx context.Context, b model.Batch) (model.Receipt, error) {
	grant, err := a.n.app.Ingest.ResolveSource(ctx, a.n.srcCred, b)
	if err != nil {
		return model.Receipt{}, err
	}
	return a.n.app.Ingest.Admit(ctx, grant, b)
}

func (a ingestAdmitter) LookupReceipt(ctx context.Context, b model.Batch) (model.Receipt, bool, error) {
	grant, err := a.n.app.Ingest.ResolveSource(ctx, a.n.srcCred, b)
	if err != nil {
		return model.Receipt{}, false, err
	}
	normalized, err := policy.Normalize(grant, b)
	if err != nil {
		return model.Receipt{}, false, err
	}
	receipt, err := a.n.app.Ingest.LookupReceipt(ctx, a.n.srcCred, model.ReceiptRequest{Source: b.Source, Producer: b.Producer, RouteSlot: b.RouteSlot, BatchID: b.ID, OriginalHash: normalized.Hash})
	var fault *model.Fault
	if errors.As(err, &fault) && fault.Code == model.NotFound {
		return model.Receipt{}, false, nil
	}
	return receipt, err == nil, err
}

type fixedClock struct{ v atomic.Int64 }

func (c *fixedClock) Now() model.UnixNano { return model.UnixNano(c.v.Load()) }
func (c *fixedClock) set(s int64)         { c.v.Store(s * int64(time.Second)) }

// crashingOutbox kills the "process" after the receipt is durable but before the
// outbox learns of it.
type crashingOutbox struct {
	rules.Outbox
	crashOn string
	crashed bool
}

func (o *crashingOutbox) Settle(ctx context.Context, scope auth.Scope, lease replica.FenceToken, item control.RuleOutput, update control.RuleOutputApply) (control.Result, error) {
	if !o.crashed && update.To == o.crashOn {
		o.crashed = true
		return control.Result{}, errors.New("process crashed")
	}
	return o.Outbox.Settle(ctx, scope, lease, item, update)
}

func (n *node) rule(kind rules.Kind, expression string) rules.Rule {
	r := rules.Rule{ID: model.NewID(), Project: n.project, Version: 1, Kind: kind, Profile: "promql-prometheus-3.13.5", FeatureSet: n.features["promql-prometheus-3.13.5"], Expression: expression, Interval: time.Minute}
	if kind == rules.KindAlert {
		r.Severity = "page"
	} else {
		r.RecordName, r.Labels = "job:queue_depth:sum", lbl("env", "prod")
	}
	return r
}

func (n *node) wiring(clock rules.Clock, options ...rules.Option) (*rules.Evaluator, *rules.Committer, rules.RuleStateReader) {
	store := rules.NewStateStore(n.app.Control)
	group := n.app.Control.ReplicaGroup()
	all := append([]rules.Option{rules.WithClock(clock), rules.WithFencer(group), rules.WithEvidence(rules.GapEvidence{Gaps: n.app.Control})}, options...)
	return rules.NewEvaluator(n.engine, store, all...), rules.NewCommitter(n.app.Control, group), store
}

func (n *node) lease() replica.FenceToken {
	n.t.Helper()
	token, err := n.app.Control.ReplicaGroup().Fence(n.ctx)
	if err != nil {
		n.t.Fatal(err)
	}
	return token
}

// Alert and recording rules over actually admitted metrics, through the real C06
// engine, real storage and the real control machine: a leadership fence change,
// a recording outbox crash with restart, an unavailable shard and full recovery.
func TestRulesOverRealStorageAndControl(t *testing.T) {
	n := newNode(t)
	// queue_depth{job="api"} is above the threshold until 210s, below from 270s.
	for _, s := range []struct {
		at int64
		v  float64
	}{{30, 10}, {90, 10}, {150, 10}, {210, 10}, {270, 1}, {330, 1}} {
		n.put("queue_depth", lbl("job", "api"), model.UnixNano(s.at)*sec, s.v)
	}
	alert := n.rule(rules.KindAlert, `queue_depth > 5`)
	recording := n.rule(rules.KindRecording, `sum by (job) (queue_depth)`)
	if err := alert.Check(n.registry); err != nil {
		t.Fatal(err)
	}
	if err := recording.Check(n.registry); err != nil {
		t.Fatal(err)
	}
	producer := rules.ProducerIdentity{Source: n.source, Producer: model.ID{0xee}, PolicyRevision: 1, Resource: n.resource}
	clock := &fixedClock{}
	clock.set(65)
	read, admin := n.scope(auth.Read), n.scope(auth.OrgAdmin)

	evaluator, committer, store := n.wiring(clock, rules.WithProducer(producer))
	scheduler := rules.NewScheduler(evaluator, committer, store, rules.WithSchedulerClock(clock))
	lease := n.lease()
	oldLease := lease

	runBoth := func(l replica.FenceToken) {
		t.Helper()
		for _, r := range []rules.Rule{alert, recording} {
			if _, err := scheduler.RunOnce(n.ctx, read, admin, r, l); err != nil {
				t.Fatalf("%s rule: %v", r.Kind, err)
			}
		}
	}
	// 60s: the alert fires (queue_depth is 10); the recording rule derives a sample.
	runBoth(lease)
	state, err := store.Read(n.ctx, read, alert.ID)
	if err != nil || len(state.Series) != 1 || state.Health != rules.HealthOK || state.Revision != 1 || len(state.Cursors) == 0 {
		t.Fatalf("alert state after 60s: %+v %v", state, err)
	}
	for _, series := range state.Series {
		if series.Phase != rules.PhaseFiring {
			t.Fatalf("series is %s", series.Phase)
		}
	}
	recorded, err := store.Read(n.ctx, read, recording.ID)
	if err != nil || recorded.Revision != 1 {
		t.Fatalf("recording state: %+v %v", recorded, err)
	}

	// The recording output: admit durably, then the process dies before the outbox
	// is told. A restart of the whole node follows.
	outbox := rules.NewOutboxStore(n.app.Control)
	crashing := &crashingOutbox{Outbox: outbox, crashOn: control.RulePhaseAdmitted}
	worker, err := rules.NewOutputWorker(ingestAdmitter{n}, crashing, ingestAdmitter{n}, n.app.Control.ReplicaGroup())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = worker.Flush(n.ctx, admin, lease, 10); err == nil || !crashing.crashed {
		t.Fatalf("crash not observed: %v", err)
	}
	if got := n.stored("job:queue_depth:sum"); len(got) != 1 || got[0] != 60*sec {
		t.Fatalf("durable recording after the ACK: %v", got)
	}
	pending, err := n.app.Control.RuleOutputs(n.ctx, admin, n.project, recording.ID, control.RulePhasePending, 0)
	if err != nil || len(pending) != 1 {
		t.Fatalf("outbox after the crash: %d pending, %v", len(pending), err)
	}

	n.restart()
	read, admin = n.scope(auth.Read), n.scope(auth.OrgAdmin)
	evaluator, committer, store = n.wiring(clock, rules.WithProducer(producer))
	scheduler = rules.NewScheduler(evaluator, committer, store, rules.WithSchedulerClock(clock))
	lease = n.lease()
	if lease.Term <= oldLease.Term {
		t.Fatalf("a restart did not start a new leadership term: %d -> %d", oldLease.Term, lease.Term)
	}
	// The committed state survived: the same evaluation is returned verbatim, and
	// re-committing it under the new lease changes nothing.
	again, found, err := store.ReadEvaluation(n.ctx, read, alert.ID, 1, 60*sec)
	if err != nil || !found || len(again.State.Series) != 1 || again.ObservedAt != 65*sec {
		t.Fatalf("committed evaluation after restart: %+v found=%v err=%v", again, found, err)
	}
	report, err := func() (rules.OutputReport, error) {
		w, err := rules.NewOutputWorker(ingestAdmitter{n}, rules.NewOutboxStore(n.app.Control), ingestAdmitter{n}, n.app.Control.ReplicaGroup())
		if err != nil {
			t.Fatal(err)
		}
		return w.Flush(n.ctx, admin, lease, 10)
	}()
	if err != nil || len(report.Finalized) != 1 || len(report.Admitted) != 1 {
		t.Fatalf("recovery flush: %+v %v", report, err)
	}
	// Exactly one sample, however often the batch was admitted: the same stable
	// batch was re-admitted after the restart and the data group deduplicated it.
	if got := n.stored("job:queue_depth:sum"); len(got) != 1 {
		t.Fatalf("recording duplicated across crash and restart: %v", got)
	}
	finalized, err := n.app.Control.RuleOutputs(n.ctx, admin, n.project, recording.ID, control.RulePhaseFinalized, 0)
	if err != nil || len(finalized) != 1 || finalized[0].Receipt == nil || *finalized[0].Receipt != report.Admitted[0] || len(finalized[0].Inputs) == 0 {
		t.Fatalf("stored recording provenance: %+v %v", finalized, err)
	}
	// The deposed pre-restart leader cannot commit evaluations any more.
	clock.set(125)
	if _, err = rules.NewScheduler(evaluator, rules.NewCommitter(n.app.Control, nil), store, rules.WithSchedulerClock(clock)).RunOnce(n.ctx, read, admin, alert, lease); err != nil {
		t.Fatal(err)
	}
	clock.set(185)
	if _, err = rules.NewScheduler(evaluator, rules.NewCommitter(n.app.Control, nil), store, rules.WithSchedulerClock(clock)).RunOnce(n.ctx, read, admin, alert, oldLease); err == nil {
		t.Fatal("the pre-restart leader committed an evaluation")
	}

	// 180s with the lease of the new term: still firing (queue_depth is 10).
	runBoth(lease)
	state, _ = store.Read(n.ctx, read, alert.ID)
	if len(state.Series) != 1 || state.Revision != 3 {
		t.Fatalf("alert state after 180s: %+v", state)
	}

	// 240s: the data is unavailable (a missing shard). The evaluation is
	// unknown, the firing series is untouched, nothing recovers.
	n.scanner.down.Store(true)
	clock.set(245)
	if _, err = scheduler.RunOnce(n.ctx, read, admin, alert, lease); err != nil {
		t.Fatal(err)
	}
	state, _ = store.Read(n.ctx, read, alert.ID)
	if state.Health != rules.HealthUnknown || state.Reason != rules.ReasonUnavailable || len(state.Series) != 1 || state.Revision != 4 {
		t.Fatalf("alert state with unavailable data: %+v", state)
	}
	for _, series := range state.Series {
		if series.Phase != rules.PhaseFiring {
			t.Fatalf("unavailable data moved the series to %s", series.Phase)
		}
	}

	// 300s: the data is back and complete; queue_depth is 1 since 270s, so the
	// series is genuinely absent and the alert recovers.
	n.scanner.down.Store(false)
	clock.set(305)
	if _, err = scheduler.RunOnce(n.ctx, read, admin, alert, lease); err != nil {
		t.Fatal(err)
	}
	state, _ = store.Read(n.ctx, read, alert.ID)
	if state.Health != rules.HealthOK || len(state.Series) != 0 || state.Revision != 5 {
		t.Fatalf("alert state after recovery: %+v", state)
	}
	// Condition history through C05: firing at 60s, resolved at 300s, nothing else.
	var statuses []string
	outs, err := n.app.Control.RuleOutputs(n.ctx, admin, n.project, alert.ID, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range outs {
		var intent rules.ConditionIntent
		if err := json.Unmarshal(o.Payload, &intent); err != nil {
			t.Fatal(err)
		}
		statuses = append(statuses, intent.Event.Status)
	}
	if len(statuses) != 2 || statuses[0] != "firing" || statuses[1] != "resolved" {
		t.Fatalf("condition history %v", statuses)
	}
}

// A derived series that collides with an already-ingested sample of the same
// identity and time is refused by real C05 admission for its whole batch. Only
// the colliding series is lost, reported; the recording's other series is stored.
func TestRecordingCollisionWithAnIngestedSampleDropsOnlyThatSeries(t *testing.T) {
	n := newNode(t)
	n.put("queue_depth", lbl("job", "api"), 30*sec, 10)
	n.put("queue_depth", lbl("job", "worker"), 30*sec, 10)
	// The same identity the rule records for job=api, at the rule's grid time,
	// with another value.
	n.put("job:queue_depth:sum", lbl("env", "prod", "job", "api"), 60*sec, 99)

	recording := n.rule(rules.KindRecording, `sum by (job) (queue_depth)`)
	if err := recording.Check(n.registry); err != nil {
		t.Fatal(err)
	}
	producer := rules.ProducerIdentity{Source: n.source, Producer: model.ID{0xee}, PolicyRevision: 1, Resource: n.resource}
	clock := &fixedClock{}
	clock.set(65)
	read, admin := n.scope(auth.Read), n.scope(auth.OrgAdmin)
	evaluator, committer, store := n.wiring(clock, rules.WithProducer(producer))
	lease := n.lease()
	if _, err := rules.NewScheduler(evaluator, committer, store, rules.WithSchedulerClock(clock)).RunOnce(n.ctx, read, admin, recording, lease); err != nil {
		t.Fatal(err)
	}
	worker, err := rules.NewOutputWorker(ingestAdmitter{n}, rules.NewOutboxStore(n.app.Control), ingestAdmitter{n}, n.app.Control.ReplicaGroup())
	if err != nil {
		t.Fatal(err)
	}
	report, err := worker.Flush(n.ctx, admin, lease, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Dropped) != 1 || report.Dropped[0].Reason != rules.ReasonSeriesConflict {
		t.Fatalf("the colliding series was not reported: %+v", report)
	}
	// The ingested sample (99) and the derived job=worker sample; the derived
	// job=api sample was the only one given up.
	if got := n.stored("job:queue_depth:sum"); len(got) != 2 || got[0] != 60*sec || got[1] != 60*sec {
		t.Fatalf("stored samples at the grid time: %v (report %+v)", got, report)
	}
	if pending, err := n.app.Control.RuleOutputs(n.ctx, admin, n.project, recording.ID, control.RulePhasePending, 0); err != nil || len(pending) != 0 {
		t.Fatalf("outputs still pending: %d %v", len(pending), err)
	}
}
