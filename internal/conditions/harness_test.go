// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package conditions_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/conditions"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/query"
	"soundpost/internal/query/profile"
	"soundpost/internal/replica"
	"soundpost/internal/rules"
	"soundpost/internal/storage"
	"soundpost/profiles"
)

// This is the in-process stand-in for the brief's three-node smoke (which needs
// rule scheduling that appcore does not wire): a real appcore node (real control
// Raft group, auth, C03 admission, C05 storage), the real C06 engine behind a
// scanner wrapper that can make the data unavailable, real metric data admitted
// through the production ingest path, the committed C07 scheduler/committer, and
// the condition service over the same control store. Only the process boundary
// is not crossed: "restart" closes and reopens the node on the same directory.

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
	session, err := n.app.Auth.Bootstrap(n.ctx, boot, "conditions-owner@example.test", "conditions integration password 2026")
	if err != nil {
		t.Fatal(err)
	}
	n.token = session.Token
	n.authenticate()
	n.command("create_org", auth.AdminPayload{Name: "conditions"})
	n.command("create_project", auth.AdminPayload{ID: n.project, Name: "conditions"})
	n.command("membership", auth.AdminPayload{UserID: session.User, Enabled: true})
	n.command("grant", auth.AdminPayload{UserID: session.User, ProjectID: n.project, Enabled: true, Permissions: []string{string(auth.Read)}})
	n.resource = model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "conditions-1", Labels: model.Labels{}}
	sourcePolicy := model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric},
		Resources:     model.ResourceRegistry{Services: []model.ID{n.resource.Service}, Environments: []model.ID{n.resource.Environment}, Builds: []model.ID{n.resource.Build}, Instances: []string{n.resource.Instance}},
		Labels:        map[string][]string{"job": {"api", "worker"}, "env": {"prod"}},
		RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 64 << 20, MaxSeries: 1000,
	}
	issued, err := n.app.Auth.OnboardSource(n.ctx, n.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: n.org, Project: n.project, Source: n.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: sourcePolicy, Reason: "conditions integration"})
	if err != nil {
		t.Fatal(err)
	}
	n.issued = issued.Credential
	n.authenticateSource()
	return n
}

// open opens the node and binds the rule and condition dispatchers. A node whose
// application wiring already binds one is accepted as it is.
func (n *node) open() {
	n.t.Helper()
	var err error
	if n.app, err = appcore.Open(n.dir); err != nil {
		n.t.Fatal(err)
	}
	for _, bind := range []func() error{n.app.Control.BindRuleEvaluation, n.app.Control.BindConditionApply} {
		if err = bind(); err != nil {
			var fault *model.Fault
			if !errors.As(err, &fault) || fault.Code != model.Conflict {
				n.t.Fatal(err)
			}
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
	p.Reason = "conditions integration"
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

// orgScope is an organization-wide administrator scope (no project named).
func (n *node) orgScope() auth.Scope {
	n.t.Helper()
	s, err := n.app.Auth.Authorize(n.ctx, n.actor, n.org, nil, auth.OrgAdmin)
	if err != nil {
		n.t.Fatal(err)
	}
	return s
}

// put admits one metric sample through the production ingest path.
func (n *node) put(name string, lbls model.Labels, at model.UnixNano, value float64) {
	n.t.Helper()
	bits := model.FloatBits(math.Float64bits(value))
	producer := model.ID{0xd1}
	record := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: at, Resource: n.resource,
		Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: lbls, SampleKind: "float", Value: &bits, Unit: "1", Type: "gauge"}}}
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

func (n *node) lease() replica.FenceToken {
	n.t.Helper()
	token, err := n.app.Control.ReplicaGroup().Fence(n.ctx)
	if err != nil {
		n.t.Fatal(err)
	}
	return token
}

func (n *node) rule(expression string) rules.Rule {
	return rules.Rule{ID: model.NewID(), Project: n.project, Version: 1, Kind: rules.KindAlert, Profile: "promql-prometheus-3.13.5", FeatureSet: n.features["promql-prometheus-3.13.5"],
		Expression: expression, Interval: time.Minute, Severity: "page"}
}

func (n *node) wiring(clock rules.Clock) (*rules.Evaluator, *rules.Committer, rules.RuleStateReader) {
	store := rules.NewStateStore(n.app.Control)
	group := n.app.Control.ReplicaGroup()
	return rules.NewEvaluator(n.engine, store, rules.WithClock(clock), rules.WithFencer(group), rules.WithEvidence(rules.GapEvidence{Gaps: n.app.Control})), rules.NewCommitter(n.app.Control, group), store
}

// service is the condition service over the node's control store and group.
func (n *node) service(clock conditions.Clock, outbox conditions.Outbox) *conditions.Service {
	n.t.Helper()
	if outbox == nil {
		outbox = rules.NewOutboxStore(n.app.Control)
	}
	svc, err := conditions.New(n.app.Control, n.app.Control.ReplicaGroup(), outbox, clock)
	if err != nil {
		n.t.Fatal(err)
	}
	return svc
}

// conditionRecords are the committed control records, decoded.
func (n *node) conditionRecords() []control.ConditionRecord {
	n.t.Helper()
	recs, err := n.app.Control.Conditions(n.ctx, n.scope(auth.Read), n.project)
	if err != nil {
		n.t.Fatal(err)
	}
	return recs
}

func (n *node) audits(action string) int {
	n.t.Helper()
	count := 0
	if err := n.app.Control.View(n.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if a.Action == action {
				count++
			}
		}
		return nil
	}); err != nil {
		n.t.Fatal(err)
	}
	return count
}

func (n *node) revision() model.Revision {
	n.t.Helper()
	var r model.Revision
	if err := n.app.Control.View(n.ctx, func(st model.ControlState) error { r = st.Revision; return nil }); err != nil {
		n.t.Fatal(err)
	}
	return r
}

type fixedClock struct{ v atomic.Int64 }

func (c *fixedClock) Now() model.UnixNano { return model.UnixNano(c.v.Load()) }
func (c *fixedClock) set(s int64)         { c.v.Store(s * int64(time.Second)) }

// crashingOutbox makes the first finalize fail once armed: the process dies
// after the lifecycle state is durable but before the output is finalized.
type crashingOutbox struct {
	conditions.Outbox
	crashed atomic.Bool
	armed   atomic.Bool
}

func (o *crashingOutbox) Settle(ctx context.Context, scope auth.Scope, lease replica.FenceToken, item control.RuleOutput, update control.RuleOutputApply) (control.Result, error) {
	if o.armed.Load() && update.To == control.RulePhaseFinalized && o.crashed.CompareAndSwap(false, true) {
		return control.Result{}, errors.New("process crashed")
	}
	return o.Outbox.Settle(ctx, scope, lease, item, update)
}

// stateOf decodes a committed record's state (the wire form also carries the
// org and project headers, which State ignores).
func stateOf(t *testing.T, rec control.ConditionRecord) conditions.State {
	t.Helper()
	var s conditions.State
	if err := json.Unmarshal(rec.State, &s); err != nil {
		t.Fatal(err)
	}
	return s
}
