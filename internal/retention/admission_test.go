// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
	"github.com/arynyklas/soundpost/internal/retention"
)

// admitted runs one metric batch through source resolution and normalization, as ingest does, and
// returns the metric deadline of the receipt it would be given.
func (f *fx) admitted(p *policy.Service) (model.UnixNano, model.UnixNano) {
	f.t.Helper()
	src, err := f.auth.SourceAuthority(f.ctx, f.source, true)
	if err != nil {
		f.t.Fatal(err)
	}
	grant, err := p.ResolveSource(f.ctx, f.source, f.desc.Project, f.desc.Source, src.Policy.Revision)
	if err != nil {
		f.t.Fatal(err)
	}
	v := model.FloatBits(0x3ff0000000000000)
	b := model.Batch{Version: 1, Project: f.desc.Project, Source: f.desc.Source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: src.Policy.Revision, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(f.clock.Load()), Resource: model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}, Payload: model.Payload{Metric: &model.MetricPoint{Name: "admission_retention", Labels: model.Labels{}, SampleKind: "float", Value: &v, Type: "counter", Unit: "1"}}}}}
	if b.RouteSlot, err = model.OwnerSlot(f.desc.Org, b.Project, b.Source, b.Producer, b.Records[0]); err != nil {
		f.t.Fatal(err)
	}
	n, err := policy.Normalize(grant, b)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, d := range n.Deadlines {
		if d.Kind == model.Metric {
			return n.AdmissionAt, d.RetainUntil
		}
	}
	f.t.Fatal("no metric deadline")
	return 0, 0
}

func (f *fx) audits() []model.ControlAudit {
	f.t.Helper()
	var out []model.ControlAudit
	if err := f.store.View(f.ctx, func(st control.State) error { out = append(out, st.Audits...); return nil }); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func days(at, until model.UnixNano) uint32 {
	return uint32((time.Duration(until-at) + 12*time.Hour) / (24 * time.Hour))
}

// 01.08-W1: receipt deadlines come from the design s12 resolution (defaults, then the audited
// organization and project versions in force at admission), not from the days a source policy
// happens to carry; an admin "retention" command is such an audited version; a receipt already
// issued keeps its absolute deadline.
func TestAdmissionDeadlinesUseResolvedRetentionAndAdminRetentionCommand(t *testing.T) {
	f := newFx(t, options{})
	now := func() time.Time { return f.at() }
	p, err := policy.New(f.auth, now)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := retention.NewAdmissionResolver(f.store)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.BindRetention(resolver); err != nil {
		t.Fatal(err)
	}
	// The fixture's source policy declares 14 days for metrics, which is also the design default.
	at0, first := f.admitted(p)
	if got := days(at0, first); got != 14 {
		t.Fatalf("no version: %d days, want the design default 14", got)
	}

	// The admin 'retention' command: 30 days of metrics for the project, audited.
	cfg, _ := json.Marshal(auth.RetentionConfig{ProjectID: f.project, Signal: "metrics", Days: 30})
	f.advance(time.Second) // the version takes effect after the first batch was admitted
	f.admin("retention", auth.AdminPayload{ID: model.NewID(), Config: cfg, Reason: "longer metrics"})
	f.advance(time.Second)
	at1, second := f.admitted(p)
	if got := days(at1, second); got != 30 {
		t.Fatalf("after the admin command: %d days, want 30 (the source policy still says 14)", got)
	}
	// Receipts keep the absolute deadline they were issued with; an earlier instant resolves to
	// the policy that was in force then.
	if first != at0+model.UnixNano(14*24*time.Hour) {
		t.Fatalf("an issued deadline moved: %d", first)
	}
	old, err := resolver.ResolveRetention(f.ctx, f.org, f.project, at0)
	if err != nil || old.Days[model.Metric] != 14 {
		t.Fatalf("resolving the past: %v %v", old.Days[model.Metric], err)
	}
	audited := false
	for _, a := range f.audits() {
		audited = audited || a.Action == "retention" && a.Reason == "longer metrics"
	}
	if !audited {
		t.Fatal("the admin retention command left no audit record")
	}
	// A project version for another signal does not touch metrics.
	cfg, _ = json.Marshal(auth.RetentionConfig{ProjectID: f.project, Signal: "logs", Days: 3})
	f.admin("retention", auth.AdminPayload{ID: model.NewID(), Config: cfg, Reason: "short logs"})
	f.advance(time.Second)
	at2, third := f.admitted(p)
	if got := days(at2, third); got != 30 {
		t.Fatalf("logs version changed the metric deadline: %d days", got)
	}
}
