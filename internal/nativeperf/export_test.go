// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/ingest"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
	"github.com/arynyklas/soundpost/internal/policy"
	"testing"
	"time"
)

type exportTestLease struct{}

func (exportTestLease) Bytes() uint64 { return 2 << 20 }
func (exportTestLease) Close() error  { return nil }

type loseProfileReceipt struct {
	real     *ingest.Service
	lost     bool
	original model.Receipt
}

func (l *loseProfileReceipt) Admit(ctx context.Context, g policy.SourceGrant, b model.Batch) (model.Receipt, error) {
	r, e := l.real.Admit(ctx, g, b)
	if e == nil && !l.lost {
		for _, row := range b.Records {
			if row.Kind == model.Profile {
				l.lost = true
				l.original = r
				return model.Receipt{}, errors.New("fixture_lost_response")
			}
		}
	}
	return r, e
}

type exportReceiptLookup struct {
	s *ingest.Service
	c auth.SourceCredential
}

func (l exportReceiptLookup) LookupReceipt(ctx context.Context, q model.ReceiptRequest) (model.Receipt, error) {
	return l.s.LookupReceipt(ctx, l.c, q)
}
func TestProfileExportHistoricalPolicyRestrictionNoNewAdmission(t *testing.T) {
	ctx := context.Background()
	app, e := appcore.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer app.Close()
	boot, _ := app.Control.BootstrapToken()
	session, e := app.Auth.Bootstrap(ctx, boot, "profile@example.test", "profile fixture password 2026")
	if e != nil {
		t.Fatal(e)
	}
	actor, e := app.Auth.Authenticate(ctx, session.Token)
	if e != nil {
		t.Fatal(e)
	}
	org, project, source := model.NewID(), model.NewID(), model.NewID()
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var rev model.Revision
		app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil })
		p.Reason = "profile fixture"
		raw, _ := json.Marshal(p)
		if _, err := app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	command("create_org", auth.AdminPayload{Name: "profile"})
	command("create_project", auth.AdminPayload{ID: project, Name: "profile"})
	resource := model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "fixture", Labels: model.Labels{}}
	p := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Profile, model.CapabilityKind, model.Loss}, Resources: model.ResourceRegistry{Services: []model.ID{resource.Service}, Environments: []model.ID{resource.Environment}, Builds: []model.ID{resource.Build}, Instances: []string{"fixture"}}, RetentionDays: map[model.Kind]uint32{model.Profile: 7, model.CapabilityKind: 30, model.Loss: 30}, MaxBytes: 16 << 20, MaxSeries: 100}
	issued, e := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: p, Reason: "profile fixture"})
	if e != nil {
		t.Fatal(e)
	}
	credential, e := app.Auth.AuthenticateSource(ctx, issued.Credential, "", false)
	if e != nil {
		t.Fatal(e)
	}
	ps, e := policy.New(app.Auth, nil)
	if e != nil {
		t.Fatal(e)
	}
	grant, e := ps.ResolveSource(ctx, credential, project, source, 1)
	if e != nil {
		t.Fatal(e)
	}
	producer := model.NewID()
	root := model.NewID()
	capID := model.NewID()
	d := nativeperf.ClockDomain{HostID: "host", BootID: "boot"}
	k := nativeperf.TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}
	// Profile is last lane: all side-band evidence is already admitted before its
	// deliberately lost durable response. The ordering is a fixture input only.
	capRow := model.Record{ID: capID, Kind: model.CapabilityKind, Payload: model.Payload{Capability: &model.Capability{}}}
	capSlot, _ := model.OwnerSlot(org, project, source, producer, capRow)
	lossSlot, _ := model.OwnerSlot(org, project, source, producer, model.Record{Kind: model.Loss, Payload: model.Payload{Loss: &model.LossReport{}}})
	if lossSlot > capSlot {
		capSlot = lossSlot
	}
	for n := range 4096 {
		row := model.Record{Kind: model.Profile, Payload: model.Payload{Profile: &model.ProfileChunk{Profile: root}}}
		slot, _ := model.OwnerSlot(org, project, source, producer, row)
		if slot >= capSlot {
			break
		}
		root = model.NewID()
		if n == 4095 {
			t.Fatal("fixture route ordering unavailable")
		}
	}
	now := model.UnixNano(time.Now().UnixNano())
	limits := nativeperf.ProfileLimits{Profile: root, Process: model.NewID(), Capability: capID, Domain: d, PolicyRevision: 1, Sequence: 1, Start: now, End: now + 100, Clock: model.TraceClock{Wall: now, Domain: model.ClockDomain{Host: model.ID{4}, Boot: model.ID{5}, Runtime: model.ID{6}}}, MaxBytes: 8 << 20, MaxSamples: 8192, MaxIntervals: 8192, MaxFrames: 4096, MaxStacks: 4096}
	caps := nativeperf.Capabilities{CPU: nativeperf.Supported, OffCPU: nativeperf.Denied, RunqueueSplit: nativeperf.Denied, Permissions: nativeperf.Permissions{CPUEventOpen: nativeperf.Supported, SchedulerEventOpen: nativeperf.Denied}, FrameCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}, ThreadCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}}
	lost := &loseProfileReceipt{real: app.Ingest}
	exporter, e := nativeperf.NewExporter(lost, exportReceiptLookup{app.Ingest, credential}, nativeperf.ExportConfig{Project: project, Source: source, Producer: producer, Resource: resource, Limits: limits, Capabilities: caps}, exportTestLease{})
	if e != nil {
		t.Fatal(e)
	}
	defer exporter.Close()
	chunk := nativeperf.ProfileChunk{ProfileID: root, PolicyRevision: 1, Domain: d, Events: []nativeperf.SanitizedEvent{{Kind: nativeperf.EventCPU, Domain: d, Task: k, Sequence: 1, Time: 10, CPUEvent: &nativeperf.CPUSample{IP: 4096, Callchain: []nativeperf.CallchainEntry{{IP: 4096}}, Method: nativeperf.MethodSoftwareCPUClock, Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: 901}}}}
	oversized := chunk
	oversized.Events = make([]nativeperf.SanitizedEvent, 257)
	if _, e = exporter.Send(ctx, grant, oversized); !errors.Is(e, nativeperf.ErrResourceBudget) {
		t.Fatal("oversized capture did not backpressure", e)
	}
	drop := exporter.DropReport()
	if drop.Count != 1 || drop.Reason != "queue_full" || drop.Source != source || drop.Producer != producer || exporter.Stats().Admitted {
		t.Fatal("bounded drop was hidden or claimed admitted")
	}
	if _, e = exporter.Send(ctx, grant, chunk); e == nil || !lost.lost {
		t.Fatal("ambiguous commit was ACKed")
	}
	next := p
	next.Revision = 2
	next.Enabled = false
	if _, e = app.Auth.ChangeSourcePolicy(ctx, actor, auth.SourcePolicyChange{CommandID: model.NewID(), Source: source, ExpectedRevision: 1, Policy: next, Reason: "restrict native fixture"}); e != nil {
		t.Fatal(e)
	}
	if e = app.Auth.DrainSourceFences(ctx); e != nil {
		t.Fatal(e)
	}
	var before int
	app.Control.View(ctx, func(st model.ControlState) error { before = len(st.Reservations); return nil })
	r, e := exporter.Send(ctx, grant, chunk)
	if e != nil || !r.Historical {
		t.Fatalf("historical recovery: %v", e)
	}
	r.Historical = false
	a, _ := json.Marshal(r)
	b, _ := json.Marshal(lost.original)
	if string(a) != string(b) {
		t.Fatal("historical receipt changed deadlines/hash/cursor")
	}
	app.Control.View(ctx, func(st model.ControlState) error {
		if len(st.Reservations) != before {
			t.Fatal("historical lookup reserved again")
		}
		return nil
	})
	changed := chunk
	changed.Events = append([]nativeperf.SanitizedEvent(nil), chunk.Events...)
	changedSample := *chunk.Events[0].CPUEvent
	changedSample.Period++
	changed.Events[0].CPUEvent = &changedSample
	_, e = exporter.Send(ctx, grant, changed)
	var conflict *model.Fault
	if !errors.As(e, &conflict) || conflict.Code != model.Conflict {
		t.Fatal("frozen profile identity accepted changed bytes", e)
	}
	if e = app.Auth.RevokeSource(ctx, actor, source, "revoke native fixture"); e != nil {
		t.Fatal(e)
	}
	q := exporter.LastReceiptRequest()
	_, e = app.Ingest.LookupReceipt(ctx, credential, q)
	var denied *model.Fault
	if !errors.As(e, &denied) || denied.Code != model.Forbidden {
		t.Fatal("revoked source receipt lookup did not return required403", e)
	}
}
