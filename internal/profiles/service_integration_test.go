// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package profiles_test

import (
	"context"
	"encoding/json"
	"errors"
	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/nativeperf"
	"soundpost/internal/policy"
	"soundpost/internal/profiles"
	"strings"
	"testing"
	"time"
)

func TestProfileRealReadPaginationForeignScopeAndRevocation(t *testing.T) {
	ctx := context.Background()
	app, e := appcore.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer app.Close()
	bootstrap, _ := app.Control.BootstrapToken()
	session, e := app.Auth.Bootstrap(ctx, bootstrap, "profiles-owner@example.test", "native profile password 2026")
	if e != nil {
		t.Fatal(e)
	}
	actor, e := app.Auth.Authenticate(ctx, session.Token)
	if e != nil {
		t.Fatal(e)
	}
	org, project, source, user := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	command := func(orgID model.ID, kind string, p auth.AdminPayload) {
		t.Helper()
		var rev model.Revision
		app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil })
		p.Reason = "real profile read fixture"
		raw, _ := json.Marshal(p)
		if _, err := app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: orgID, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	command(org, "create_org", auth.AdminPayload{Name: "profiles"})
	command(org, "create_project", auth.AdminPayload{ID: project, Name: "profiles"})
	command(org, "create_user", auth.AdminPayload{ID: user, Email: "profiles-reader@example.test", Password: "reader password long 2026"})
	command(org, "membership", auth.AdminPayload{UserID: user, Enabled: true})
	command(org, "grant", auth.AdminPayload{UserID: user, ProjectID: project, Enabled: true, Permissions: []string{"profiles.read"}})
	resource := model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "profiles", Labels: model.Labels{}}
	p := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Profile, model.CapabilityKind, model.Loss}, Resources: model.ResourceRegistry{Services: []model.ID{resource.Service}, Environments: []model.ID{resource.Environment}, Builds: []model.ID{resource.Build}, Instances: []string{"profiles"}}, RetentionDays: map[model.Kind]uint32{model.Profile: 7, model.CapabilityKind: 30, model.Loss: 30}, MaxBytes: 16 << 20, MaxSeries: 100}
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
	producer, root, capID := model.NewID(), model.NewID(), model.NewID()
	now := model.UnixNano(time.Now().UnixNano())
	d := nativeperf.ClockDomain{HostID: "host", BootID: "boot"}
	k := nativeperf.TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}
	caps := nativeperf.Capabilities{CPU: nativeperf.Supported, OffCPU: nativeperf.Denied, RunqueueSplit: nativeperf.Denied, Permissions: nativeperf.Permissions{CPUEventOpen: nativeperf.Supported, SchedulerEventOpen: nativeperf.Denied}, FrameCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}, ThreadCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}}
	events := []nativeperf.SanitizedEvent{}
	for i := range 3 {
		events = append(events, nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, Domain: d, Task: k, Sequence: model.Uint64(i + 1), Time: model.MonoNano(i + 1), CPUEvent: &nativeperf.CPUSample{IP: 4096, Callchain: []nativeperf.CallchainEntry{{IP: 4096}}, Method: nativeperf.MethodSoftwareCPUClock, Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: 901}})
	}
	c, e := nativeperf.AssembleProfile(ctx, events, nil, caps, nativeperf.ProfileLimits{Profile: root, Process: model.NewID(), Capability: capID, Domain: d, PolicyRevision: 1, Sequence: 1, Start: now, End: now + 100, Clock: model.TraceClock{Wall: now, Domain: model.ClockDomain{Host: model.ID{4}, Boot: model.ID{5}, Runtime: model.ID{6}}}, Complete: true, MaxBytes: 8 << 20, MaxSamples: 8192, MaxIntervals: 8192, MaxFrames: 4096, MaxStacks: 4096})
	if e != nil {
		t.Fatal(e)
	}
	appendRow := func(row model.Record) {
		t.Helper()
		row.Resource = resource
		row.ObservedAt = now
		row.ID = model.NewID()
		if row.Payload.Capability != nil {
			for i, method := range []string{"native_cpu", "native_offcpu", "native_runqueue_split"} {
				if row.Payload.Capability.Method == method {
					row.ID = c.NativeCapabilities[i]
				}
			}
		}
		batch := model.Batch{Version: 1, Project: project, Source: source, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{row}}
		batch.RouteSlot, _ = model.OwnerSlot(org, project, source, producer, row)
		if _, err := app.Ingest.Admit(ctx, grant, batch); err != nil {
			t.Fatal(err)
		}
	}
	c.Frames[0] = model.ProfileFrame{Module: strings.Repeat("a", 64), Artifact: model.NewID().String(), Reason: "artifact_unavailable"}
	appendRow(model.Record{Kind: model.Profile, Payload: model.Payload{Profile: &c}})
	for i, method := range []string{"native_cpu", "native_offcpu", "native_runqueue_split"} {
		status := "denied"
		reason := "permission_denied"
		if i == 0 {
			status = "supported"
			reason = "coverage_unmeasured"
		}
		value := model.Capability{Runtime: "native_linux", Version: "1", Build: "owned", OS: "linux", Arch: "amd64", Signal: model.Profile, Method: method, Status: status, Reason: reason, Coverage: model.Coverage{Frames: "unknown", Threads: "unknown", Workers: "none", Tasks: "unknown"}, Clock: c.Clock.Domain, Expires: now + model.UnixNano(time.Hour)}
		appendRow(model.Record{Kind: model.CapabilityKind, Payload: model.Payload{Capability: &value}})
	}
	login, e := app.Auth.Login(ctx, "profiles-reader@example.test", "reader password long 2026", "")
	if e != nil {
		t.Fatal(e)
	}
	reader, e := app.Auth.Authenticate(ctx, login.Token)
	if e != nil {
		t.Fatal(e)
	}
	scope, e := app.Auth.Authorize(ctx, reader, org, []model.ID{project}, auth.Permission("profiles.read"))
	if e != nil {
		t.Fatal(e)
	}
	service := app.NewNativeProfiles()
	w := profiles.Window{Start: now, End: now + 100, MaxSamples: 1}
	first, e := service.Read(ctx, scope, root, w)
	if e != nil {
		t.Fatal(e)
	}
	if len(first.Samples) != 1 || first.NextCursor == "" || len(first.Capabilities) != 3 {
		t.Fatal("real read missing samples/capabilities/pagination")
	}
	w.Cursor = first.NextCursor
	second, e := service.Read(ctx, scope, root, w)
	if e != nil || len(second.Samples) != 1 || second.Samples[0].At == first.Samples[0].At {
		t.Fatalf("pagination repeated/lost sample: %v", e)
	}
	if len(first.Links) != 1 || first.Links[0].Available || first.Links[0].Reference != nil {
		t.Fatal("missing/unauthorized artifact link leaked target metadata")
	}
	grant, e = ps.ResolveSource(ctx, credential, project, source, 1)
	if e != nil {
		t.Fatal(e)
	}
	missingMiddle := c
	missingMiddle.Sequence = 3
	missingMiddle.Samples = append([]model.ProfileSample(nil), c.Samples...)
	for i := range missingMiddle.Samples {
		missingMiddle.Samples[i].At = model.MonoNano(i + 4)
	}
	appendRow(model.Record{Kind: model.Profile, Payload: model.Payload{Profile: &missingMiddle}})
	all, e := service.Read(ctx, scope, root, profiles.Window{Start: now, End: now + 100, MaxSamples: 8192})
	if e != nil || all.Completeness != "partial" || len(all.Samples) != 6 {
		t.Fatal("missing middle chunk became complete or zero profile", e)
	}
	empty, e := service.Read(ctx, scope, root, profiles.Window{Start: now + 1000, End: now + 2000, MaxSamples: 1})
	if e != nil || empty.Completeness != "partial" || empty.BlockedNano != nil || len(empty.Samples) != 0 {
		t.Fatal("uncovered window presented zero CPU/scheduler", e)
	}
	foreignOrg, foreignProject := model.NewID(), model.NewID()
	command(foreignOrg, "create_org", auth.AdminPayload{Name: "foreign"})
	command(foreignOrg, "create_project", auth.AdminPayload{ID: foreignProject, Name: "foreign"})
	command(foreignOrg, "membership", auth.AdminPayload{UserID: user, Enabled: true})
	command(foreignOrg, "grant", auth.AdminPayload{UserID: user, ProjectID: foreignProject, Enabled: true, Permissions: []string{"profiles.read"}})
	foreign, e := app.Auth.Authorize(ctx, reader, foreignOrg, []model.ID{foreignProject}, auth.Permission("profiles.read"))
	if e != nil {
		t.Fatal(e)
	}
	_, foreignErr := service.Read(ctx, foreign, root, profiles.Window{Start: now, End: now + 100, MaxSamples: 1})
	_, missingErr := service.Read(ctx, foreign, model.NewID(), profiles.Window{Start: now, End: now + 100, MaxSamples: 1})
	var f, m *model.Fault
	if !errors.As(foreignErr, &f) || !errors.As(missingErr, &m) || f.Code != m.Code {
		t.Fatal("foreign root differs from unavailable")
	}
	if _, e = service.Read(ctx, foreign, root, w); e == nil {
		t.Fatal("foreign scope reused cursor")
	}
	command(org, "grant", auth.AdminPayload{UserID: user, ProjectID: project, Enabled: false})
	if _, e = service.Read(ctx, scope, root, w); e == nil {
		t.Fatal("revoked grant released next page")
	}
}
