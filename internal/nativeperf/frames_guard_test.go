// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// resolveFrames carries its own guard in front of the first artifact read: the symbol policy of the table must be valid
// and its scope must be an artifacts.read scope of an organization that allows the policy's project. AssembleProfile
// checks the same things in SymbolBinding.validate first, so the guard is not reachable through it; this test calls
// resolveFrames (through the export_test seam) with policies and scopes that binding would have refused, and pins that
// each one ends as artifact_denied without a single read of the backend, while a policy that satisfies the guard names
// the frame.
func TestResolveFramesDeniesAPolicyItsOwnGuardRejectsBeforeAnyRead(t *testing.T) {
	ctx := context.Background()
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	boot, _ := app.Control.BootstrapToken()
	session, err := app.Auth.Bootstrap(ctx, boot, "guard@example.test", "frame guard fixture password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, project := model.NewID(), model.NewID()
	command := func(kind string, p auth.AdminPayload) {
		t.Helper()
		var rev model.Revision
		app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil })
		p.Reason = "frame guard fixture"
		raw, _ := json.Marshal(p)
		if _, e := app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: kind, Payload: raw}); e != nil {
			t.Fatal(e)
		}
	}
	command("create_org", auth.AdminPayload{Name: "guard"})
	command("create_project", auth.AdminPayload{ID: project, Name: "guard"})
	if err = app.Control.Update(ctx, func(st *model.ControlState) error {
		o := st.Orgs[org.String()]
		o.Members[session.User.String()] = true
		o.Grants[session.User.String()+":"+project.String()] = []string{string(auth.ArtifactRead), string(auth.Read)}
		st.Orgs[org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	scope := func(action auth.Permission) auth.Scope {
		t.Helper()
		s, e := app.Auth.Authorize(ctx, actor, org, []model.ID{project}, action)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	readScope := scope(auth.ArtifactRead)
	if readScope.OrgID() == (model.ID{}) || !readScope.AllowsProject(project) || readScope.Permission() != auth.ArtifactRead {
		t.Fatalf("the fixture scope is not an artifacts.read scope of the project: %v", readScope.Permission())
	}

	policy := func(edit func(*nativeperf.SymbolPolicy)) nativeperf.SymbolPolicy {
		p := nativeperf.DefaultSymbolPolicy(1)
		p.ArtifactScope, p.ProjectID = readScope, project
		p.Artifacts = map[string]model.ID{"ab12": model.NewID()}
		if edit != nil {
			edit(&p)
		}
		return p
	}

	// the control: a policy that satisfies the guard is read once and names the frame
	frame, reads := nativeperf.ResolveApprovedFrameUnderPolicy(t, policy(nil))
	if frame.Reason != "" || frame.Symbol != "approved_hot_loop" || reads != 1 || frame.Module == nil {
		t.Fatalf("a valid policy: %+v after %d reads", frame, reads)
	}

	for _, tc := range []struct {
		name string
		edit func(*nativeperf.SymbolPolicy)
	}{
		{"a policy without a revision", func(p *nativeperf.SymbolPolicy) { p.Revision = 0 }},
		{"an ELF ceiling above 32 MiB", func(p *nativeperf.SymbolPolicy) { p.MaxELFBytes = 33 << 20 }},
		{"no symbol budget", func(p *nativeperf.SymbolPolicy) { p.MaxSymbols = 0 }},
		{"a read interval under 100 ms", func(p *nativeperf.SymbolPolicy) { p.MinReadInterval = 99_000_000 }},
		{"an artifact map naming an invalid build", func(p *nativeperf.SymbolPolicy) { p.Artifacts["not-a-build"] = model.NewID() }},
		{"a scope of another permission", func(p *nativeperf.SymbolPolicy) { p.ArtifactScope = scope(auth.Read) }},
		{"a project outside the scope", func(p *nativeperf.SymbolPolicy) { p.ProjectID = model.NewID() }},
		{"no scope at all", func(p *nativeperf.SymbolPolicy) { p.ArtifactScope = auth.Scope{} }},
	} {
		frame, reads := nativeperf.ResolveApprovedFrameUnderPolicy(t, policy(tc.edit))
		if frame.Reason != nativeperf.FrameArtifactDenied || frame.Symbol != "" || reads != 0 {
			t.Errorf("%s: %+v after %d reads, want artifact_denied and no read", tc.name, frame, reads)
		}
		if frame.Module == nil || frame.Module.BuildID != "ab12" || uint64(frame.Offset) != 0x108 {
			t.Errorf("%s: the denied frame lost its identity: %+v", tc.name, frame)
		}
	}
}
