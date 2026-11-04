// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate_test

import (
	"context"
	"encoding/json"
	"reflect"
	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/symbolicate"
	"testing"
)

type revokeBeforeRelease struct {
	*artifacts.Service
	calls  int
	revoke func() error
}

func (r *revokeBeforeRelease) Lookup(ctx context.Context, s auth.Scope, id model.ID) (artifacts.Artifact, error) {
	r.calls++
	if r.calls == 2 {
		if e := r.revoke(); e != nil {
			return artifacts.Artifact{}, e
		}
	}
	return r.Service.Lookup(ctx, s, id)
}
func TestCurrentAuthorityRecheckedAtWorkerRelease(t *testing.T) {
	f := newScopedFixture(t)
	_, frame := f.put(t, []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`), []byte("generated"), false)
	ctx := context.Background()
	reader := &revokeBeforeRelease{Service: f.app.Artifacts, revoke: func() error {
		return f.app.Control.Update(ctx, func(st *model.ControlState) error {
			src := st.Sources[f.source.String()]
			src.Revoked = true
			st.Sources[f.source.String()] = src
			return nil
		})
	}}
	service, e := symbolicate.New(reader, symbolicate.Config{})
	if e != nil {
		t.Fatal(e)
	}
	got, e := service.Resolve(ctx, f.scope(t, auth.ArtifactRead), f.build, []model.Frame{frame})
	if e != nil || got[0].Reason != symbolicate.Unavailable || got[0].Resolved != nil || !reflect.DeepEqual(got[0].Original, frame) {
		t.Fatalf("post-worker revocation not fenced: %+v %v", got, e)
	}
}
func TestBarePathsAndLabelsNeverBecomeArtifactLookup(t *testing.T) {
	f := newScopedFixture(t)
	_, frame := f.put(t, []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`), []byte("generated"), false)
	service, e := symbolicate.New(f.app.Artifacts, symbolicate.Config{})
	if e != nil {
		t.Fatal(e)
	}
	for _, identity := range []string{"dist/simple.mjs", "release-2026.11", "https://example.invalid/app.js.map", "../../private", "a4"} {
		frame.Artifact = identity
		got, e := service.Resolve(context.Background(), f.scope(t, auth.ArtifactRead), f.build, []model.Frame{frame})
		if e != nil || got[0].Reason != symbolicate.Unavailable || got[0].Resolved != nil || !reflect.DeepEqual(got[0].Original, frame) {
			t.Fatal("legacy identity used as lookup alias", identity, e)
		}
	}
}
func TestActualArtifactCannotBeSelectedWithOtherBuild(t *testing.T) {
	f := newScopedFixture(t)
	_, frame := f.put(t, []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`), []byte("generated"), false)
	service, e := symbolicate.New(f.app.Artifacts, symbolicate.Config{})
	if e != nil {
		t.Fatal(e)
	}
	got, e := service.Resolve(context.Background(), f.scope(t, auth.ArtifactRead), model.NewID(), []model.Frame{frame})
	if e != nil || got[0].Reason != symbolicate.IdentityMismatch || got[0].Resolved != nil || !reflect.DeepEqual(got[0].Original, frame) {
		t.Fatal("wrong build fell back to actual artifact", got, e)
	}
}
func TestWarmedArtifactCacheCannotCrossActualOrganizationScope(t *testing.T) {
	f := newScopedFixture(t)
	_, frame := f.put(t, []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`), []byte("generated"), false)
	service, e := symbolicate.New(f.app.Artifacts, symbolicate.Config{})
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	first, e := service.Resolve(ctx, f.scope(t, auth.ArtifactRead), f.build, []model.Frame{frame})
	if e != nil || first[0].Reason != symbolicate.SandboxUnavailable {
		t.Fatal("real authorized map did not reach sandbox/cache boundary", first, e)
	}
	actor, e := f.app.Auth.Authenticate(ctx, f.token)
	if e != nil {
		t.Fatal(e)
	}
	org, project := model.NewID(), model.NewID()
	for _, command := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: "other-symbolicate"}}, {"create_project", auth.AdminPayload{ID: project, Name: "other-sources"}}} {
		command.p.Reason = "symbolication cross-org denial"
		raw, e := json.Marshal(command.p)
		if e != nil {
			t.Fatal(e)
		}
		var revision model.Revision
		if e = f.app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); e != nil {
			t.Fatal(e)
		}
		if _, e = f.app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: command.kind, Payload: raw}); e != nil {
			t.Fatal(e)
		}
	}
	principal := f.scope(t, auth.ArtifactRead).PrincipalID()
	if e = f.app.Control.Update(ctx, func(st *model.ControlState) error {
		o := st.Orgs[org.String()]
		o.Members[principal.String()] = true
		o.Grants[principal.String()+":"+project.String()] = []string{"artifacts.read"}
		st.Orgs[org.String()] = o
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	other, e := f.app.Auth.Authorize(ctx, actor, org, []model.ID{project}, auth.ArtifactRead)
	if e != nil {
		t.Fatal(e)
	}
	got, e := service.Resolve(ctx, other, f.build, []model.Frame{frame})
	if e != nil || got[0].Reason != symbolicate.Unavailable || got[0].Resolved != nil || got[0].SourceContext != nil || !reflect.DeepEqual(got[0].Original, frame) {
		t.Fatalf("warmed artifact crossed actual organization authority: %+v %v", got, e)
	}
}
