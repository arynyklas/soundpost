// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"soundpost/internal/appcore"
	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/symbolicate"
	"testing"
	"time"
)

type scopedFixture struct {
	app                         *appcore.App
	token                       string
	org, project, source, build model.ID
}

func newScopedFixture(t *testing.T) *scopedFixture {
	t.Helper()
	f := &scopedFixture{org: model.NewID(), project: model.NewID(), source: model.NewID(), build: model.NewID()}
	var e error
	f.app, e = appcore.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.app.Close() })
	ctx := context.Background()
	bootstrap, e := f.app.Control.BootstrapToken()
	if e != nil {
		t.Fatal(e)
	}
	session, e := f.app.Auth.Bootstrap(ctx, bootstrap, "symbolicate@example.test", "symbolicate fixture password 2026")
	if e != nil {
		t.Fatal(e)
	}
	f.token = session.Token
	actor, e := f.app.Auth.Authenticate(ctx, f.token)
	if e != nil {
		t.Fatal(e)
	}
	for _, command := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: "symbolicate"}}, {"create_project", auth.AdminPayload{ID: f.project, Name: "sources"}}} {
		command.p.Reason = "symbolication fixture"
		raw, e := json.Marshal(command.p)
		if e != nil {
			t.Fatal(e)
		}
		var rev model.Revision
		if e = f.app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil }); e != nil {
			t.Fatal(e)
		}
		if _, e = f.app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: f.org, Kind: command.kind, Payload: raw}); e != nil {
			t.Fatal(e)
		}
	}
	if e = f.app.Control.Update(ctx, func(st *model.ControlState) error {
		o := st.Orgs[f.org.String()]
		o.Members[session.User.String()] = true
		o.Grants[session.User.String()+":"+f.project.String()] = []string{"artifacts.write", "artifacts.read", "raw.read"}
		cfg, e := json.Marshal(auth.SourcePolicyConfig{ProjectID: f.project, Enabled: true, Readers: []model.ID{session.User}})
		if e != nil {
			return e
		}
		o.Settings["source_policy:"+f.source.String()] = cfg
		st.Orgs[f.org.String()] = o
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	_, e = f.app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: f.org, Project: f.project, Source: f.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Reason: "symbolication fixture", Policy: model.SourcePolicy{Enabled: true, Revision: 1, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()}, Builds: []model.ID{f.build}, Instances: []string{"symbolication-fixture"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 30, MaxSeries: 1000}})
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *scopedFixture) scope(t *testing.T, permission auth.Permission) auth.Scope {
	t.Helper()
	actor, e := f.app.Auth.Authenticate(context.Background(), f.token)
	if e != nil {
		t.Fatal(e)
	}
	s, e := f.app.Auth.Authorize(context.Background(), actor, f.org, []model.ID{f.project}, permission)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func (f *scopedFixture) put(t *testing.T, raw, generated []byte, private bool) (artifacts.Artifact, model.Frame) {
	t.Helper()
	m := artifacts.Manifest{Version: 1, Org: f.org, Project: f.project, Source: f.source, Build: f.build, DebugID: "exact-debug", GeneratedSHA256: model.HashCanonical(generated), MapSHA256: model.HashCanonical(raw), Path: "dist/simple.mjs", SourceContent: private, Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
	r, e := f.app.Artifacts.Put(context.Background(), f.scope(t, auth.ArtifactWrite), m, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	col := uint32(0)
	return r, model.Frame{Module: "fixture", Function: "original", Artifact: r.ID.String(), Line: 1, Column: &col}
}

type mismatchedReader struct{ *artifacts.Service }

func (r mismatchedReader) Lookup(ctx context.Context, s auth.Scope, id model.ID) (artifacts.Artifact, error) {
	a, e := r.Service.Lookup(ctx, s, id)
	a.Manifest.GeneratedSHA256 = model.HashCanonical([]byte("other"))
	return a, e
}
func TestScopedWrongHashNeverLaunchesFallback(t *testing.T) {
	f := newScopedFixture(t)
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`)
	_, frame := f.put(t, raw, []byte("generated"), false)
	s, e := symbolicate.New(mismatchedReader{f.app.Artifacts}, symbolicate.Config{})
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.Resolve(context.Background(), f.scope(t, auth.ArtifactRead), f.build, []model.Frame{frame})
	if e != nil || got[0].Reason != symbolicate.IdentityMismatch || !reflect.DeepEqual(got[0].Original, frame) {
		t.Fatalf("wrong hash fell back: %+v %v", got, e)
	}
}
func TestScopedSourceContextRequiresNamedGrant(t *testing.T) {
	f := newScopedFixture(t)
	_, frame := f.put(t, []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA","sourcesContent":["SECRET CANARY"]}`), []byte("generated"), true)
	ctx := context.Background()
	if e := f.app.Control.Update(ctx, func(st *model.ControlState) error {
		o := st.Orgs[f.org.String()]
		o.Epoch++
		cfg, e := json.Marshal(auth.SourcePolicyConfig{ProjectID: f.project, Enabled: true})
		if e != nil {
			return e
		}
		o.Settings["source_policy:"+f.source.String()] = cfg
		st.Orgs[f.org.String()] = o
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	s, e := symbolicate.New(f.app.Artifacts, symbolicate.Config{})
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.ResolveWithOptions(ctx, f.scope(t, auth.ArtifactRead), f.build, []model.Frame{frame}, symbolicate.Options{IncludeSources: true})
	if e != nil || got[0].Reason != symbolicate.SourceDenied || got[0].SourceContext != nil || !reflect.DeepEqual(got[0].Original, frame) {
		t.Fatalf("private grant bypass: %+v %v", got, e)
	}
}
func TestActualScopedViteSymbolicationAndRevocation(t *testing.T) {
	dir := os.Getenv("SOUNDPOST_SOURCEMAP_FIXTURE_DIR")
	configName := os.Getenv("SOUNDPOST_SYMBOLICATE_TEST_CONFIG")
	if dir == "" || configName == "" {
		t.Skip("requires actual Node/Vite fixture and sandbox configuration")
	}
	b, e := os.ReadFile(configName)
	if e != nil {
		t.Fatal(e)
	}
	var config symbolicate.Config
	if e = json.Unmarshal(b, &config); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(dir, "simple.mjs.map"))
	if e != nil {
		t.Fatal(e)
	}
	generated, e := os.ReadFile(filepath.Join(dir, "simple.mjs"))
	if e != nil {
		t.Fatal(e)
	}
	b, e = os.ReadFile(filepath.Join(dir, "simple.position.json"))
	if e != nil {
		t.Fatal(e)
	}
	var position struct{ GeneratedLine, GeneratedColumn uint32 }
	if e = json.Unmarshal(b, &position); e != nil {
		t.Fatal(e)
	}
	f := newScopedFixture(t)
	_, frame := f.put(t, raw, generated, false)
	frame.Line = position.GeneratedLine
	frame.Column = &position.GeneratedColumn
	s, e := symbolicate.New(f.app.Artifacts, config)
	if e != nil {
		t.Fatal(e)
	}
	scope := f.scope(t, auth.ArtifactRead)
	ctx := context.Background()
	for range 2 {
		got, e := s.Resolve(ctx, scope, f.build, []model.Frame{frame})
		if e != nil || got[0].Reason != symbolicate.Resolved || got[0].Resolved == nil || got[0].Resolved.Source != "simple.ts" || got[0].Resolved.Line != 4 || got[0].Resolved.Column != 8 || got[0].SourceContext != nil {
			t.Fatalf("real generated throw did not resolve: %+v %v", got, e)
		}
	}
	if e = f.app.Control.Update(ctx, func(st *model.ControlState) error {
		src := st.Sources[f.source.String()]
		src.Revoked = true
		st.Sources[f.source.String()] = src
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	got, e := s.Resolve(ctx, scope, f.build, []model.Frame{frame})
	if e != nil || got[0].Resolved != nil || got[0].SourceContext != nil || !reflect.DeepEqual(got[0].Original, frame) {
		t.Fatalf("warm cache leaked revoked source: %+v %v", got, e)
	}
}
