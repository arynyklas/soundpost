// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"soundpost/internal/appcore"
	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"testing"
	"time"
)

// artifactDeletionFx is a real organization with one published artifact (map
// plus private sources) so ValidateArtifactState runs against authentic
// manifests, reservations and source policy.
type artifactDeletionFx struct {
	app                         *appcore.App
	token                       string
	org, project, source, build model.ID
	art                         artifacts.Artifact
}

func newArtifactDeletionFx(t *testing.T) *artifactDeletionFx {
	t.Helper()
	f := &artifactDeletionFx{org: model.NewID(), project: model.NewID(), source: model.NewID(), build: model.NewID()}
	var err error
	if f.app, err = appcore.Open(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.app.Close() })
	ctx := context.Background()
	bootstrap, err := f.app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := f.app.Auth.Bootstrap(ctx, bootstrap, "artifact-delete@example.test", "artifact deletion fixture password 2026")
	if err != nil {
		t.Fatal(err)
	}
	f.token = session.Token
	actor, err := f.app.Auth.Authenticate(ctx, f.token)
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: "artifact-delete"}}, {"create_project", auth.AdminPayload{ID: f.project, Name: "builds"}}} {
		cmd.p.Reason = "artifact deletion fixture"
		raw, e := json.Marshal(cmd.p)
		if e != nil {
			t.Fatal(e)
		}
		var rev model.Revision
		if err = f.app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil }); err != nil {
			t.Fatal(err)
		}
		if _, err = f.app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: f.org, Kind: cmd.kind, Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.app.Control.Update(ctx, func(st *model.ControlState) error {
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
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: f.org, Project: f.project, Source: f.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Reason: "artifact deletion fixture", Policy: model.SourcePolicy{Enabled: true, Revision: 1, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()}, Builds: []model.ID{f.build}, Instances: []string{"artifact-delete"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 30, MaxSeries: 1000}}); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA","sourcesContent":["PRIVATE"]}`)
	m := artifacts.Manifest{Version: 1, Org: f.org, Project: f.project, Source: f.source, Build: f.build, DebugID: "debug-delete", GeneratedSHA256: model.HashCanonical([]byte("generated")), MapSHA256: model.HashCanonical(raw), Path: "dist/app.js", SourceContent: true, Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
	if f.art, err = f.app.Artifacts.Put(ctx, f.scope(t, auth.ArtifactWrite), m, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if f.art.Sources == nil {
		t.Fatal("fixture artifact has no private sources")
	}
	return f
}
func (f *artifactDeletionFx) scope(t *testing.T, action auth.Permission) auth.Scope {
	t.Helper()
	actor, err := f.app.Auth.Authenticate(context.Background(), f.token)
	if err != nil {
		t.Fatal(err)
	}
	s, err := f.app.Auth.Authorize(context.Background(), actor, f.org, []model.ID{f.project}, action)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// validate runs the pure state predicate against the real control state with
// exactly one deletion record added; the stored state is never touched.
func (f *artifactDeletionFx) validate(t *testing.T, scope auth.Scope, m model.BlobManifest, write bool, deletions ...model.DeletionOperation) error {
	t.Helper()
	var out error
	if err := f.app.Control.View(context.Background(), func(st model.ControlState) error {
		st.Deletions = map[string]model.DeletionOperation{}
		for _, op := range deletions {
			st.Deletions[op.Predicate.Operation.String()] = op
		}
		out = scope.ValidateArtifactState(st, m, write)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}
func faultCode(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}

func (f *artifactDeletionFx) op(mode, phase string, mut func(*model.DeletePredicate)) model.DeletionOperation {
	p := model.DeletePredicate{Operation: model.NewID(), Org: f.org, Mode: mode}
	switch mode {
	case model.DeleteRetireProject:
		p.Projects = []model.ID{f.project}
	case model.DeleteEntity:
		p.Projects, p.Entities = []model.ID{f.project}, []model.ID{f.art.ID}
	case model.DeleteHistoricalRange:
		p.Projects, p.Signals, p.Start, p.End = []model.ID{f.project}, []model.Kind{model.Metric}, 0, 1<<62
	}
	if mut != nil {
		mut(&p)
	}
	return model.DeletionOperation{Predicate: p, Phase: phase}
}

// An active deletion that covers an artifact root makes every blob of that root
// (map and private sources) indistinguishable from an absent artifact on read,
// and is a Conflict on write (the storage barrier answers the same code). Every
// consumer that revalidates through ValidateArtifactState inherits this.
func TestValidateArtifactStateRefusesRootCoveredByActiveDeletion(t *testing.T) {
	f := newArtifactDeletionFx(t)
	read, write := f.scope(t, auth.ArtifactRead), f.scope(t, auth.ArtifactWrite)
	blobs := map[string]model.BlobManifest{"map": f.art.Map.Manifest, "sources": f.art.Sources.Manifest}
	for name, m := range blobs {
		if err := f.validate(t, read, m, false); err != nil {
			t.Fatalf("%s: baseline read refused: %v", name, err)
		}
		if err := f.validate(t, write, m, true); err != nil {
			t.Fatalf("%s: baseline write refused: %v", name, err)
		}
	}
	other := model.NewID()
	elsewhere := f.op(model.DeleteEntity, model.DeletePhaseComplete, func(p *model.DeletePredicate) { p.Org = model.NewID() })
	for _, tc := range []struct {
		name  string
		op    model.DeletionOperation
		read  model.Code // "" means allowed
		write model.Code
	}{
		{"entity naming the root, fencing", f.op(model.DeleteEntity, model.DeletePhaseFencing, nil), model.NotFound, model.Conflict},
		{"entity naming the root, complete", f.op(model.DeleteEntity, model.DeletePhaseComplete, nil), model.NotFound, model.Conflict},
		{"entity naming the root, failed", f.op(model.DeleteEntity, model.DeletePhaseFailed, nil), model.NotFound, model.Conflict},
		{"entity naming the root, held (not begun)", f.op(model.DeleteEntity, model.DeletePhaseHeld, nil), "", ""},
		{"entity naming another root", f.op(model.DeleteEntity, model.DeletePhaseComplete, func(p *model.DeletePredicate) { p.Entities = []model.ID{other} }), "", ""},
		{"entity of another project", f.op(model.DeleteEntity, model.DeletePhaseComplete, func(p *model.DeletePredicate) { p.Projects = []model.ID{model.NewID()} }), "", ""},
		{"entity of another organization", elsewhere, "", ""},
		{"retire_project of the project", f.op(model.DeleteRetireProject, model.DeletePhaseFencing, nil), model.NotFound, model.Conflict},
		{"retire_project of another project", f.op(model.DeleteRetireProject, model.DeletePhaseComplete, func(p *model.DeletePredicate) { p.Projects = []model.ID{model.NewID()} }), "", ""},
		{"retire_org", f.op(model.DeleteRetireOrg, model.DeletePhaseComplete, nil), model.NotFound, model.Conflict},
		{"historical_range never covers an artifact", f.op(model.DeleteHistoricalRange, model.DeletePhaseComplete, nil), "", ""},
	} {
		for blob, m := range blobs {
			if got := faultCode(f.validate(t, read, m, false, tc.op)); got != tc.read {
				t.Errorf("%s / %s read: got %q want %q", tc.name, blob, got, tc.read)
			}
			if got := faultCode(f.validate(t, write, m, true, tc.op)); got != tc.write {
				t.Errorf("%s / %s write: got %q want %q", tc.name, blob, got, tc.write)
			}
		}
	}
	// One covering record among unrelated ones is enough.
	mixed := []model.DeletionOperation{elsewhere, f.op(model.DeleteHistoricalRange, model.DeletePhaseComplete, nil), f.op(model.DeleteEntity, model.DeletePhaseComplete, nil)}
	if got := faultCode(f.validate(t, read, f.art.Map.Manifest, false, mixed...)); got != model.NotFound {
		t.Fatalf("covering deletion among others ignored: %q", got)
	}
}
