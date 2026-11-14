// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/retention"
	"testing"
	"time"
)

type artifactLookupFx struct {
	app                         *appcore.App
	token                       string
	org, project, source, build model.ID
}

func newArtifactLookupFx(t *testing.T) *artifactLookupFx {
	t.Helper()
	f := &artifactLookupFx{org: model.NewID(), project: model.NewID(), source: model.NewID(), build: model.NewID()}
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
	session, err := f.app.Auth.Bootstrap(ctx, bootstrap, "artifact-lookup@example.test", "artifact lookup fixture password 2026")
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
	}{{"create_org", auth.AdminPayload{Name: "artifact-lookup"}}, {"create_project", auth.AdminPayload{ID: f.project, Name: "builds"}}} {
		cmd.p.Reason = "artifact lookup fixture"
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
		o.Grants[session.User.String()+":"+f.project.String()] = []string{"artifacts.write", "artifacts.read"}
		cfg, e := json.Marshal(auth.SourcePolicyConfig{ProjectID: f.project, Enabled: true})
		if e != nil {
			return e
		}
		o.Settings["source_policy:"+f.source.String()] = cfg
		st.Orgs[f.org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: f.org, Project: f.project, Source: f.source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Reason: "artifact lookup fixture", Policy: model.SourcePolicy{Enabled: true, Revision: 1, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()}, Builds: []model.ID{f.build}, Instances: []string{"artifact-lookup"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 30, MaxSeries: 1000}}); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *artifactLookupFx) scope(t *testing.T, action auth.Permission) auth.Scope {
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
func (f *artifactLookupFx) put(t *testing.T, debug string) artifacts.Artifact {
	t.Helper()
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`)
	m := artifacts.Manifest{Version: 1, Org: f.org, Project: f.project, Source: f.source, Build: f.build, DebugID: debug, GeneratedSHA256: model.HashCanonical([]byte(debug)), MapSHA256: model.HashCanonical(raw), Path: "dist/" + debug + ".js", Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
	a, err := f.app.Artifacts.Put(context.Background(), f.scope(t, auth.ArtifactWrite), m, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func (f *artifactLookupFx) deleteEntity(t *testing.T, root model.ID) retention.DeleteReceipt {
	t.Helper()
	var rev model.Revision
	if err := f.app.Control.View(context.Background(), func(st model.ControlState) error { rev = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	actor, err := f.app.Auth.Authenticate(context.Background(), f.token)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := f.app.Auth.Authorize(context.Background(), actor, f.org, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.app.Retention.Delete(context.Background(), admin, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: rev, Mode: model.DeleteEntity, OrgID: f.org, ProjectIDs: []model.ID{f.project}, EntityIDs: []model.ID{root}, Reason: "artifact lookup fixture"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func lookupCode(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}

// The control lookup is what every consumer of an artifact reference
// (protected reads, symbolication, HTTP) fences on: a root covered by an active
// entity deletion is NotFound the moment Begin commits, exactly like an absent
// root, while the other roots of the same project stay readable.
func TestLookupArtifactIsNotFoundForRootOfActiveEntityDeletion(t *testing.T) {
	f := newArtifactLookupFx(t)
	ctx := context.Background()
	gone, kept := f.put(t, "debug-gone"), f.put(t, "debug-kept")
	for _, a := range []artifacts.Artifact{gone, kept} {
		if got, err := f.app.Control.LookupArtifact(ctx, f.scope(t, auth.ArtifactRead), a.ID); err != nil || got.ID != a.ID {
			t.Fatalf("baseline lookup of %s: %v", a.ID, err)
		}
	}
	absent := lookupCode(func() error {
		_, err := f.app.Control.LookupArtifact(ctx, f.scope(t, auth.ArtifactRead), model.NewID())
		return err
	}())
	f.deleteEntity(t, gone.ID)
	_, err := f.app.Control.LookupArtifact(ctx, f.scope(t, auth.ArtifactRead), gone.ID)
	if lookupCode(err) != model.NotFound || lookupCode(err) != absent {
		t.Fatalf("lookup of a root under an active deletion: %v (absent root answers %q)", err, absent)
	}
	if _, err = f.app.Artifacts.Lookup(ctx, f.scope(t, auth.ArtifactRead), gone.ID); lookupCode(err) != model.NotFound {
		t.Fatalf("artifact service lookup of a deleted root: %v", err)
	}
	if got, err := f.app.Control.LookupArtifact(ctx, f.scope(t, auth.ArtifactRead), kept.ID); err != nil || got.ID != kept.ID {
		t.Fatalf("unrelated root lost: %v", err)
	}
}

func (f *artifactLookupFx) setIntent(t *testing.T, a artifacts.Artifact, mutate func(*model.ArtifactReferenceIntent)) {
	t.Helper()
	key := f.org.String() + ":" + f.project.String() + ":" + a.ID.String()
	if err := f.app.Control.Update(context.Background(), func(st *model.ControlState) error {
		intent, ok := st.ArtifactIntents[key]
		if !ok {
			return model.Fail(model.NotFound)
		}
		mutate(&intent)
		st.ArtifactIntents[key] = intent
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Startup validation requires the bytes of every PUBLISHED intent (a published intent
// whose blob is gone is Corrupt: control never repairs authority from missing files) and
// requires nothing of a RETIRED one, whose state the artifact lifecycle wrote in the
// transition that fenced the root for erasure. A retired intent is still validated for
// structure, is never readable through the lookup, and the skip is per intent.
func TestValidateArtifactReferencesSkipsOnlyRetiredIntents(t *testing.T) {
	f := newArtifactLookupFx(t)
	ctx := context.Background()
	a, b := f.put(t, "validate-a"), f.put(t, "validate-b")
	if err := f.app.Control.ValidateArtifactReferences(ctx); err != nil {
		t.Fatalf("intact references: %v", err)
	}
	// The expiry eraser (engine API, no guard) removes both roots and never touches control.
	if report, err := f.app.Storage.EraseExpired(ctx, model.UnixNano(time.Now().Add(48*time.Hour).UnixNano()), nil); err != nil || report.Blobs != 2 {
		t.Fatalf("erase: %+v %v", report, err)
	}
	if err := f.app.Control.ValidateArtifactReferences(ctx); lookupCode(err) != model.Corrupt {
		t.Fatalf("published intents over missing blobs validated: %v", err)
	}
	f.setIntent(t, a, func(i *model.ArtifactReferenceIntent) { i.State = "retired" })
	if err := f.app.Control.ValidateArtifactReferences(ctx); lookupCode(err) != model.Corrupt {
		t.Fatalf("retiring one intent excused the other published intent over a missing blob: %v", err)
	}
	f.setIntent(t, b, func(i *model.ArtifactReferenceIntent) { i.State = "retired" })
	if err := f.app.Control.ValidateArtifactReferences(ctx); err != nil {
		t.Fatalf("retired intents over erased blobs must validate: %v", err)
	}
	if _, err := f.app.Control.LookupArtifact(ctx, f.scope(t, auth.ArtifactRead), a.ID); lookupCode(err) != model.NotFound {
		t.Fatalf("a retired intent is readable through the lookup: %v", err)
	}
	// A published intent with its bytes present validates beside the retired ones.
	f.put(t, "validate-c")
	if err := f.app.Control.ValidateArtifactReferences(ctx); err != nil {
		t.Fatalf("published intent with bytes beside retired ones: %v", err)
	}
	// Retired is not a free pass: structure is still validated, and so is the state name.
	f.setIntent(t, a, func(i *model.ArtifactReferenceIntent) { i.ControlRevision = 0 })
	if err := f.app.Control.ValidateArtifactReferences(ctx); lookupCode(err) != model.Corrupt {
		t.Fatalf("a malformed retired intent validated: %v", err)
	}
	f.setIntent(t, a, func(i *model.ArtifactReferenceIntent) { i.ControlRevision = 1; i.State = "bogus" })
	if err := f.app.Control.ValidateArtifactReferences(ctx); lookupCode(err) != model.Corrupt {
		t.Fatalf("an unknown intent state validated: %v", err)
	}
}
