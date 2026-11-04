// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"soundpost/internal/appcore"
	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"testing"
	"time"
)

type artifactFixture struct {
	app                         *appcore.App
	dir, token                  string
	org, project, source, build model.ID
}

func newArtifactFixture(t *testing.T) *artifactFixture {
	t.Helper()
	f := &artifactFixture{dir: t.TempDir(), org: model.NewID(), project: model.NewID(), source: model.NewID(), build: model.NewID()}
	var err error
	f.app, err = appcore.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f.app != nil {
			f.app.Close()
		}
	})
	ctx := context.Background()
	bootstrap, err := f.app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := f.app.Auth.Bootstrap(ctx, bootstrap, "artifact@example.test", "artifact fixture password 2026")
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
	}{{"create_org", auth.AdminPayload{Name: "artifacts"}}, {"create_project", auth.AdminPayload{ID: f.project, Name: "builds"}}} {
		cmd.p.Reason = "artifact fixture"
		raw, encodeErr := json.Marshal(cmd.p)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		var rev model.Revision
		f.app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil })
		if _, err = f.app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: f.org, Kind: cmd.kind, Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.app.Control.Update(ctx, func(st *model.ControlState) error {
		o := st.Orgs[f.org.String()]
		o.Members[session.User.String()] = true
		o.Grants[session.User.String()+":"+f.project.String()] = []string{"artifacts.write", "artifacts.read", "raw.read"}
		cfg, encodeErr := json.Marshal(auth.SourcePolicyConfig{ProjectID: f.project, Enabled: true, Readers: []model.ID{session.User}})
		if encodeErr != nil {
			return encodeErr
		}
		o.Settings["source_policy:"+f.source.String()] = cfg
		st.Orgs[f.org.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err = f.app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{
		CommandID: model.NewID(), Org: f.org, Project: f.project, Source: f.source,
		Expires: model.UnixNano(time.Now().Add(24 * time.Hour).UnixNano()),
		Policy: model.SourcePolicy{
			Enabled: true, Revision: 1, Class: "structured", Kinds: []model.Kind{model.Metric},
			Resources: model.ResourceRegistry{
				Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()},
				Builds: []model.ID{f.build}, Instances: []string{"artifact-fixture"},
			},
			RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 30, MaxSeries: 1000,
		},
		Reason: "artifact fixture real source authority",
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *artifactFixture) scope(t *testing.T, action auth.Permission) auth.Scope {
	t.Helper()
	actor, e := f.app.Auth.Authenticate(context.Background(), f.token)
	if e != nil {
		t.Fatal(e)
	}
	s, e := f.app.Auth.Authorize(context.Background(), actor, f.org, []model.ID{f.project}, action)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func (f *artifactFixture) manifest(raw []byte) artifacts.Manifest {
	return artifacts.Manifest{Version: 1, Org: f.org, Project: f.project, Source: f.source, Build: f.build, DebugID: "debug-1", GeneratedSHA256: model.HashCanonical([]byte("generated")), MapSHA256: model.HashCanonical(raw), Path: "dist/app.js", Size: model.Uint64(len(raw)), RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
}
func TestArtifactExactIdentityAndPrivateGrant(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	raw := []byte(`{"version":3,"sources":["src/app.ts"],"names":[],"mappings":"AAAA","sourcesContent":["PRIVATE SOURCE"]}`)
	m := f.manifest(raw)
	got, e := f.app.Artifacts.Put(ctx, f.scope(t, auth.Permission("artifacts.write")), m, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	read := f.scope(t, auth.Permission("artifacts.read"))
	r, e := f.app.Artifacts.Get(ctx, read, got.ID)
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(r)
	r.Close()
	if e != nil || bytes.Contains(b, []byte("PRIVATE")) || bytes.Contains(b, []byte("sourcesContent")) {
		t.Fatalf("default source exclusion: %s %v", b, e)
	}
	bad := m
	bad.GeneratedSHA256 = model.HashCanonical([]byte("other"))
	if _, e = f.app.Artifacts.Put(ctx, f.scope(t, auth.Permission("artifacts.write")), bad, bytes.NewReader(raw)); e == nil {
		t.Fatal("debug/build generated identity rewritten")
	}
	bad = m
	bad.Build = model.NewID()
	if _, e = f.app.Artifacts.Put(ctx, f.scope(t, auth.Permission("artifacts.write")), bad, bytes.NewReader(raw)); e == nil {
		t.Fatal("unregistered build accepted")
	}
	bad = m
	bad.DebugID = "../debug"
	if _, e = f.app.Artifacts.Put(ctx, f.scope(t, auth.Permission("artifacts.write")), bad, bytes.NewReader(raw)); e == nil {
		t.Fatal("invalid debug identity accepted")
	}
	private := m
	private.DebugID = "debug-private"
	private.SourceContent = true
	published, e := f.app.Artifacts.Put(ctx, f.scope(t, auth.Permission("artifacts.write")), private, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	if published.Sources == nil || published.Map.Cursor.Group != published.Sources.Cursor.Group || published.Map.Cursor.Index >= published.Sources.Cursor.Index || published.ControlRevision == 0 || published.CommandID != published.ID {
		t.Fatal("private source escaped fixed root owner or reference publication")
	}
	sources, e := f.app.Artifacts.GetSources(ctx, read, published.ID)
	if e != nil {
		t.Fatal(e)
	}
	sourceBytes, e := io.ReadAll(sources)
	sources.Close()
	if e != nil || !bytes.Contains(sourceBytes, []byte("PRIVATE SOURCE")) {
		t.Fatal("granted private source unavailable", e)
	}
	if e = f.app.Control.Update(ctx, func(st *model.ControlState) error {
		o := st.Orgs[f.org.String()]
		o.Epoch++
		cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: f.project, Enabled: true})
		o.Settings["source_policy:"+f.source.String()] = cfg
		st.Orgs[f.org.String()] = o
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.app.Artifacts.GetSources(ctx, f.scope(t, auth.Permission("artifacts.read")), published.ID); e == nil {
		t.Fatal("private source without named reader grant")
	}
	if _, e = r.Read(make([]byte, 1)); e == nil {
		t.Fatal("closed stream read")
	}
}
func TestArtifactFailedInputNeverPublishes(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	raw := []byte(`{"version":3,"sources":[],"names":[],"mappings":""}`)
	m := f.manifest(raw)
	m.MapSHA256 = model.HashCanonical([]byte("wrong"))
	if _, e := f.app.Artifacts.Put(ctx, f.scope(t, auth.Permission("artifacts.write")), m, bytes.NewReader(raw)); e == nil {
		t.Fatal("hash mismatch ACK")
	}
	m = f.manifest(raw)
	m.Size--
	if _, e := f.app.Artifacts.Put(ctx, f.scope(t, auth.Permission("artifacts.write")), m, bytes.NewReader(raw)); e == nil {
		t.Fatal("oversize stream ACK")
	}
	f.app.Control.View(ctx, func(st model.ControlState) error {
		if len(st.ArtifactIntents) != 0 {
			t.Fatal("failed input published intent")
		}
		return nil
	})
}

func TestArtifactSameHashCannotCrossWarmedOrganization(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	raw := []byte(`{"version":3,"sources":[],"names":[],"mappings":""}`)
	m := f.manifest(raw)
	first, e := f.app.Artifacts.Put(ctx, f.scope(t, auth.ArtifactWrite), m, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	a := f.scope(t, auth.ArtifactRead)
	stream, e := f.app.Artifacts.Get(ctx, a, first.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = io.ReadAll(stream); e != nil {
		t.Fatal(e)
	}
	stream.Close()
	orgB, projectB, sourceB := model.NewID(), model.NewID(), model.NewID()
	principal := a.PrincipalID()
	if e = f.app.Control.Update(ctx, func(st *model.ControlState) error {
		cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: projectB, Enabled: true})
		st.Orgs[orgB.String()] = model.ControlOrg{ID: orgB, Epoch: 1, Members: map[string]bool{principal.String(): true}, Projects: map[string]string{projectB.String(): "second"}, Grants: map[string][]string{principal.String() + ":" + projectB.String(): {"artifacts.write", "artifacts.read"}}, Settings: map[string]json.RawMessage{"source_policy:" + sourceB.String(): cfg}}
		source := st.Sources[f.source.String()]
		source.ID = sourceB
		source.Org = orgB
		source.Project = projectB
		st.Sources[sourceB.String()] = source
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	actor, e := f.app.Auth.Authenticate(ctx, f.token)
	if e != nil {
		t.Fatal(e)
	}
	b, e := f.app.Auth.Authorize(ctx, actor, orgB, []model.ID{projectB}, auth.ArtifactRead)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.app.Artifacts.Get(ctx, b, first.ID); e == nil {
		t.Fatal("warmed same-hash cross-org read")
	}
	writeB, e := f.app.Auth.Authorize(ctx, actor, orgB, []model.ID{projectB}, auth.ArtifactWrite)
	if e != nil {
		t.Fatal(e)
	}
	m.Org = orgB
	m.Project = projectB
	m.Source = sourceB
	second, e := f.app.Artifacts.Put(ctx, writeB, m, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	if first.ID == second.ID || first.Map.Hash != second.Map.Hash {
		t.Fatal("scoped identity/content mismatch")
	}
	if _, e = f.app.Artifacts.Get(ctx, a, second.ID); e == nil {
		t.Fatal("reverse cross-org read")
	}
}
func TestArtifactBufferedStreamRevocationAndReferenceRestart(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`)
	m := f.manifest(raw)
	got, e := f.app.Artifacts.Put(ctx, f.scope(t, auth.ArtifactWrite), m, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	r, e := f.app.Artifacts.Get(ctx, f.scope(t, auth.ArtifactRead), got.ID)
	if e != nil {
		t.Fatal(e)
	}
	if n, e := r.Read(make([]byte, 1)); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	if e = f.app.Control.Update(ctx, func(st *model.ControlState) error {
		delete(st.ArtifactIntents, m.Org.String()+":"+m.Project.String()+":"+got.ID.String())
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	buffer := bytes.Repeat([]byte{0x7f}, 8)
	if n, e := r.Read(buffer); e == nil || n != 0 || !bytes.Equal(buffer, bytes.Repeat([]byte{0x7f}, 8)) {
		t.Fatal("deleted reference released buffered bytes", n, e)
	}
	r.Close()
	// An orphan's exact durable fragment receipt can be retried after reopening;
	// the public reference exists only after the real control publication.
	if e = f.app.Close(); e != nil {
		t.Fatal(e)
	}
	f.app = nil
	f.app, e = appcore.Open(f.dir)
	if e != nil {
		t.Fatal(e)
	}
	again, e := f.app.Artifacts.Put(ctx, f.scope(t, auth.ArtifactWrite), m, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	a, _ := model.CanonicalJSON(got.Map)
	b, _ := model.CanonicalJSON(again.Map)
	if !bytes.Equal(a, b) {
		t.Fatal("durable bytes/cursors changed on reference retry")
	}
}

func TestArtifactReferenceAuthorityLossBlocksReadAndReadiness(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	raw := []byte(`{"version":3,"sources":[],"names":[],"mappings":""}`)
	m := f.manifest(raw)
	got, e := f.app.Artifacts.Put(ctx, f.scope(t, auth.ArtifactWrite), m, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	if e = f.app.Control.Update(ctx, func(st *model.ControlState) error {
		delete(st.ArtifactReservations, got.Map.Manifest.ReservationID.String())
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = f.app.Artifacts.Get(ctx, f.scope(t, auth.ArtifactRead), got.ID); e == nil {
		t.Fatal("lost reference authority still readable")
	}
	if e = f.app.Close(); e != nil {
		t.Fatal(e)
	}
	f.app = nil
	if recovered, e := appcore.Open(f.dir); e == nil {
		recovered.Close()
		t.Fatal("reference authority silently reconstructed on reopen")
	}
}
func TestArtifactRetentionIsNotCredentialExpiry(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	raw := []byte(`{"version":3,"sources":[],"names":[],"mappings":""}`)
	m := f.manifest(raw)
	if e := f.app.Control.Update(ctx, func(st *model.ControlState) error {
		source := st.Sources[f.source.String()]
		source.Expires = model.UnixNano(time.Now().Add(time.Minute).UnixNano())
		st.Sources[f.source.String()] = source
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	got, e := f.app.Artifacts.Put(ctx, f.scope(t, auth.ArtifactWrite), m, bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	if got.Map.Manifest.RetainUntil != m.RetainUntil {
		t.Fatal("credential expiry shortened acknowledged retention")
	}
}

// An incomplete hand-built SourceAuthority would fail this fixture before the
// artifact behavior tests reach their subject; a credential ID must come from
// the real source onboarding transaction, never a dummy zero/nonzero ID.
func TestArtifactFixtureUsesCommittedSourceCredentialAuthority(t *testing.T) {
	f := newArtifactFixture(t)
	if err := f.app.Control.View(context.Background(), func(st model.ControlState) error {
		source, ok := st.Sources[f.source.String()]
		if !ok || source.CredentialID == (model.ID{}) || source.Org != f.org || source.Project != f.project {
			t.Fatal("fixture has no committed exact source authority")
		}
		found := false
		for _, id := range st.SourceCredentials {
			if id == f.source.String() {
				found = true
			}
		}
		if !found {
			t.Fatal("fixture source lacks actual credential binding")
		}
		if _, err := json.Marshal(source); err != nil {
			t.Fatal(err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactWireRequiresCanonicalDecimalStrings(t *testing.T) {
	for _, value := range []string{`null`, `17`, `"017"`, `"+17"`, `" 17"`, `"1e1"`, `"18446744073709551616"`} {
		t.Run(value, func(t *testing.T) {
			var manifest model.ArtifactManifest
			if err := model.StrictJSON([]byte(`{"size":`+value+`}`), &manifest); err == nil {
				t.Fatal("artifact size accepted a noncanonical decimal")
			}
			var blob model.BlobManifest
			if err := model.StrictJSON([]byte(`{"policy_epoch":`+value+`}`), &blob); err == nil {
				t.Fatal("blob policy epoch accepted a noncanonical decimal")
			}
		})
	}
	var manifest model.ArtifactManifest
	if err := model.StrictJSON([]byte(`{"size":"18446744073709551615"}`), &manifest); err != nil || uint64(manifest.Size) != ^uint64(0) {
		t.Fatal("canonical maximum artifact size scalar did not round-trip", err)
	}
}

func TestArtifactBlobManifestHashKeepsPrimitiveNumericBinding(t *testing.T) {
	id, err := model.ParseID("11111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	m := model.BlobManifest{Org: id, Project: id, Source: id, Root: id, Build: id, DebugID: "debug", Path: "dist/app.js", Size: 17, PolicyEpoch: 7, PolicyRevision: 1, RetainUntil: 9}
	// This hand-written pre-cutover canonical projection intentionally has
	// numeric Size/PolicyEpoch, unlike their externally quoted wire DTOs.
	legacy := []byte(`{"Build":"11111111111111111111111111111111","DebugID":"debug","GeneratedSHA256":"0000000000000000000000000000000000000000000000000000000000000000","Hash":"0000000000000000000000000000000000000000000000000000000000000000","MapSHA256":"0000000000000000000000000000000000000000000000000000000000000000","Org":"11111111111111111111111111111111","Path":"dist/app.js","PolicyEpoch":7,"PolicyRevision":"1","PrivateSources":false,"Project":"11111111111111111111111111111111","RetainUntil":"9","Root":"11111111111111111111111111111111","Size":17,"Source":"11111111111111111111111111111111"}`)
	if model.BlobManifestHash(m) != model.HashCanonical(legacy) {
		t.Fatal("wire scalar cutover changed the durable manifest binding bytes")
	}
}
