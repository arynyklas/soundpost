// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
	"time"
)

// orphan uploads durable bytes through the real reserve+write path and stops
// before publication, exactly like a killed upload.
func (f *artifactFixture) orphan(t *testing.T) model.ArtifactQuotaReservation {
	t.Helper()
	ctx := context.Background()
	raw := []byte(`{"version":3,"sources":[],"names":[],"mappings":""}`)
	scope := f.scope(t, auth.ArtifactWrite)
	var rev model.Revision
	f.app.Control.View(ctx, func(st model.ControlState) error { rev = st.Sources[f.source.String()].Policy.Revision; return nil })
	m := model.BlobManifest{Org: f.org, Project: f.project, Source: f.source, Root: model.NewID(), Build: f.build, DebugID: "debug-1", Path: "dist/app.js", GeneratedSHA256: model.HashCanonical([]byte("generated")), MapSHA256: model.HashCanonical(raw), Hash: model.HashCanonical(raw), Size: model.Uint64(len(raw)), PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyRevision: rev, RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
	r, err := f.app.Control.ReserveArtifact(ctx, scope, m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.app.Storage.WriteBlob(ctx, scope, r.Manifest, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *artifactFixture) orgBytes(t *testing.T) model.Uint64 {
	t.Helper()
	var n model.Uint64
	f.app.Control.View(context.Background(), func(st model.ControlState) error { n = st.Quotas["org:"+f.org.String()].Bytes; return nil })
	return n
}

func (f *artifactFixture) bumpSourcePolicy(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	actor, err := f.app.Auth.Authenticate(ctx, f.token)
	if err != nil {
		t.Fatal(err)
	}
	var next model.SourcePolicy
	f.app.Control.View(ctx, func(st model.ControlState) error { next = st.Sources[f.source.String()].Policy; return nil })
	cur := next.Revision
	next.Revision++
	if _, err = f.app.Auth.ChangeSourcePolicy(ctx, actor, auth.SourcePolicyChange{CommandID: model.NewID(), Source: f.source, ExpectedRevision: cur, Policy: next, Reason: "policy bump after interrupted upload"}); err != nil {
		t.Fatal(err)
	}
	if err = f.app.Auth.DrainSourceFences(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactOrphanCleanupSurvivesSourcePolicyEpochBump(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	r := f.orphan(t)
	charged := f.orgBytes(t)
	if charged == 0 {
		t.Fatal("orphan bytes not charged")
	}
	f.bumpSourcePolicy(t)
	scope := f.scope(t, auth.ArtifactWrite)
	cmd := model.NewID()
	proof, err := f.app.Control.CancelArtifact(ctx, scope, r.Manifest.ReservationID, cmd)
	if err != nil {
		t.Fatal("cancel after policy/epoch bump wedged:", err)
	}
	again, err := f.app.Control.CancelArtifact(ctx, scope, r.Manifest.ReservationID, model.NewID())
	if err != nil || again.CommandID != proof.CommandID || again.ControlRevision != proof.ControlRevision {
		t.Fatal("cancel not idempotent", err)
	}
	if _, err = f.app.Storage.GCUnreferencedBlob(ctx, scope, proof); err != nil {
		t.Fatal("GC after policy/epoch bump wedged:", err)
	}
	if _, err = f.app.Storage.GCUnreferencedBlob(ctx, scope, proof); err != nil {
		t.Fatal("GC not idempotent:", err)
	}
	if got := f.orgBytes(t); got != charged {
		t.Fatalf("cleanup refunded quota: %d -> %d", charged, got)
	}
	// Cleanup authority is still the caller's current artifacts.write scope.
	if _, err = f.app.Storage.GCUnreferencedBlob(ctx, f.scope(t, auth.ArtifactRead), proof); err == nil {
		t.Fatal("read scope performed GC")
	}
	if _, err = f.app.Control.CancelArtifact(ctx, f.scope(t, auth.ArtifactRead), r.Manifest.ReservationID, model.NewID()); err == nil {
		t.Fatal("read scope performed cancel")
	}
}

func TestArtifactOrphanCleanupDeniedToOtherOrganization(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	r := f.orphan(t)
	actor, err := f.app.Auth.Authenticate(ctx, f.token)
	if err != nil {
		t.Fatal(err)
	}
	org2, project2 := model.NewID(), model.NewID()
	var user string
	f.app.Control.View(ctx, func(st model.ControlState) error {
		for id := range st.Orgs[f.org.String()].Members {
			user = id
		}
		return nil
	})
	for _, cmd := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: "other"}}, {"create_project", auth.AdminPayload{ID: project2, Name: "other builds"}}} {
		cmd.p.Reason = "second org"
		raw, _ := json.Marshal(cmd.p)
		var rev model.Revision
		f.app.Control.View(ctx, func(st model.ControlState) error { rev = st.Revision; return nil })
		if _, err = f.app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org2, Kind: cmd.kind, Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	if err = f.app.Control.Update(ctx, func(st *model.ControlState) error {
		o := st.Orgs[org2.String()]
		o.Members[user] = true
		o.Grants[user+":"+project2.String()] = []string{"artifacts.write"}
		st.Orgs[org2.String()] = o
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	other, err := f.app.Auth.Authorize(ctx, actor, org2, []model.ID{project2}, auth.ArtifactWrite)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.app.Control.CancelArtifact(ctx, other, r.Manifest.ReservationID, model.NewID()); err == nil {
		t.Fatal("other organization cancelled orphan")
	}
	proof, err := f.app.Control.CancelArtifact(ctx, f.scope(t, auth.ArtifactWrite), r.Manifest.ReservationID, model.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.app.Storage.GCUnreferencedBlob(ctx, other, proof); err == nil {
		t.Fatal("other organization garbage-collected orphan")
	}
}

func TestArtifactPublishedReferenceCannotBeCancelledAfterPolicyBump(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`)
	got, err := f.app.Artifacts.Put(ctx, f.scope(t, auth.ArtifactWrite), f.manifest(raw), bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	id := got.Map.Manifest.ReservationID
	if _, err = f.app.Control.CancelArtifact(ctx, f.scope(t, auth.ArtifactWrite), id, model.NewID()); err == nil {
		t.Fatal("published artifact cancelled")
	}
	f.bumpSourcePolicy(t)
	if _, err = f.app.Control.CancelArtifact(ctx, f.scope(t, auth.ArtifactWrite), id, model.NewID()); err == nil {
		t.Fatal("published artifact cancelled after policy bump")
	}
}
