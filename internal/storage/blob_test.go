// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"errors"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"testing"
	"time"
)

func blobFixture(t *testing.T) (*control.Store, *auth.Service, auth.Scope, model.BlobManifest, []byte) {
	t.Helper()
	c, a, _, d := fixture(t)
	ctx := context.Background()
	session, err := a.Login(ctx, "owner@example.test", "a long test password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := a.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	var build model.ID
	err = c.Update(ctx, func(st *model.ControlState) error {
		o := st.Orgs[d.Org.String()]
		o.Members[session.User.String()] = true
		o.Grants[session.User.String()+":"+d.Project.String()] = []string{"artifacts.write", "artifacts.read"}
		st.Orgs[d.Org.String()] = o
		build = st.Sources[d.Source.String()].Policy.Resources.Builds[0]
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := a.Authorize(ctx, actor, d.Org, []model.ID{d.Project}, auth.ArtifactWrite)
	if err != nil {
		t.Fatal(err)
	}
	raw := bytes.Repeat([]byte("artifact-byte"), 30000)
	m := model.BlobManifest{Org: d.Org, Project: d.Project, Source: d.Source, Build: build, Root: model.NewID(), Hash: model.HashCanonical(raw), Size: model.Uint64(len(raw)), PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyRevision: 1, RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
	r, err := c.ReserveArtifact(ctx, scope, m)
	if err != nil {
		t.Fatal(err)
	}
	m = r.Manifest
	return c, a, scope, m, raw
}
func TestArtifactFragmentDurabilityAndWholePublication(t *testing.T) {
	c, a, scope, m, raw := blobFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	engine, err := openTestEngine(t, dir, a, c)
	if err != nil {
		t.Fatal(err)
	}
	commits := 0
	engine.fault = func(at string) error {
		if at == "blob_fragment_committed" {
			commits++
			if commits == 1 {
				return errors.New("crash before whole blob")
			}
		}
		return nil
	}
	if receipt, err := engine.WriteBlob(ctx, scope, m, bytes.NewReader(raw)); err == nil || receipt.Cursor.Index != 0 {
		t.Fatal("partial blob ACK")
	}
	if err = engine.Close(); err != nil {
		t.Fatal(err)
	}
	engine, err = openTestEngine(t, dir, a, c)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	receipt, err := engine.WriteBlob(ctx, scope, m, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(receipt.Fragments) != 2 || receipt.Fragments[0].Size != 256<<10 {
		t.Fatalf("fragment bounds: %#v", receipt.Fragments)
	}
	if receipt.Fragments[0].Cursor.Group != receipt.Fragments[1].Cursor.Group || receipt.Fragments[0].Cursor.Index >= receipt.Fragments[1].Cursor.Index {
		t.Fatal("split owner order")
	}
	if err = engine.VerifyBlob(ctx, receipt); err != nil {
		t.Fatal(err)
	}
	c.View(ctx, func(st model.ControlState) error {
		if len(st.ArtifactIntents) != 0 {
			t.Fatal("orphan readable as published")
		}
		return nil
	})
	again, err := engine.WriteBlob(ctx, scope, m, bytes.NewReader(raw))
	if err != nil || !bytes.Equal(mustJSON(t, again), mustJSON(t, receipt)) {
		t.Fatal("retry receipt changed", err)
	}
	if err = engine.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("artifact_fragments")).Delete(blobFragmentKey(m, 0)) }); err != nil {
		t.Fatal(err)
	}
	if err = engine.VerifyBlob(ctx, receipt); err == nil {
		t.Fatal("missing referenced bytes accepted")
	}
}
func TestArtifactBlobHashFailureHasNoDurableBytes(t *testing.T) {
	c, a, scope, m, raw := blobFixture(t)
	engine, err := openTestEngine(t, t.TempDir(), a, c)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	raw[0] ^= 1
	if _, err = engine.WriteBlob(context.Background(), scope, m, bytes.NewReader(raw)); err == nil {
		t.Fatal("mismatched blob ACK")
	}
	engine.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("artifact_fragments")).Stats().KeyN != 0 {
			t.Fatal("unverified bytes admitted")
		}
		return nil
	})
}
func TestArtifactBlobAuthorityLossFailsClosed(t *testing.T) {
	c, a, scope, m, raw := blobFixture(t)
	dir := t.TempDir()
	engine, err := openTestEngine(t, dir, a, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.WriteBlob(context.Background(), scope, m, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if err = engine.db.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket([]byte("artifact_fragments")) }); err != nil {
		t.Fatal(err)
	}
	engine.Close()
	if recovered, err := openTestEngine(t, dir, a, c); err == nil {
		recovered.Close()
		t.Fatal("lost blob authority silently recreated")
	}
	if _, err = os.Stat(filepath.Join(dir, "apply.db")); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactOrphanGCRequiresTerminalProofAndIsIdempotent(t *testing.T) {
	c, a, scope, m, raw := blobFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	engine, err := openTestEngine(t, dir, a, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.WriteBlob(ctx, scope, m, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	forged := model.ArtifactGC{Manifest: m, CommandID: model.NewID(), ControlRevision: 1}
	if _, err = engine.GCUnreferencedBlob(ctx, scope, forged); err == nil {
		t.Fatal("forged no-reference proof accepted")
	}
	var before model.Uint64
	c.View(ctx, func(st model.ControlState) error { before = st.Quotas["org:"+m.Org.String()].Bytes; return nil })
	proof, err := c.CancelArtifact(ctx, scope, m.ReservationID, model.NewID())
	if err != nil {
		t.Fatal(err)
	}
	first, err := engine.GCUnreferencedBlob(ctx, scope, proof)
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.GCUnreferencedBlob(ctx, scope, proof)
	if err != nil || !bytes.Equal(mustJSON(t, first), mustJSON(t, second)) {
		t.Fatal("GC not idempotent", err)
	}
	if _, err = engine.WriteBlob(ctx, scope, m, bytes.NewReader(raw)); err == nil {
		t.Fatal("cancelled blob resurrected")
	}
	engine.Close()
	engine, err = openTestEngine(t, dir, a, c)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	third, err := engine.GCUnreferencedBlob(ctx, scope, proof)
	if err != nil || !bytes.Equal(mustJSON(t, third), mustJSON(t, first)) {
		t.Fatal("GC fence lost on restart", err)
	}
	c.View(ctx, func(st model.ControlState) error {
		if st.Quotas["org:"+m.Org.String()].Bytes != before {
			t.Fatal("unproven refund")
		}
		return nil
	})
}
