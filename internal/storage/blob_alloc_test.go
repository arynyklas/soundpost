// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"runtime"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
)

// writeBlobAllocBound is the cumulative-allocation ceiling of one replicated WriteBlob, as a
// multiple of the input for an 8 MiB blob. Measured on Linux: HEAD e805349 61.3x (one run); after
// the change 40.5x-40.8x over repeated runs, so 52x leaves 25% headroom over the stable value and
// is below the HEAD figure.
const writeBlobAllocBound = 52

// blobFixtureSized is blobFixture with an input of size bytes.
func blobFixtureSized(t *testing.T, size int) (*control.Store, *auth.Service, auth.Scope, model.BlobManifest, []byte) {
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
	unit := []byte("function f(a, b) {\n\treturn a < b && \"x\" > '<y>' ? a : b; // \u00e9\u4e16\n}\n")
	raw := bytes.Repeat(unit, size/len(unit)+1)[:size]
	m := model.BlobManifest{Org: d.Org, Project: d.Project, Source: d.Source, Build: build, Root: model.NewID(), Hash: model.HashCanonical(raw), Size: model.Uint64(len(raw)), PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyRevision: 1, RetainUntil: model.UnixNano(time.Now().Add(time.Hour).UnixNano())}
	r, err := c.ReserveArtifact(ctx, scope, m)
	if err != nil {
		t.Fatal(err)
	}
	return c, a, scope, r.Manifest, raw
}

// TestWriteBlobCumulativeAllocationIsBounded writes a multi-fragment blob through the replicated
// path (propose, ready WAL, apply) and bounds what that path allocates in total.
func TestWriteBlobCumulativeAllocationIsBounded(t *testing.T) {
	const size = 8 << 20
	c, a, scope, m, raw := blobFixtureSized(t, size)
	e := openDeleteEngine(t, t.TempDir(), a, c)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	if _, err := e.WriteBlob(context.Background(), scope, m, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	wall := time.Since(start)
	runtime.ReadMemStats(&after)
	total := after.TotalAlloc - before.TotalAlloc
	ratio := float64(total) / float64(len(raw))
	t.Logf("WRITEBLOB-MEM input=%d total_alloc=%d (%.1fx) wall=%s", len(raw), total, ratio, wall)
	if ratio > writeBlobAllocBound {
		t.Fatalf("WriteBlob allocated %.1fx its input (bound %dx)", ratio, writeBlobAllocBound)
	}
}
