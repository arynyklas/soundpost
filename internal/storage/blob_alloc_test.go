// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// writeBlobAllocBound is the cumulative-allocation ceiling of one replicated WriteBlob, as a
// multiple of the input for an 8 MiB blob. Measured on Linux: HEAD e805349 61.3x (one run); 40.5x-40.8x
// before the single-allocation fragment encoder (encodeFragmentJSON); 33.4x after it (one run, lane 1
// wave 8), so 42x leaves 25% headroom over the measured value.
const writeBlobAllocBound = 42

// writeBlobEnvelopeAllocBound is the same ceiling with the binary fragment envelope on. Measured on
// Linux (lane 1 wave 9): 26.4x with the envelope against 32.9x for the JSON form in the same run;
// 33x leaves 25% headroom over the envelope figure.
const writeBlobEnvelopeAllocBound = 33

// noCutCadence is a cut cadence no write of these tests reaches. The default cadence of the data groups is
// staggered per slot (slotStagger: slot 0 cuts at half the 16 MiB bound), so a blob of 8 MiB can make the group
// of its slot cut a snapshot while the write is measured, and the cut's allocation (the window files it stages)
// lands in or out of the measurement with the scheduler: 33x to 45x for the same write. What is measured here
// is the allocation of WriteBlob.
var noCutCadence = replica.Cadence{Commands: 1 << 30, Bytes: 1 << 40}

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
	e := openDeleteEngineCadence(t, t.TempDir(), a, c, noCutCadence)
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

// The same write with fragments proposed in the binary envelope: the payload is no longer base64
// text inside base64 text, so the path allocates less (envelope.go).
func TestWriteBlobCumulativeAllocationWithEnvelope(t *testing.T) {
	const size = 8 << 20
	c, a, scope, m, raw := blobFixtureSized(t, size)
	e := openDeleteEngineCadence(t, t.TempDir(), a, c, noCutCadence)
	e.EnableFragmentEnvelope(true)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	r, err := e.WriteBlob(context.Background(), scope, m, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	wall := time.Since(start)
	runtime.ReadMemStats(&after)
	total := after.TotalAlloc - before.TotalAlloc
	ratio := float64(total) / float64(len(raw))
	t.Logf("WRITEBLOB-ENVELOPE-MEM input=%d total_alloc=%d (%.1fx) wall=%s", len(raw), total, ratio, wall)
	if e.envelopesProposed.Load() != uint64(len(r.Fragments)) {
		t.Fatalf("%d envelope proposals for %d fragments", e.envelopesProposed.Load(), len(r.Fragments))
	}
	if ratio > writeBlobEnvelopeAllocBound {
		t.Fatalf("WriteBlob with the envelope allocated %.1fx its input (bound %dx)", ratio, writeBlobEnvelopeAllocBound)
	}
}
