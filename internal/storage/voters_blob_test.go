// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// blobOnVoters is a three-voter installation holding one published multi-fragment artifact and one
// orphan (fragments committed, never published).
type blobOnVoters struct {
	v        *voters
	scope    auth.Scope
	store    *control.Store
	raw      []byte
	manifest model.BlobManifest
	receipt  model.BlobReceipt
	orphan   model.BlobManifest
}

// orphanManifest reserves a second artifact of the same bytes under a new root.
func orphanManifest(t *testing.T, c *control.Store, scope auth.Scope, m model.BlobManifest) model.BlobManifest {
	t.Helper()
	m.Root, m.ReservationID = model.NewID(), model.ID{}
	r, err := c.ReserveArtifact(context.Background(), scope, m)
	if err != nil {
		t.Fatal(err)
	}
	return r.Manifest
}

// writeBlob writes m through voter 1 as a client would. The in-process mesh has no proposal
// forwarder, so a write is leader-bound: before each attempt voter 1 is confirmed as the leader of
// the artifact's owner slot, and an attempt that still lost the leadership (typed unavailable or
// stale, nothing acknowledged) is repeated; WriteBlob resumes after the fragments already
// committed. Any other error, including an injected fault, is returned as it is.
func (x *blobOnVoters) writeBlob(ctx context.Context, t *testing.T, m model.BlobManifest) (model.BlobReceipt, error) {
	t.Helper()
	slot := int(model.BlobOwnerSlot(m.Org, m.Project, m.Root))
	var last error
	for ctx.Err() == nil {
		x.v.leadSlot(t, slot, 1, time.Now().Add(30*time.Second))
		receipt, err := x.v.engines[1].WriteBlob(ctx, x.scope, m, bytes.NewReader(x.raw))
		var fault *model.Fault
		if err == nil || !errors.As(err, &fault) || fault.Code != model.Unavailable && fault.Code != model.Stale {
			return receipt, err
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	return model.BlobReceipt{}, last
}

// newBlobOnVoters publishes the artifact through voter 1 while voter 3 is partitioned (when cut) and
// leaves an orphan behind: the writer of the orphan fails after its first fragment committed.
func newBlobOnVoters(t *testing.T, cutVoter3 bool) *blobOnVoters {
	t.Helper()
	c, a, scope, m, raw := blobFixture(t)
	x := &blobOnVoters{store: c, scope: scope, raw: raw, manifest: m}
	x.v = openVoters(t, a, c)
	x.v.lead(t, func(int) uint64 { return 1 })
	if cutVoter3 {
		x.v.mesh.partition(3, true)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var err error
	if x.receipt, err = x.writeBlob(ctx, t, m); err != nil {
		t.Fatal(err)
	}
	if len(x.receipt.Fragments) < 2 {
		t.Fatalf("fixture invalid: %d fragments, the artifact must span several", len(x.receipt.Fragments))
	}
	x.orphan = orphanManifest(t, c, scope, m)
	x.v.lead(t, func(int) uint64 { return 1 })
	commits := 0
	x.v.engines[1].setFault(func(at string) error {
		if at == "blob_fragment_committed" {
			if commits++; commits == 1 {
				return errors.New("crash before the whole blob")
			}
		}
		return nil
	})
	if _, err = x.writeBlob(ctx, t, x.orphan); err == nil {
		t.Fatal("fixture invalid: the orphan writer was not interrupted")
	}
	x.v.engines[1].setFault(nil)
	if commits != 1 {
		t.Fatalf("fixture invalid: the orphan writer committed %d fragments before it was interrupted, want exactly 1", commits)
	}
	return x
}

// holds reports whether voter node holds the bytes of fragment ordinal of m in its fragment table.
func (x *blobOnVoters) holds(node uint64, m model.BlobManifest, ordinal uint32) []byte {
	e := x.v.engines[node]
	var out []byte
	_ = e.db.View(func(tx *bolt.Tx) error {
		out = bytes.Clone(tx.Bucket([]byte("artifact_fragments")).Get(blobFragmentKey(m, ordinal)))
		return nil
	})
	return out
}

// requireEveryFragment asserts voter node serves the published artifact fragment by fragment (exact
// bytes, through the scope-checked read) and can verify it, and that the orphan stays unreadable
// whatever the fragment table holds.
func (x *blobOnVoters) requireEveryFragment(t *testing.T, node uint64) {
	t.Helper()
	ctx := context.Background()
	e := x.v.engines[node]
	var got []byte
	for i := range x.receipt.Fragments {
		raw := x.holds(node, x.manifest, uint32(i))
		if len(raw) == 0 {
			t.Fatalf("voter %d lacks fragment %d of the published artifact", node, i)
		}
		got = append(got, raw...)
	}
	if !bytes.Equal(got, x.raw) {
		t.Fatalf("voter %d's fragments do not add up to the artifact", node)
	}
	if err := e.VerifyBlob(ctx, x.receipt); err != nil {
		t.Fatalf("voter %d cannot verify the artifact: %v", node, err)
	}
	// The root receipt is what makes bytes readable (ReadBlobFragment and VerifyBlob release a
	// fragment only through it): the published artifact has it, byte for byte the leader's, and
	// the orphan, whose fragment the log carried, has none.
	root := x.root(node, x.manifest)
	want, err := model.CanonicalJSON(x.receipt)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := model.CanonicalJSON(root); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("voter %d's root receipt differs from the published one: %v", node, err)
	}
	if orphan := x.root(node, x.orphan); len(orphan.Fragments) >= len(x.receipt.Fragments) {
		t.Fatalf("voter %d holds a complete receipt for the orphan: %d fragments", node, len(orphan.Fragments))
	} else if err := e.VerifyBlob(ctx, orphan); err == nil {
		t.Fatalf("voter %d verifies an unpublished artifact", node)
	}
}

// root is the receipt voter node stores for the root of m (the zero receipt when none).
func (x *blobOnVoters) root(node uint64, m model.BlobManifest) model.BlobReceipt {
	var out model.BlobReceipt
	_ = x.v.engines[node].db.View(func(tx *bolt.Tx) error {
		_ = model.StrictJSON(tx.Bucket([]byte("artifact_roots")).Get([]byte(model.BlobKey(m))), &out)
		return nil
	})
	return out
}

// Every referenced artifact fragment reaches every voter of a three-voter installation through the
// log, and an orphan is carried but never readable.
func TestThreeVotersCarryEveryReferencedArtifactFragment(t *testing.T) {
	x := newBlobOnVoters(t, false)
	x.v.converge(t, nil)
	for node := uint64(1); node <= 3; node++ {
		x.requireEveryFragment(t, node)
		if len(x.holds(node, x.orphan, 0)) == 0 {
			t.Fatalf("voter %d lacks the orphan's committed fragment (the log carries it)", node)
		}
	}
}

// A voter that was cut off while the artifact was published, whose peers then cut their journals,
// is repaired by a snapshot install: the install must carry every referenced fragment (and the
// orphan stays unreadable).
func TestSnapshotInstallCarriesEveryReferencedArtifactFragment(t *testing.T) {
	x := newBlobOnVoters(t, true)
	for node := uint64(1); node <= 2; node++ {
		if err := x.v.maintain(node); err != nil {
			t.Fatalf("maintain %d: %v", node, err)
		}
	}
	for i := range x.receipt.Fragments {
		if len(x.holds(3, x.manifest, uint32(i))) != 0 {
			t.Fatalf("fixture invalid: the cut-off voter holds fragment %d", i)
		}
	}
	before := func() int { x.v.mesh.mu.Lock(); defer x.v.mesh.mu.Unlock(); return x.v.mesh.snaps[3] }()
	x.v.mesh.partition(3, false)
	deadline := time.Now().Add(60 * time.Second)
	for len(x.holds(3, x.manifest, uint32(len(x.receipt.Fragments)-1))) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("voter 3 never received the artifact after the partition healed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	x.v.converge(t, nil)
	x.v.mesh.mu.Lock()
	installed := x.v.mesh.snaps[3] - before
	x.v.mesh.mu.Unlock()
	if installed == 0 {
		t.Fatal("fixture invalid: voter 3 caught up by log append, not by a snapshot install")
	}
	x.requireEveryFragment(t, 3)
}
