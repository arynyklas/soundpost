// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"io"
	"os"
	"path/filepath"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"strconv"
)

var blobBuckets = []string{"artifact_roots", "artifact_fragments", "artifact_gc"}

func blobFragmentKey(m model.BlobManifest, n uint32) []byte {
	return []byte(fmt.Sprintf("%s:%04d", model.BlobKey(m), n))
}
func (e *Engine) initBlobs() error {
	var initialized bool
	if err := e.db.View(func(tx *bolt.Tx) error {
		marker := tx.Bucket([]byte("meta")).Get([]byte("artifacts_v1"))
		initialized = bytes.Equal(marker, []byte{1})
		if marker != nil && !initialized {
			return model.Fail(model.Corrupt)
		}
		if !initialized && tx.Bucket([]byte("meta")).Get([]byte("replica_format")) != nil {
			return model.Fail(model.Corrupt)
		}
		for _, name := range blobBuckets {
			if initialized && tx.Bucket([]byte(name)) == nil || !initialized && tx.Bucket([]byte(name)) != nil {
				return model.Fail(model.Corrupt)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if !initialized {
		// The only migration is from a store that has never admitted a private blob.
		// Losing both marker and buckets must not turn old WAL into a repair source.
		for slot := range uint16(64) {
			f, err := os.Open(filepath.Join(e.dir, walName(slot)))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			err = func() error {
				defer f.Close()
				for {
					var h [walHeader]byte
					if _, err := io.ReadFull(f, h[:]); err == io.EOF || err == io.ErrUnexpectedEOF {
						return nil
					} else if err != nil {
						return err
					}
					n := binary.BigEndian.Uint32(h[8:12])
					if n == 0 || n > 8<<20 {
						return model.Fail(model.Corrupt)
					}
					raw := make([]byte, n)
					if _, err := io.ReadFull(f, raw); err == io.EOF || err == io.ErrUnexpectedEOF {
						return nil
					} else if err != nil {
						return err
					}
					var entry struct {
						Type string `json:"type"`
					}
					if json.Unmarshal(raw, &entry) != nil {
						return model.Fail(model.Corrupt)
					}
					if entry.Type == "artifact_fragment" || entry.Type == "artifact_gc" {
						return model.Fail(model.Corrupt)
					}
				}
			}()
			if err != nil {
				return err
			}
		}
		return e.db.Update(func(tx *bolt.Tx) error {
			for _, name := range blobBuckets {
				if _, err := tx.CreateBucket([]byte(name)); err != nil {
					return err
				}
			}
			if err := tx.Bucket([]byte("meta")).Put([]byte("artifact_counts"), make([]byte, 24)); err != nil {
				return err
			}
			return tx.Bucket([]byte("meta")).Put([]byte("artifacts_v1"), []byte{1})
		})
	}
	return e.db.View(func(tx *bolt.Tx) error {
		counts := tx.Bucket([]byte("meta")).Get([]byte("artifact_counts"))
		if len(counts) != 24 {
			return model.Fail(model.Corrupt)
		}
		var roots, fragments, gcs uint64
		err := tx.Bucket([]byte("artifact_roots")).ForEach(func(key, raw []byte) error {
			var r model.BlobReceipt
			if model.StrictJSON(raw, &r) != nil || string(key) != model.BlobKey(r.Manifest) {
				return model.Fail(model.Corrupt)
			}
			if err := verifyBlobTx(tx, r, false); err != nil {
				return err
			}
			roots++
			fragments += uint64(len(r.Fragments))
			return nil
		})
		if err != nil {
			return err
		}
		if err = tx.Bucket([]byte("artifact_gc")).ForEach(func(key, raw []byte) error {
			var g model.ArtifactGC
			if model.StrictJSON(raw, &g) != nil || !validBlob(g.Manifest) || string(key) != model.BlobKey(g.Manifest) || g.CommandID == (model.ID{}) || g.ControlRevision == 0 || g.Cursor == nil || g.Cursor.Index == 0 || tx.Bucket([]byte("artifact_roots")).Get(key) != nil {
				return model.Fail(model.Corrupt)
			}
			gcs++
			return nil
		}); err != nil {
			return err
		}
		var actualFragments uint64
		if err = tx.Bucket([]byte("artifact_fragments")).ForEach(func(_, v []byte) error {
			actualFragments++
			if len(v) == 0 {
				return model.Fail(model.Corrupt)
			}
			return nil
		}); err != nil {
			return err
		}
		if fragments != actualFragments || roots != binary.BigEndian.Uint64(counts[:8]) || fragments != binary.BigEndian.Uint64(counts[8:16]) || gcs != binary.BigEndian.Uint64(counts[16:]) {
			return model.Fail(model.Corrupt)
		}
		return nil
	})
}
func validBlob(m model.BlobManifest) bool {
	return m.Org != (model.ID{}) && m.Project != (model.ID{}) && m.Source != (model.ID{}) && m.Root != (model.ID{}) && m.Build != (model.ID{}) && m.Hash != (model.Hash{}) && m.Size > 0 && m.Size <= model.ArtifactBundleLimit && m.PolicyEpoch > 0 && m.PolicyRevision > 0 && m.RetainUntil > 0 && m.ReservationID != (model.ID{})
}
func validateBlobFence(tx *bolt.Tx, m model.BlobManifest, slot uint16) error {
	if err := validateTombstoneBlob(tx, m, slot); err != nil {
		return err
	}
	raw := tx.Bucket([]byte("fences")).Get([]byte(m.Source.String() + ":" + strconv.Itoa(int(slot))))
	if raw == nil {
		return nil
	}
	var f model.SourceFence
	if json.Unmarshal(raw, &f) != nil {
		return model.Fail(model.Corrupt)
	}
	if uint64(m.PolicyEpoch) < uint64(f.Epoch) {
		return model.Fail(model.Stale)
	}
	return nil
}
func (e *Engine) applyBlobFragment(tx *bolt.Tx, slot uint16, index uint64, f model.ArtifactFragment) error {
	m := f.Manifest
	expected := uint32((m.Size + model.ArtifactFragmentLimit - 1) / model.ArtifactFragmentLimit)
	n := uint64(model.ArtifactFragmentLimit)
	if f.Ordinal == expected-1 {
		n = uint64(m.Size) - uint64(f.Ordinal)*model.ArtifactFragmentLimit
	}
	if !validBlob(m) || slot != model.BlobOwnerSlot(m.Org, m.Project, m.Root) || f.Ordinal >= expected || uint64(len(f.Bytes)) != n || model.HashCanonical(f.Bytes) != f.Hash || f.Cursor != (model.Cursor{Group: e.group(slot), Index: model.Uint64(index)}) || f.Reservation.ID != m.ReservationID || f.Reservation.Manifest != m || f.Reservation.ManifestHash != model.BlobManifestHash(m) || f.Reservation.Slot != slot || f.Reservation.State != "reserved" && f.Reservation.State != "consumed" {
		return model.Fail(model.Corrupt)
	}
	if err := validateBlobFence(tx, m, slot); err != nil {
		return err
	}
	if tx.Bucket([]byte("artifact_gc")).Get([]byte(model.BlobKey(m))) != nil {
		return model.Fail(model.Conflict)
	}
	roots := tx.Bucket([]byte("artifact_roots"))
	var r model.BlobReceipt
	if raw := roots.Get([]byte(model.BlobKey(m))); raw != nil {
		if model.StrictJSON(raw, &r) != nil || r.Manifest != m {
			return model.Fail(model.Corrupt)
		}
	} else {
		r = model.BlobReceipt{Manifest: m, Hash: m.Hash}
	}
	if int(f.Ordinal) != len(r.Fragments) {
		return model.Fail(model.Corrupt)
	}
	key := blobFragmentKey(m, f.Ordinal)
	if tx.Bucket([]byte("artifact_fragments")).Get(key) != nil {
		return model.Fail(model.Corrupt)
	}
	if err := tx.Bucket([]byte("artifact_fragments")).Put(key, f.Bytes); err != nil {
		return err
	}
	r.Fragments = append(r.Fragments, model.BlobFragmentReceipt{Ordinal: f.Ordinal, Hash: f.Hash, Size: uint32(len(f.Bytes)), Cursor: f.Cursor})
	r.Cursor = f.Cursor
	if uint64(f.Ordinal+1) == uint64(expected) {
		if err := verifyBlobTx(tx, r, true); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	newRoot := int64(0)
	if f.Ordinal == 0 {
		newRoot = 1
	}
	if err = roots.Put([]byte(model.BlobKey(m)), raw); err != nil {
		return err
	}
	return adjustBlobCounts(tx, newRoot, 1, 0)
}
func verifyBlobTx(tx *bolt.Tx, r model.BlobReceipt, whole bool) error {
	if !validBlob(r.Manifest) || r.Hash != r.Manifest.Hash || len(r.Fragments) == 0 || len(r.Fragments) > 128 {
		return model.Fail(model.Corrupt)
	}
	h := sha256.New()
	var size uint64
	var previous model.Cursor
	for i, f := range r.Fragments {
		raw := tx.Bucket([]byte("artifact_fragments")).Get(blobFragmentKey(r.Manifest, uint32(i)))
		if f.Ordinal != uint32(i) || len(raw) == 0 || len(raw) > model.ArtifactFragmentLimit || uint32(len(raw)) != f.Size || model.HashCanonical(raw) != f.Hash || f.Cursor.Index == 0 || f.Cursor.Group == (model.ID{}) || i > 0 && (f.Cursor.Group != previous.Group || f.Cursor.Index <= previous.Index) {
			return model.Fail(model.Corrupt)
		}
		h.Write(raw)
		size += uint64(len(raw))
		previous = f.Cursor
	}
	if previous != r.Cursor || size > uint64(r.Manifest.Size) {
		return model.Fail(model.Corrupt)
	}
	if whole && size != uint64(r.Manifest.Size) {
		return model.Fail(model.Unavailable)
	}
	if size == uint64(r.Manifest.Size) {
		var sum model.Hash
		copy(sum[:], h.Sum(nil))
		if sum != r.Hash {
			return model.Fail(model.Corrupt)
		}
	}
	return nil
}

// WriteBlob stages and verifies the complete bounded stream before the first
// proposal. Every fragment then uses commit's WAL/fsync/apply/receipt path.
func (e *Engine) WriteBlob(ctx context.Context, scope auth.Scope, m model.BlobManifest, input io.Reader) (model.BlobReceipt, error) {
	if !validBlob(m) || input == nil {
		return model.BlobReceipt{}, model.Fail(model.Invalid)
	}
	reservation, err := scope.ValidateBlobReservation(ctx, m)
	if err != nil {
		return model.BlobReceipt{}, err
	}
	temp, err := os.CreateTemp("", "soundpost-artifact-")
	if err != nil {
		return model.BlobReceipt{}, model.Fail(model.Unavailable)
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(temp, h), io.LimitReader(input, int64(m.Size)+1))
	if err != nil {
		return model.BlobReceipt{}, model.Fail(model.Invalid)
	}
	if n != int64(m.Size) {
		return model.BlobReceipt{}, model.Fail(model.TooLarge)
	}
	var hash model.Hash
	copy(hash[:], h.Sum(nil))
	if hash != m.Hash {
		return model.BlobReceipt{}, model.Fail(model.Invalid)
	}
	if _, err = temp.Seek(0, 0); err != nil {
		return model.BlobReceipt{}, err
	}
	e.proposalMu.Lock()
	defer e.proposalMu.Unlock()
	if err := e.replicaBeforeWrite(ctx, model.BlobOwnerSlot(m.Org, m.Project, m.Root)); err != nil {
		return model.BlobReceipt{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.BlobReceipt{}, model.Fail(model.Unavailable)
	}
	// Pressure admits only an upload that still has to commit a fragment: the
	// gate runs at the first missing ordinal, so a retry of a complete upload
	// verifies its stored fragments and returns the existing receipt at any
	// pressure level (nothing is written, so there is nothing to refuse).
	admitted := false
	slot := model.BlobOwnerSlot(m.Org, m.Project, m.Root)
	buffer := make([]byte, model.ArtifactFragmentLimit)
	var out model.BlobReceipt
	for ordinal := uint32(0); uint64(ordinal)*model.ArtifactFragmentLimit < uint64(m.Size); ordinal++ {
		if err = ctx.Err(); err != nil {
			return model.BlobReceipt{}, model.Fail(model.Cancelled)
		}
		if _, err = scope.ValidateBlobReservation(ctx, m); err != nil {
			return model.BlobReceipt{}, err
		}
		size := uint64(model.ArtifactFragmentLimit)
		if left := uint64(m.Size) - uint64(ordinal)*model.ArtifactFragmentLimit; left < size {
			size = left
		}
		if _, err = io.ReadFull(temp, buffer[:size]); err != nil {
			return model.BlobReceipt{}, err
		}
		hash := model.HashCanonical(buffer[:size])
		var old model.BlobReceipt
		err = e.db.View(func(tx *bolt.Tx) error {
			if err := validateBlobFence(tx, m, slot); err != nil {
				return err
			}
			raw := tx.Bucket([]byte("artifact_roots")).Get([]byte(model.BlobKey(m)))
			if raw != nil {
				if model.StrictJSON(raw, &old) != nil || old.Manifest != m {
					return model.Fail(model.Conflict)
				}
				if int(ordinal) < len(old.Fragments) {
					if old.Fragments[ordinal].Hash != hash {
						return model.Fail(model.Conflict)
					}
					return nil
				}
			}
			return nil
		})
		if err != nil {
			return model.BlobReceipt{}, err
		}
		if int(ordinal) >= len(old.Fragments) {
			if !admitted {
				if err = e.admitPressure(ClassNormal, uint64(m.Size)); err != nil {
					return model.BlobReceipt{}, err
				}
				admitted = true
			}
			if err = e.writeBlobDeletions(ctx, m); err != nil {
				return model.BlobReceipt{}, err
			}
			f := model.ArtifactFragment{Manifest: m, Reservation: reservation, Ordinal: ordinal, Bytes: buffer[:size], Hash: hash, Cursor: model.Cursor{Group: e.group(slot), Index: model.Uint64(e.indexes[slot] + 1)}}
			if err = e.commit(slot, uint64(f.Cursor.Index), walEntry{Type: "artifact_fragment", Artifact: &f}); err != nil {
				return model.BlobReceipt{}, err
			}
			if err = e.trip("blob_fragment_committed"); err != nil {
				return model.BlobReceipt{}, err
			}
		}
	}
	err = e.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte("artifact_roots")).Get([]byte(model.BlobKey(m)))
		if model.StrictJSON(raw, &out) != nil {
			return model.Fail(model.Corrupt)
		}
		return verifyBlobTx(tx, out, true)
	})
	if err != nil {
		return model.BlobReceipt{}, err
	}
	return out, nil
}
func (e *Engine) VerifyBlob(ctx context.Context, r model.BlobReceipt) error {
	if err := e.replicaBeforeWrite(ctx, model.BlobOwnerSlot(r.Manifest.Org, r.Manifest.Project, r.Manifest.Root)); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil || e.closed || e.failed {
		return model.Fail(model.Unavailable)
	}
	return e.db.View(func(tx *bolt.Tx) error {
		var old model.BlobReceipt
		if model.StrictJSON(tx.Bucket([]byte("artifact_roots")).Get([]byte(model.BlobKey(r.Manifest))), &old) != nil {
			return model.Fail(model.Unavailable)
		}
		a, _ := model.CanonicalJSON(old)
		b, _ := model.CanonicalJSON(r)
		if !bytes.Equal(a, b) {
			return model.Fail(model.Forbidden)
		}
		return verifyBlobTx(tx, r, true)
	})
}

// ReadBlobFragment releases at most one protected fragment after a fresh scope
// check. The feature layer independently revalidates the published reference.
func (e *Engine) ReadBlobFragment(ctx context.Context, scope auth.Scope, r model.BlobReceipt, ordinal uint32) ([]byte, error) {
	if err := scope.RevalidateArtifact(ctx, r.Manifest, false); err != nil {
		return nil, err
	}
	if err := e.replicaBeforeWrite(ctx, model.BlobOwnerSlot(r.Manifest.Org, r.Manifest.Project, r.Manifest.Root)); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return nil, model.Fail(model.Unavailable)
	}
	if err := e.readBlobDeletions(ctx, r.Manifest); err != nil {
		return nil, err
	}
	var out []byte
	err := e.db.View(func(tx *bolt.Tx) error {
		var old model.BlobReceipt
		if model.StrictJSON(tx.Bucket([]byte("artifact_roots")).Get([]byte(model.BlobKey(r.Manifest))), &old) != nil {
			return model.Fail(model.Unavailable)
		}
		a, _ := model.CanonicalJSON(old)
		b, _ := model.CanonicalJSON(r)
		if !bytes.Equal(a, b) {
			return model.Fail(model.Unavailable)
		}
		if int(ordinal) >= len(r.Fragments) {
			return io.EOF
		}
		raw := tx.Bucket([]byte("artifact_fragments")).Get(blobFragmentKey(r.Manifest, ordinal))
		fragment := r.Fragments[ordinal]
		if len(raw) == 0 || uint32(len(raw)) != fragment.Size || model.HashCanonical(raw) != fragment.Hash {
			return model.Fail(model.Corrupt)
		}
		out = bytes.Clone(raw)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = scope.RevalidateArtifact(ctx, r.Manifest, false); err != nil {
		return nil, err
	}
	return out, nil
}

func (e *Engine) applyBlobGC(tx *bolt.Tx, slot uint16, index uint64, g model.ArtifactGC) error {
	m := g.Manifest
	if !validBlob(m) || g.CommandID == (model.ID{}) || g.ControlRevision == 0 || slot != model.BlobOwnerSlot(m.Org, m.Project, m.Root) || g.Cursor == nil || *g.Cursor != (model.Cursor{Group: e.group(slot), Index: model.Uint64(index)}) {
		return model.Fail(model.Corrupt)
	}
	key := []byte(model.BlobKey(m))
	if tx.Bucket([]byte("artifact_gc")).Get(key) != nil {
		return model.Fail(model.Corrupt)
	}
	rootDelta, fragmentDelta := int64(0), int64(0)
	roots := tx.Bucket([]byte("artifact_roots"))
	if raw := roots.Get(key); raw != nil {
		var r model.BlobReceipt
		if model.StrictJSON(raw, &r) != nil || r.Manifest != m {
			return model.Fail(model.Corrupt)
		}
		rootDelta = -1
		fragmentDelta = -int64(len(r.Fragments))
		for _, f := range r.Fragments {
			if err := tx.Bucket([]byte("artifact_fragments")).Delete(blobFragmentKey(m, f.Ordinal)); err != nil {
				return err
			}
		}
		if err := roots.Delete(key); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(g)
	if err != nil {
		return err
	}
	if err = tx.Bucket([]byte("artifact_gc")).Put(key, raw); err != nil {
		return err
	}
	return adjustBlobCounts(tx, rootDelta, fragmentDelta, 1)
}
func (e *Engine) GCUnreferencedBlob(ctx context.Context, scope auth.Scope, proof model.ArtifactGC) (model.ArtifactGC, error) {
	if err := scope.ValidateArtifactGC(ctx, proof); err != nil {
		return model.ArtifactGC{}, err
	}
	e.proposalMu.Lock()
	defer e.proposalMu.Unlock()
	if err := e.replicaBeforeWrite(ctx, model.BlobOwnerSlot(proof.Manifest.Org, proof.Manifest.Project, proof.Manifest.Root)); err != nil {
		return model.ArtifactGC{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.ArtifactGC{}, model.Fail(model.Unavailable)
	}
	var old model.ArtifactGC
	err := e.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte("artifact_gc")).Get([]byte(model.BlobKey(proof.Manifest)))
		if raw != nil {
			if model.StrictJSON(raw, &old) != nil || old.Manifest != proof.Manifest || old.CommandID != proof.CommandID || old.ControlRevision != proof.ControlRevision || old.Cursor == nil || old.Cursor.Index == 0 {
				return model.Fail(model.Corrupt)
			}
		}
		return nil
	})
	if err != nil {
		return model.ArtifactGC{}, err
	}
	if old.Cursor != nil {
		return old, nil
	}
	slot := model.BlobOwnerSlot(proof.Manifest.Org, proof.Manifest.Project, proof.Manifest.Root)
	proof.Cursor = &model.Cursor{Group: e.group(slot), Index: model.Uint64(e.indexes[slot] + 1)}
	if err = e.commit(slot, uint64(proof.Cursor.Index), walEntry{Type: "artifact_gc", ArtifactGC: &proof}); err != nil {
		return model.ArtifactGC{}, err
	}
	return proof, nil
}

func adjustBlobCounts(tx *bolt.Tx, roots, fragments, gcs int64) error {
	old := tx.Bucket([]byte("meta")).Get([]byte("artifact_counts"))
	if len(old) != 24 {
		return model.Fail(model.Corrupt)
	}
	var next [24]byte
	for i, delta := range []int64{roots, fragments, gcs} {
		value := binary.BigEndian.Uint64(old[i*8 : i*8+8])
		if delta < 0 {
			amount := uint64(-delta)
			if value < amount {
				return model.Fail(model.Corrupt)
			}
			value -= amount
		} else {
			if value > ^uint64(0)-uint64(delta) {
				return model.Fail(model.Corrupt)
			}
			value += uint64(delta)
		}
		binary.BigEndian.PutUint64(next[i*8:i*8+8], value)
	}
	return tx.Bucket([]byte("meta")).Put([]byte("artifact_counts"), next[:])
}
