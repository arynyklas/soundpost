// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	bolt "go.etcd.io/bbolt"
	"hash"
	"os"
	"path/filepath"
	"reflect"
	"soundpost/internal/durablefs"
	"soundpost/internal/model"
)

type SegmentManifest struct {
	ID                      model.ID
	File                    string
	Org, Project, Source    model.ID
	Signal, Subject         model.Kind
	Restricted              bool
	PolicyRevision          model.Revision
	Format                  uint16
	Start, End, RetainUntil model.UnixNano
	Checksum                model.Hash
	Bytes, Rows             uint64
	Pages                   []model.ID
}
type IndexReference struct {
	Name   string
	Format uint16
	Digest *IndexDigest `json:"digest,omitempty"`
}
type Manifest struct {
	Version             uint16
	Group               model.ID
	Term                uint64
	Revision            model.Revision
	Segments            []SegmentManifest
	IndexReferences     []IndexReference
	Applied             []model.Cursor
	TombstoneGeneration uint64
	SnapshotCoverage    []model.Cursor
}
type manifestState struct {
	Manifest Manifest
	File     string
	Hash     model.Hash
}

func newFileHash() hash.Hash { return sha256.New() }
func (e *Engine) initStorage() error {
	e.subscribers = map[*changeIterator]struct{}{}
	e.scans = map[*rowIterator]struct{}{}
	err := e.db.Update(func(tx *bolt.Tx) error {
		marker := tx.Bucket([]byte("meta")).Get([]byte("scan_index_version"))
		initialized := marker != nil
		if initialized && (len(marker) != 1 || marker[0] != 1) {
			return model.Fail(model.Corrupt)
		}
		if !initialized && tx.Bucket([]byte("meta")).Get([]byte("replica_format")) != nil {
			return model.Fail(model.Corrupt)
		}
		if !initialized && tx.Bucket([]byte("meta")).Get([]byte("segment_manifest")) != nil {
			return model.Fail(model.Corrupt)
		}
		for _, name := range []string{"scan_pages", "scan_time", "scan_postings", "scan_commits", "scan_integrity"} {
			if initialized && tx.Bucket([]byte(name)) == nil {
				return model.Fail(model.Corrupt)
			}
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		if !initialized {
			if err := initializeIndexIntegrity(tx); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err = durablefs.MkdirAll(filepath.Join(e.dir, "segments")); err != nil {
		return err
	}
	err = e.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("meta")).Get([]byte("segment_manifest"))
		if b == nil {
			e.catalog = manifestState{Manifest: Manifest{Version: 1, Group: e.identity, Term: 1, IndexReferences: storageIndexes()}}
			return nil
		}
		if json.Unmarshal(b, &e.catalog) != nil || e.catalog.Manifest.Version != 1 || e.catalog.Manifest.Group != e.identity || e.catalog.Manifest.Term != 1 || !validIndexReferences(e.catalog.Manifest.IndexReferences) {
			return model.Fail(model.Corrupt)
		}
		if filepath.Base(e.catalog.File) != e.catalog.File {
			return model.Fail(model.Corrupt)
		}
		data, err := os.ReadFile(filepath.Join(e.dir, e.catalog.File))
		if err != nil || model.HashCanonical(data) != e.catalog.Hash {
			return model.Fail(model.Corrupt)
		}
		canonical, err := json.Marshal(e.catalog.Manifest)
		if err != nil || string(canonical) != string(data) {
			return model.Fail(model.Corrupt)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, s := range e.catalog.Manifest.Segments {
		if s.Format != 1 || s.PolicyRevision == 0 || !validSubject(s.Signal, s.Subject) || s.File != segmentName(s.Org, s.Project, s.Signal, s.Start, s.ID) {
			return model.Fail(model.Corrupt)
		}
		path, err := segmentPath(e.dir, s.File)
		if err != nil {
			return err
		}
		h, err := hashFile(path)
		if err != nil || h != s.Checksum {
			return model.Fail(model.Corrupt)
		}
		if err = verifySegmentFileHeader(path, s); err != nil {
			return err
		}
	}
	// Upgrade the existing 01.03 apply database once, without changing WAL/receipts.
	err = e.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		if meta.Get([]byte("scan_index_version")) != nil {
			return nil
		}
		if err := e.migrateIndexes(tx); err != nil {
			return err
		}
		return meta.Put([]byte("scan_index_version"), []byte{1})
	})
	if err != nil {
		return err
	}
	return e.db.View(validateIndexIntegrity)
}
func (e *Engine) Publish(ctx context.Context, groupID model.ID, expected model.Revision, replacement Manifest) (model.Revision, error) {
	if ctx.Err() != nil {
		return 0, model.Fail(model.Cancelled)
	}
	replacement.Segments = append([]SegmentManifest(nil), replacement.Segments...)
	for i := range replacement.Segments {
		replacement.Segments[i].Pages = append([]model.ID(nil), replacement.Segments[i].Pages...)
	}
	replacement.IndexReferences = append([]IndexReference(nil), replacement.IndexReferences...)
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.publishManifestLocked(ctx, groupID, expected, replacement, nil)
}

// publishManifestLocalLocked atomically replaces this node's own physical-layout
// manifest. The manifest, the segment files and the page locations are
// node-local state: every voter rebuilds them from the replicated command
// history, and nothing outside this engine observes them except through this
// engine's own fenced reads. A publication therefore has no Raft leadership or
// quorum requirement: a follower, a node that leads only some groups and a
// node that has just lost leadership all maintain their own layout. Requiring
// leadership of all 65 groups, as an earlier version did, made maintenance
// impossible on every follower and on every leader that did not happen to lead
// everything, and with it the snapshot coverage a publication records.
//
// The one lock it needs is e.mu, which the caller holds for the whole
// operation, from choosing the pages being relocated until the durable
// compare-and-swap. Apply, snapshot Restore, the snapshot cut (Snapshot,
// DeletionLedger, PinFiles), Append and every read take e.mu, so none of them
// can interleave: a hot page cannot grow or move while it is flushed, and the
// recorded Applied watermarks and snapshot coverage are read from the same
// engine state the publication verified. No group mutex is taken (Apply holds
// one while waiting for e.mu), and no quorum round trip is made for a purely
// local operation.
//
// What this path must never do is change anything other nodes or clients
// depend on: TombstoneGeneration must stay equal and no retained page may be
// dropped, so a publication cannot delete or hide data. Deletion, retention
// and any external destination must go through replicated commands (and, for
// external effects, Group.Fence/ValidateFence), not through this function.
// The format term stays 1: it is an on-disk format constant, not a Raft term.
//
// Segments that the previous publication (or this engine's open) already
// verified are immutable and are carried forward after a size/existence/header
// check without hashing or decoding them again; new or altered segments are
// hashed and every page is read back before the manifest can point at them.
func (e *Engine) publishManifestLocalLocked(ctx context.Context, groupID model.ID, expected model.Revision, replacement Manifest, updates []pageRef) (model.Revision, error) {
	if err := ctx.Err(); err != nil {
		return 0, model.Fail(model.Cancelled)
	}
	if e.closed || e.failed {
		return 0, model.Fail(model.Unavailable)
	}
	old := e.catalog.Manifest
	if groupID != e.identity || replacement.Group != groupID || replacement.Term != old.Term || expected != old.Revision || replacement.Version != 1 || replacement.TombstoneGeneration != old.TombstoneGeneration || !validIndexReferences(replacement.IndexReferences) {
		return 0, model.Fail(model.Conflict)
	}
	previous := make(map[string]SegmentManifest, len(old.Segments))
	for _, s := range old.Segments {
		previous[s.File] = s
	}
	// Publication may relocate every retained page, never drop a committed page.
	covered := map[model.ID]SegmentManifest{}
	files, carried := map[string]bool{}, map[string]bool{}
	for _, s := range replacement.Segments {
		if ctx.Err() != nil {
			return 0, model.Fail(model.Cancelled)
		}
		if s.Format != 1 || s.PolicyRevision == 0 || !validSubject(s.Signal, s.Subject) || s.File != segmentName(s.Org, s.Project, s.Signal, s.Start, s.ID) || files[s.File] || len(s.Pages) == 0 {
			return 0, model.Fail(model.Invalid)
		}
		files[s.File] = true
		path, err := segmentPath(e.dir, s.File)
		if err != nil {
			return 0, err
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() < 0 || uint64(info.Size()) != s.Bytes {
			return 0, model.Fail(model.Corrupt)
		}
		if verified, ok := previous[s.File]; ok && sameSegmentManifest(verified, s) {
			carried[s.File] = true
		} else {
			hash, err := hashFile(path)
			if err != nil || hash != s.Checksum {
				return 0, model.Fail(model.Corrupt)
			}
		}
		for _, id := range s.Pages {
			if _, ok := covered[id]; ok {
				return 0, model.Fail(model.Invalid)
			}
			covered[id] = s
		}
	}
	updateMap := map[model.ID]pageRef{}
	for _, p := range updates {
		if _, ok := updateMap[p.ID]; ok {
			return 0, model.Fail(model.Invalid)
		}
		updateMap[p.ID] = p
	}
	bounds := map[string]*segmentBounds{}
	seen := 0
	err := e.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("scan_pages")).ForEach(func(_, b []byte) error {
			if ctx.Err() != nil {
				return model.Fail(model.Cancelled)
			}
			p, err := parsePageRef(b)
			if err != nil {
				return err
			}
			if u, ok := updateMap[p.ID]; ok {
				if u.Hash != p.Hash || u.Count != p.Count || u.Length != p.Length || u.Org != p.Org || u.Project != p.Project || u.Source != p.Source || u.Kind != p.Kind || u.Subject != p.Subject || u.Restricted != p.Restricted || u.PolicyRevision != p.PolicyRevision || u.Start != p.Start || u.End != p.End || u.RetainUntil != p.RetainUntil {
					return model.Fail(model.Corrupt)
				}
				p = u
			}
			if p.Segment != "" {
				s, ok := covered[p.ID]
				if !ok || s.File != p.Segment || s.Org != p.Org || s.Project != p.Project || s.Source != p.Source || s.Signal != p.Kind || s.Subject != p.Subject || s.Restricted != p.Restricted || s.PolicyRevision != p.PolicyRevision {
					return model.Fail(model.Conflict)
				}
				seen++
				summary := bounds[p.Segment]
				if summary == nil {
					summary = &segmentBounds{Start: p.Start, End: p.End, RetainUntil: p.RetainUntil, Bytes: segmentHeaderSize}
					bounds[p.Segment] = summary
				}
				if p.Start < summary.Start {
					summary.Start = p.Start
				}
				if p.End > summary.End {
					summary.End = p.End
				}
				if p.RetainUntil > summary.RetainUntil {
					summary.RetainUntil = p.RetainUntil
				}
				summary.Bytes += uint64(p.Length)
				summary.Rows += uint64(p.Count)
				summary.Pages++
				if !carried[p.Segment] {
					if _, err = e.readPage(p); err != nil {
						return err
					}
				}
			}
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	if seen != len(covered) {
		return 0, model.Fail(model.Invalid)
	}
	for _, s := range replacement.Segments {
		summary := bounds[s.File]
		if summary == nil || summary.Start != s.Start || summary.End != s.End || summary.RetainUntil != s.RetainUntil || summary.Bytes != s.Bytes || summary.Rows != s.Rows || summary.Pages != len(s.Pages) {
			return 0, model.Fail(model.Corrupt)
		}
		path, err := segmentPath(e.dir, s.File)
		if err != nil {
			return 0, err
		}
		if err = verifySegmentFileHeader(path, s); err != nil {
			return 0, err
		}
	}
	replacement.Revision = expected + 1
	if replacement.Revision == 0 {
		return 0, model.Fail(model.Unavailable)
	}
	replacement.Applied = e.watermarksLocked()
	replacement.SnapshotCoverage = e.snapshotCoverageLocked() // journal truncation is bounded by these verified cuts
	replacement.IndexReferences, err = e.currentIndexReferencesLocked()
	if err != nil {
		return 0, err
	}
	data, err := json.Marshal(replacement)
	if err != nil {
		return 0, err
	}
	name := "manifest-" + model.NewID().String() + ".json"
	if err = durablefs.Exclusive(filepath.Join(e.dir, name), data); err != nil {
		return 0, err
	}
	state := manifestState{Manifest: replacement, File: name, Hash: model.HashCanonical(data)}
	raw, err := json.Marshal(state)
	if err != nil {
		return 0, err
	}
	if err = e.trip("manifest_publish"); err != nil {
		return 0, err
	}
	if err = ctx.Err(); err != nil {
		return 0, model.Fail(model.Cancelled)
	}
	err = e.db.Update(func(tx *bolt.Tx) error {
		for _, p := range updates {
			b, err := pageRefBytes(p)
			if err != nil {
				return err
			}
			if err = tx.Bucket([]byte("scan_pages")).Put(p.ID[:], b); err != nil {
				return err
			}
		}
		return tx.Bucket([]byte("meta")).Put([]byte("segment_manifest"), raw)
	})
	if err != nil {
		e.failed = true
		return 0, err
	}
	e.catalog = state
	return replacement.Revision, nil
}
func storageIndexes() []IndexReference {
	return []IndexReference{{Name: "scan_time", Format: 1}, {Name: "scan_postings", Format: 1}, {Name: "scan_pages", Format: 1}, {Name: "scan_commits", Format: 1}, {Name: "scan_integrity", Format: 1}}
}
func validIndexReferences(refs []IndexReference) bool {
	expected := storageIndexes()
	if len(refs) != len(expected) {
		return false
	}
	for i, ref := range refs {
		if ref.Name != expected[i].Name || ref.Format != expected[i].Format {
			return false
		}
	}
	return true
}

type segmentBounds struct {
	Start, End, RetainUntil model.UnixNano
	Bytes, Rows             uint64
	Pages                   int
}

// sameSegmentManifest reports whether b is exactly the entry a publication
// already verified. Equal entries name the same immutable file and checksum.
func sameSegmentManifest(a, b SegmentManifest) bool {
	if len(a.Pages) != len(b.Pages) {
		return false
	}
	for i := range a.Pages {
		if a.Pages[i] != b.Pages[i] {
			return false
		}
	}
	a.Pages, b.Pages = nil, nil
	return reflect.DeepEqual(a, b)
}

func (e *Engine) currentIndexReferencesLocked() ([]IndexReference, error) {
	refs := storageIndexes()
	err := e.db.View(func(tx *bolt.Tx) error {
		for i := range refs {
			if refs[i].Name != "scan_time" && refs[i].Name != "scan_postings" {
				continue
			}
			state, err := parseDigest(tx.Bucket([]byte("scan_integrity")).Get([]byte(refs[i].Name)))
			if err != nil {
				return err
			}
			copyState := state
			refs[i].Digest = &copyState
		}
		return nil
	})
	return refs, err
}
