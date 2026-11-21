// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"slices"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// rootWrittenAfter reports whether any blob of the root has a fragment committed after the
// application index after: that fragment is in the journal a pin with that high-water mark
// archives. A root whose every fragment is at or below it is inside the snapshots instead.
func (e *Engine) rootWrittenAfter(org, project, root model.ID, after uint64) (bool, error) {
	found := false
	err := e.db.View(func(tx *bolt.Tx) error {
		roots := tx.Bucket([]byte("artifact_roots"))
		if roots == nil {
			return model.Fail(model.Corrupt)
		}
		for _, private := range []bool{false, true} {
			key := model.BlobKey(model.BlobManifest{Org: org, Project: project, Root: root, PrivateSources: private})
			raw := roots.Get([]byte(key))
			if raw == nil {
				continue
			}
			var r model.BlobReceipt
			if err := model.StrictJSON(raw, &r); err != nil {
				return model.Fail(model.Corrupt)
			}
			if uint64(r.Cursor.Index) > after { // the receipt's cursor is that of its newest fragment
				found = true
				return nil
			}
		}
		return nil
	})
	return found, err
}

// RootPinned reports whether a live durable journal pin of the data group that owns the artifact
// root still holds it. A pin holds the roots whose evidence lies in the journal it protects: a
// fragment of the root committed after the pin's high-water mark (BeginBackupOwned records the
// highest application index the backup had processed), which covers every root written while the
// backup runs. A root whose fragments were all committed at or below the mark is inside the
// snapshots the backup seals, not in the journal it pins, so erasing it cannot leave the pinned
// history unreplayable; a restore that finds its intent published again retires it
// (Lifecycle.ReconcileRetired). A pin of another group never holds the root. A pin that recorded no
// roots (taken by an earlier build) holds every root of its group, and a root a pin did record
// stays held by it. A pin source that cannot be read is an error, never "not pinned".
func (e *Engine) RootPinned(org, project, root model.ID) (bool, error) {
	if e.repl == nil {
		return false, model.Fail(model.Unavailable)
	}
	slot := model.BlobOwnerSlot(org, project, root)
	if int(slot) >= len(e.repl.groups) {
		return false, model.Fail(model.Corrupt)
	}
	pins, err := e.repl.groups[slot].Pins()
	if err != nil {
		return false, storageReplicaFault(err)
	}
	for _, p := range pins {
		if !p.RootsKnown || slices.Contains(p.Roots, root) {
			return true, nil
		}
		written, err := e.rootWrittenAfter(org, project, root, p.After)
		if err != nil {
			return false, err
		}
		if written {
			return true, nil
		}
	}
	return false, nil
}
