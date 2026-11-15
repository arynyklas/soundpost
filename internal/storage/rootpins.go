// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"slices"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// rootsBySlot lists the artifact roots the engine holds, grouped by the data group that owns them
// (model.BlobOwnerSlot). A root with both a map and a private-sources blob appears once.
func (e *Engine) rootsBySlot() (map[uint16][]model.ID, error) {
	out := map[uint16][]model.ID{}
	err := e.db.View(func(tx *bolt.Tx) error {
		roots := tx.Bucket([]byte("artifact_roots"))
		if roots == nil {
			return model.Fail(model.Corrupt)
		}
		return roots.ForEach(func(_, raw []byte) error {
			var r model.BlobReceipt
			if err := model.StrictJSON(raw, &r); err != nil {
				return model.Fail(model.Corrupt)
			}
			m := r.Manifest
			slot := model.BlobOwnerSlot(m.Org, m.Project, m.Root)
			if !slices.Contains(out[slot], m.Root) {
				out[slot] = append(out[slot], m.Root)
			}
			return nil
		})
	})
	return out, err
}

// rootExists reports whether any blob of the root is held now.
func (e *Engine) rootExists(org, project, root model.ID) (bool, error) {
	found := false
	err := e.db.View(func(tx *bolt.Tx) error {
		roots := tx.Bucket([]byte("artifact_roots"))
		if roots == nil {
			return model.Fail(model.Corrupt)
		}
		for _, private := range []bool{false, true} {
			key := model.BlobKey(model.BlobManifest{Org: org, Project: project, Root: root, PrivateSources: private})
			if roots.Get([]byte(key)) != nil {
				found = true
				return nil
			}
		}
		return nil
	})
	return found, err
}

// RootPinned reports whether a live durable journal pin of the data group that owns the artifact
// root still holds it: the pin recorded the root when it was taken (BeginBackupOwned), or the root
// was written after the pin and so sits in the journal the pin archives. A pin of another group
// never holds the root. A pin that recorded no roots (taken by an earlier build) holds every root
// of its group. A pin source that cannot be read is an error, never "not pinned".
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
	if len(pins) == 0 {
		return false, nil
	}
	exists, checked := false, false
	for _, p := range pins {
		if !p.RootsKnown || slices.Contains(p.Roots, root) {
			return true, nil
		}
		if !checked {
			if exists, err = e.rootExists(org, project, root); err != nil {
				return false, err
			}
			checked = true
		}
		if exists {
			return true, nil // written after the pin: held by the journal the pin archives
		}
	}
	return false, nil
}
