// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	bolt "go.etcd.io/bbolt"
	"sort"
	"soundpost/internal/model"
	"strconv"
)

func (e *Engine) Flush(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Fail(model.Unavailable)
	}
	groups, err := e.pageGroupsLocked(true)
	if err != nil {
		return err
	}
	if len(groups) == 0 {
		return nil
	}
	replacement := e.catalog.Manifest
	replacement.Segments = append([]SegmentManifest(nil), replacement.Segments...)
	var updates []pageRef
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err = ctx.Err(); err != nil {
			return model.Fail(model.Cancelled)
		}
		refs, segment, err := e.writeSegment(ctx, groups[key])
		if err != nil {
			return err
		}
		updates = append(updates, refs...)
		replacement.Segments = append(replacement.Segments, segment)
	}
	_, err = e.publishManifestLocked(ctx, e.identity, e.catalog.Manifest.Revision, replacement, updates)
	return err
}
func (e *Engine) pageGroupsLocked(hotOnly bool) (map[string][]pageRef, error) {
	groups := map[string][]pageRef{}
	err := e.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("scan_pages")).ForEach(func(_, b []byte) error {
			p, err := parsePageRef(b)
			if err != nil {
				return err
			}
			if hotOnly && p.Segment != "" {
				return nil
			}
			p.Hot = nil // metadata only: reload a bounded page when writing.
			key := string(pageNamespace(p.Org, p.Project, p.Kind, p.Restricted, p.Source, p.Subject)) + p.Source.String() + ":" + segmentDay(p.Start) + ":" + strconv.FormatUint(uint64(p.PolicyRevision), 10)
			groups[key] = append(groups[key], p)
			return nil
		})
	})
	for k, refs := range groups {
		sort.Slice(refs, func(i, j int) bool {
			if refs[i].Start != refs[j].Start {
				return refs[i].Start < refs[j].Start
			}
			return string(refs[i].ID[:]) < string(refs[j].ID[:])
		})
		groups[k] = refs
	}
	return groups, err
}
func (e *Engine) loadRefLocked(id model.ID) (pageRef, error) {
	var ref pageRef
	err := e.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("scan_pages")).Get(id[:])
		if b == nil {
			return model.Fail(model.Corrupt)
		}
		var err error
		ref, err = parsePageRef(b)
		return err
	})
	return ref, err
}
