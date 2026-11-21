// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"sort"
)

// Compact streams one bounded page at a time. It preserves every page identity,
// including equal-time distinct log IDs and exact metric stale/NaN bit patterns.
func (e *Engine) Compact(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Fail(model.Unavailable)
	}
	groups, err := e.pageGroupsLocked(false)
	if err != nil {
		return err
	}
	// With no page left (everything erased) the old segments must still be retired.
	if len(groups) == 0 && len(e.catalog.Manifest.Segments) == 0 {
		return nil
	}
	replacement := e.catalog.Manifest
	replacement.Segments = nil
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
	old := e.catalog.Manifest.Segments
	if _, err = e.publishManifestLocked(ctx, e.identity, e.catalog.Manifest.Revision, replacement, updates); err != nil {
		return err
	}
	// No IO borrows survive Next: all readers use the serialized current page
	// location. Thus retired files can be removed only after the durable CAS.
	for _, segment := range old {
		path, err := segmentPath(e.dir, segment.File)
		if err != nil {
			return err
		}
		if err = e.retireFileLocked(path); err != nil {
			return err
		}
	}
	return nil
}
